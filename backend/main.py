"""
PS106 Threat Vision — FastAPI Backend Entry Point
===================================================
Main server exposing:
  POST /api/analyze-trigger   — Android notification trigger (sender/subject/snippet)
  POST /analyze-email         — Direct email analysis endpoint
  GET  /generate-report/{id}  — Download forensic PDF dossier
  GET  /health                — Health check

Architecture:
  1. Receives trigger from Android GmailNotificationListenerService
  2. Uses Gmail OAuth2 API to fetch full RFC 822 MIME raw email
  3. Verifies SPF, DKIM, DMARC from Authentication-Results header
  4. Runs content analysis (URLs, phishing NLP, spoofing heuristics)
  5. Extracts relay IPs and resolves GeoIP (City, Country, ISP)
  6. Computes cumulative PS106 risk score (0-100) with 4-band verdict
  7. Generates downloadable forensic PDF report
"""

import os
import re
import logging
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

# Load .env before any other imports that need env vars
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.gmail_watch_service import GmailWatchService
from services.content_analyzer import ContentAnalyzer
from services.threat_intel_service import ThreatIntelService
from services.domain_intel_service import DomainIntelService
from services.report_service import ReportService
from services.correlation_service import CorrelationService
from services.campaign_service import CampaignService
from services.graph_service import InvestigationGraphService
from routes.gmail_oauth import router as gmail_oauth_router

# --------------------------------------------------------------------------- #
#  Service Singletons
# --------------------------------------------------------------------------- #
gmail_watch = GmailWatchService()
content_analyzer = ContentAnalyzer()
threat_intel = ThreatIntelService()
domain_intel = DomainIntelService()
report_service = ReportService()
correlation_service = CorrelationService()
campaign_service = CampaignService()
graph_service = InvestigationGraphService()

# --------------------------------------------------------------------------- #
#  Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ps106.main")

# --------------------------------------------------------------------------- #
#  FastAPI App
# --------------------------------------------------------------------------- #
app = FastAPI(
    title="PS106 Threat Vision Backend",
    description="Email security analysis API for MessageGuard Android application",
    version="1.0.0",
)

# CORS — allow Android app and local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Gmail OAuth routes
app.include_router(gmail_oauth_router)

# Service instances
gmail_service = GmailWatchService()
content_analyzer = ContentAnalyzer()
threat_intel = ThreatIntelService()
report_service = ReportService()


# --------------------------------------------------------------------------- #
#  Request/Response Models
# --------------------------------------------------------------------------- #

class AnalyzeTriggerRequest(BaseModel):
    """Payload from Android GmailNotificationListenerService."""
    sender: str
    subject: str
    snippet: str = ""


class AnalyzeEmailRequest(BaseModel):
    """Direct email analysis request."""
    sender: str
    subject: str
    body: str = ""
    urls: list = []


class AnalysisResponse(BaseModel):
    """PS106 analysis result returned to Android."""
    case_id: str
    verdict: str
    risk_score: int
    risk_band: str
    risk_color: str
    summary: str
    authentication: dict
    content_analysis: dict
    geoip_data: dict
    score_breakdown: dict
    report_url: str
    timestamp: str

    # Additive forensic fields (compatible with legacy app, enriching new clients)
    primaryCategory: Optional[str] = "SUSPICIOUS"
    secondaryCategories: Optional[list] = []
    forwardingAnalysis: Optional[dict] = None
    sender: Optional[str] = ""
    originalSender: Optional[str] = None
    forwarder: Optional[str] = None
    threatIndicators: Optional[list] = []
    earliest_reliable_observed_ip: Optional[str] = None
    relay_chain: Optional[list] = []
    geo_disclaimer: Optional[str] = (
        "Approximate infrastructure geolocation based on IP registry data. "
        "This does NOT establish the sender's physical location."
    )
    domain_intelligence: Optional[dict] = None
    correlation: Optional[dict] = None
    campaign: Optional[dict] = None
    investigation_graph_summary: Optional[str] = None


# --------------------------------------------------------------------------- #
#  SPF / DKIM / DMARC Verification
# --------------------------------------------------------------------------- #

def verify_authentication_headers(auth_results_header: str) -> dict:
    """
    Parse the Authentication-Results header to extract SPF, DKIM, DMARC verdicts.

    The header typically looks like:
      Authentication-Results: mx.google.com;
        spf=pass (sender IP is ...) smtp.mailfrom=example.com;
        dkim=pass header.d=example.com header.s=...;
        dmarc=pass (p=REJECT sp=REJECT) header.from=example.com
    """
    result = {
        "spf": {"status": "unknown", "detail": ""},
        "dkim": {"status": "unknown", "detail": ""},
        "dmarc": {"status": "unknown", "detail": ""},
    }

    if not auth_results_header:
        for key in result:
            result[key]["status"] = "UNKNOWN"
            result[key]["detail"] = "No Authentication-Results header found"
        result["domain_authorization_status"] = "PARTIAL_OR_UNAVAILABLE"
        result["forensic_note"] = "Authentication results are partially evaluated or headers were absent."
        return result

    header_lower = auth_results_header.lower()

    # SPF: pass, fail, softfail, neutral, none, temperror, permerror
    spf_match = re.search(r"spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", header_lower)
    if spf_match:
        status = spf_match.group(1).upper()
        result["spf"]["status"] = status
        spf_detail = re.search(r"spf\s*=\s*\w+\s*\(([^)]+)\)", header_lower)
        result["spf"]["detail"] = spf_detail.group(1) if spf_detail else status
    else:
        result["spf"]["status"] = "UNKNOWN"
        result["spf"]["detail"] = "No SPF record evaluated in Authentication-Results"

    # DKIM: pass, fail, neutral, none, temperror, permerror
    dkim_match = re.search(r"dkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)", header_lower)
    if dkim_match:
        status = dkim_match.group(1).upper()
        result["dkim"]["status"] = status
        dkim_detail = re.search(r"dkim\s*=\s*\w+\s*([^;]+)", header_lower)
        result["dkim"]["detail"] = dkim_detail.group(1).strip() if dkim_detail else status
    else:
        result["dkim"]["status"] = "UNKNOWN"
        result["dkim"]["detail"] = "No DKIM signature evaluated in Authentication-Results"

    # DMARC: pass, fail, bestguesspass, none, temperror, permerror
    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)", header_lower)
    if dmarc_match:
        status = dmarc_match.group(1).upper()
        result["dmarc"]["status"] = "PASS" if status in ("PASS", "BESTGUESSPASS") else status
        dmarc_detail = re.search(r"dmarc\s*=\s*\w+\s*\(([^)]+)\)", header_lower)
        result["dmarc"]["detail"] = dmarc_detail.group(1) if dmarc_detail else status
    else:
        result["dmarc"]["status"] = "UNKNOWN"
        result["dmarc"]["detail"] = "No DMARC policy evaluated in Authentication-Results"

    # Derive explicit domain authorization status (never falsely equate auth failure to IP spoofing)
    has_failure = any(result[k]["status"] == "FAIL" for k in ("spf", "dkim", "dmarc"))
    all_pass = all(result[k]["status"] == "PASS" for k in ("spf", "dkim", "dmarc"))

    if has_failure:
        result["domain_authorization_status"] = "DOMAIN_UNAUTHORIZED"
        result["forensic_note"] = (
            "Authentication failure indicates the sending domain was not authorized to send this message. "
            "It does NOT reveal or confirm the attacker's real IP address."
        )
    elif all_pass:
        result["domain_authorization_status"] = "DOMAIN_AUTHORIZED"
        result["forensic_note"] = "All evaluated authentication checks (SPF/DKIM/DMARC) aligned and passed."
    else:
        result["domain_authorization_status"] = "PARTIAL_OR_UNAVAILABLE"
        result["forensic_note"] = "Authentication results are partially evaluated or headers were absent."

    return result


def extract_ips_from_email(received_headers: list) -> list:
    """Wrapper around ThreatIntelService IP extraction."""
    return threat_intel.extract_ips_from_email(received_headers)


# --------------------------------------------------------------------------- #
#  Risk Score Calculation
# --------------------------------------------------------------------------- #

def calculate_ps106_risk_score(
    auth_result: dict,
    content_result: dict,
    geoip_result: dict,
) -> dict:
    """
    Calculate cumulative PS106 risk score (0-100) and 4-band verdict.

    Strict Weighted Ratio:
    - ML Content Models: 60%
    - Gmail API / Authentication (SPF/DKIM/DMARC): 40%
    """
    auth_checks = [auth_result.get("spf", {}), auth_result.get("dkim", {}), auth_result.get("dmarc", {})]
    has_auth_data = any(c.get("status") != "unknown" for c in auth_checks)
    
    # 1. Authentication / Gmail API verification score (0-100)
    auth_score = 0
    if has_auth_data:
        for check in auth_checks:
            status = check.get("status", "unknown")
            if status == "fail":
                auth_score += 33
            elif status == "unknown":
                auth_score += 10
    else:
        # Neutral if auth headers absent (snippet trigger)
        auth_score = 0

    # 2. ML Content Risk Score (0-100)
    content_score = content_result.get("content_risk_score", 0)
    relay_analysis = geoip_result.get("relay_analysis", {})
    geoip_score = relay_analysis.get("anomaly_score", 0)

    ml_model_score = max(content_score, int(content_score * 0.85 + geoip_score * 0.15))

    # Exact 60% ML Model + 40% Gmail API Auth weighting
    final_score = int(ml_model_score * 0.60 + auth_score * 0.40)
    final_score = max(0, min(100, final_score))

    # PS106 4-Band Verdict
    if final_score >= 70:
        verdict = "MALICIOUS"
        risk_band = "HIGH"
        risk_color = "#F44336"
    elif final_score >= 45:
        verdict = "SUSPICIOUS"
        risk_band = "MEDIUM-HIGH"
        risk_color = "#FF9800"
    elif final_score >= 20:
        verdict = "UNVERIFIED"
        risk_band = "MEDIUM"
        risk_color = "#FBC02D"
    else:
        verdict = "SAFE"
        risk_band = "LOW"
        risk_color = "#4CAF50"

    # Override: clean text with no threat signals evaluates to SAFE
    if ml_model_score < 20 and auth_score < 30:
        verdict = "SAFE"
        risk_band = "LOW"
        risk_color = "#4CAF50"
        final_score = min(final_score, 10)

    # Force VERIFIED if auth passes and content is clean
    if has_auth_data and all(c.get("status") == "pass" for c in auth_checks) and ml_model_score < 20:
        verdict = "VERIFIED"
        risk_band = "LOW"
        risk_color = "#4CAF50"
        final_score = min(final_score, 5)

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "risk_band": risk_band,
        "risk_color": risk_color,
        "score_breakdown": {
            "ml_content_models": {"score": ml_model_score, "weight": 0.60},
            "gmail_api_auth": {"score": auth_score, "weight": 0.40},
        },
    }


# --------------------------------------------------------------------------- #
#  API Endpoints
# --------------------------------------------------------------------------- #

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "PS106 Threat Vision Backend",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "gmail_configured": bool(os.getenv("GMAIL_REFRESH_TOKEN")),
    }


@app.post("/api/analyze-trigger", response_model=AnalysisResponse)
async def analyze_trigger(request: AnalyzeTriggerRequest):
    """
    Primary endpoint called by Android GmailNotificationListenerService.

    Flow:
    1. Receives {sender, subject, snippet} from notification interception
    2. Fetches full RFC 822 email via Gmail API
    3. Runs SPF/DKIM/DMARC, content, and GeoIP analysis
    4. Returns PS106 verdict with risk score and report URL
    """
    logger.info(f"analyze-trigger: sender={request.sender}, subject={request.subject[:50]}")

    try:
        # Step 1: Fetch full email from Gmail API
        email_data = gmail_service.search_and_fetch_message(
            sender=request.sender,
            subject=request.subject,
            snippet=request.snippet,
        )

        if email_data is None:
            logger.warning("Could not fetch email from Gmail API, analyzing with trigger data only")
            # Fallback: analyze with just the trigger data
            email_data = {
                "sender": request.sender,
                "to": os.getenv("GMAIL_USER_EMAIL", ""),
                "subject": request.subject,
                "text_body": request.snippet,
                "html_body": "",
                "urls": [],
                "attachments": [],
                "authentication_results": "",
                "received_headers": [],
                "raw_headers": {},
                "date": datetime.utcnow().isoformat(),
                "message_id": "",
                "reply_to": "",
            }

        # Step 2: Verify SPF/DKIM/DMARC
        auth_result = verify_authentication_headers(
            email_data.get("authentication_results", "")
        )

        # Step 3: Domain intelligence (WHOIS, DNS, MX, young domain check)
        sender_raw = email_data.get("sender", "")
        sender_domain_intel = domain_intel.resolve_domain_intel(sender_raw)
        
        # Check first URL domain if available
        first_url = (email_data.get("urls") or [None])[0]
        url_domain_intel = domain_intel.resolve_domain_intel(first_url) if first_url else None
        
        domain_intel_data = {
            "sender_domain": sender_domain_intel,
            "url_domain": url_domain_intel,
        }

        # Step 4: Content analysis (compounds risk if domain is young)
        content_result = content_analyzer.analyze(email_data, domain_intel=domain_intel_data)

        # Step 5: Extract relay IPs, build relay chain, and resolve GeoIP
        received_hdrs = email_data.get("received_headers", [])
        relay_chain_data = threat_intel.build_relay_chain(received_hdrs)
        relay_ips = extract_ips_from_email(received_hdrs)
        resolved_ips = threat_intel.resolve_all_ips(relay_ips)
        relay_analysis = threat_intel.analyze_relay_path(resolved_ips)

        geoip_data = {
            "relay_ips": relay_ips,
            "resolved_ips": resolved_ips,
            "relay_analysis": relay_analysis,
            "relay_chain_data": relay_chain_data,
        }

        # Step 6: Calculate PS106 risk score and verdict
        score_result = calculate_ps106_risk_score(
            auth_result, content_result, geoip_data
        )

        # Step 7: Generate forensic PDF report
        full_analysis = {
            "verdict": score_result["verdict"],
            "risk_score": score_result["risk_score"],
            "email_metadata": {
                "sender": email_data.get("sender", ""),
                "to": email_data.get("to", ""),
                "subject": email_data.get("subject", ""),
                "date": email_data.get("date", ""),
                "message_id": email_data.get("message_id", ""),
            },
            "authentication": auth_result,
            "content_analysis": content_result,
            "geoip_data": geoip_data,
            "domain_intel": domain_intel_data,
            "score_breakdown": score_result["score_breakdown"],
        }
        case_id = report_service.generate_report(full_analysis)

        # Step 8: Cross-Case Correlation & Campaign Grouping (Additive Intelligence)
        correlation_result = correlation_service.correlate_case(case_id, full_analysis)
        campaign_info = campaign_service.evaluate_and_assign_campaign(case_id, correlation_result, full_analysis)
        graph_data = graph_service.build_case_graph(case_id, full_analysis, correlation_result, campaign_info)

        # Build summary
        summary_parts = []
        if score_result["verdict"] == "VERIFIED":
            summary_parts.append("Email authenticated (SPF+DKIM+DMARC pass)")
        elif score_result["verdict"] == "SAFE":
            summary_parts.append("No significant threats detected")
        else:
            summary_parts.extend(content_result.get("risk_factors", [])[:3])

        port = os.getenv("PORT", "8000")
        response = AnalysisResponse(
            case_id=case_id,
            verdict=score_result["verdict"],
            risk_score=score_result["risk_score"],
            risk_band=score_result["risk_band"],
            risk_color=score_result["risk_color"],
            summary="; ".join(summary_parts) if summary_parts else "Analysis complete",
            authentication=auth_result,
            content_analysis={
                "content_risk_score": content_result["content_risk_score"],
                "risk_factors": content_result["risk_factors"],
                "phishing_signals": content_result.get("phishing_signals", []),
                "url_count": len(content_result.get("url_analysis", [])),
            },
            geoip_data={
                "relay_ip_count": len(relay_ips),
                "countries": relay_analysis.get("countries", []),
                "anomaly_score": relay_analysis.get("anomaly_score", 0),
                "flags": relay_analysis.get("flags", []),
            },
            score_breakdown=score_result["score_breakdown"],
            report_url=f"http://localhost:{port}/generate-report/{case_id}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            primaryCategory=content_result.get("primary_category", "SUSPICIOUS"),
            secondaryCategories=content_result.get("secondary_categories", []),
            forwardingAnalysis=content_result.get("forwarding_analysis"),
            sender=email_data.get("sender", ""),
            originalSender=content_result.get("forwarding_analysis", {}).get("original_sender"),
            forwarder=content_result.get("forwarding_analysis", {}).get("forwarded_by"),
            threatIndicators=content_result.get("risk_factors", []),
            earliest_reliable_observed_ip=relay_chain_data.get("earliest_reliable_observed_ip"),
            relay_chain=relay_chain_data.get("relay_chain", []),
            geo_disclaimer=threat_intel.GEO_DISCLAIMER,
            domain_intelligence=domain_intel_data,
            correlation=correlation_result,
            campaign=campaign_info,
            investigation_graph_summary=graph_data.get("summary"),
        )

        logger.info(
            f"analyze-trigger complete: case={case_id}, verdict={score_result['verdict']}, "
            f"score={score_result['risk_score']}"
        )
        return response

    except Exception as e:
        logger.error(f"analyze-trigger failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze-email")
async def analyze_email(request: AnalyzeEmailRequest):
    """
    Direct email analysis endpoint (bypasses Gmail API fetch).

    Useful for testing or analyzing forwarded email content directly.
    """
    logger.info(f"analyze-email: sender={request.sender}, subject={request.subject[:50]}")

    email_data = {
        "sender": request.sender,
        "to": os.getenv("GMAIL_USER_EMAIL", ""),
        "subject": request.subject,
        "text_body": request.body,
        "html_body": "",
        "urls": request.urls,
        "attachments": [],
        "authentication_results": "",
        "received_headers": [],
        "raw_headers": {},
        "date": datetime.utcnow().isoformat(),
        "message_id": "",
        "reply_to": "",
    }

    # Content analysis only (no Gmail API, no GeoIP)
    content_result = content_analyzer.analyze(email_data)

    return {
        "verdict": "SUSPICIOUS" if content_result["content_risk_score"] >= 45 else
                   "UNVERIFIED" if content_result["content_risk_score"] >= 20 else "SAFE",
        "risk_score": content_result["content_risk_score"],
        "content_analysis": content_result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/generate-report/{case_id}")
async def generate_report(case_id: str):
    """
    Download forensic PDF dossier by case ID.

    Returns the PDF file or 404 if the case ID is not found.
    """
    pdf_bytes = report_service.get_report(case_id)
    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail=f"Report {case_id} not found")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=ThreatVision_{case_id}.pdf"
        },
    )


@app.get("/reports")
async def list_reports():
    """List all generated forensic reports."""
    return report_service.list_reports()


# --------------------------------------------------------------------------- #
#  Additive Case Management, Graph & Retention Endpoints
# --------------------------------------------------------------------------- #

@app.get("/api/cases")
async def search_cases(
    sender: Optional[str] = None,
    domain: Optional[str] = None,
    verdict: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
):
    """
    Searchable case management endpoint with privacy masking.
    Supports filtering by sender, domain, verdict, risk band / threat category, or keyword.
    """
    cases = report_service.search_cases(
        sender=sender,
        domain=domain,
        verdict=verdict,
        category=category,
        search_query=search,
        limit=limit,
    )
    return {"total": len(cases), "cases": cases}


@app.get("/api/cases/{case_id}/graph")
async def get_case_graph(case_id: str):
    """
    Graph-based relationship analysis for a specific case.
    Returns bounded nodes and edges representing case provenance, infrastructure, URLs, and campaigns.
    """
    # Fetch case metadata
    cases = report_service.search_cases(search_query=case_id, limit=1)
    if not cases:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    target_case = cases[0]
    corr = correlation_service.correlate_case(case_id, target_case)
    graph = graph_service.build_case_graph(case_id, target_case, corr)
    return graph


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Retrieve details and member cases for an automated threat campaign."""
    camp = campaign_service.get_campaign_details(campaign_id)
    if not camp:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return camp


@app.post("/api/cases/retention/purge")
async def purge_retention(retention_days: int = 90):
    """Configurable retention control endpoint to purge records older than N days."""
    res = report_service.purge_expired_cases(retention_days=retention_days)
    return res


# --------------------------------------------------------------------------- #
#  Entry Point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    logger.info(f"Starting PS106 Threat Vision Backend on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
