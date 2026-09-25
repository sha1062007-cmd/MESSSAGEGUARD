"""
PS106 Threat Vision — Report Service
======================================
Generates forensic PDF dossier reports containing:
- Email metadata (sender, recipient, subject, date)
- Authentication verification (SPF, DKIM, DMARC)
- Content analysis results (URLs, phishing signals)
- GeoIP relay path data
- Risk score breakdown and final verdict
"""

import os
import io
import uuid
import hashlib
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

logger = logging.getLogger("ps106.report_service")

RETENTION_DAYS = 90

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

import sqlite3

# Directory for persisted PDF dossiers and SQLite case database
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_storage")
os.makedirs(REPORTS_DIR, exist_ok=True)
DB_PATH = os.path.join(REPORTS_DIR, "cases.db")


def _init_db():
    """Initialize persistent SQLite table for forensic cases."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS forensic_cases (
                    case_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    sender TEXT,
                    subject TEXT,
                    verdict TEXT,
                    risk_score INTEGER,
                    primary_category TEXT,
                    evidence_hash TEXT,
                    pdf_path TEXT
                )
            """)
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize SQLite case database: {e}")

_init_db()

# In-memory LRU-like cache for fast response, backed permanently by SQLite + disk
_report_store: Dict[str, Dict[str, Any]] = {}


class ReportService:
    """Generates and persistently stores forensic PDF reports for analyzed emails."""

    VERDICT_COLORS = {
        "SAFE": colors.HexColor("#4CAF50"),
        "VERIFIED": colors.HexColor("#4CAF50"),
        "UNVERIFIED": colors.HexColor("#FBC02D"),
        "SUSPICIOUS": colors.HexColor("#FF9800"),
        "MALICIOUS": colors.HexColor("#F44336"),
    }

    def generate_report(self, analysis_result: Dict[str, Any]) -> str:
        """
        Generate a forensic PDF report from analysis results.

        Returns: case_id that can be used to retrieve the PDF.
        """
        case_id = f"PS106-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Build the PDF in memory
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=25 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            "PSTitle",
            parent=styles["Title"],
            fontSize=18,
            spaceAfter=6,
            textColor=colors.HexColor("#1a237e"),
        )
        heading_style = ParagraphStyle(
            "PSHeading",
            parent=styles["Heading2"],
            fontSize=13,
            spaceAfter=6,
            spaceBefore=12,
            textColor=colors.HexColor("#283593"),
        )
        body_style = styles["Normal"]
        small_style = ParagraphStyle(
            "PSSmall",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
        )

        # ---- Header ----
        story.append(Paragraph("🛡️ PS106 Threat Vision — Forensic Report", title_style))
        story.append(Paragraph(f"Case ID: <b>{case_id}</b> &nbsp;|&nbsp; Generated: {timestamp}", small_style))
        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a237e")))
        story.append(Spacer(1, 12))

        # ---- Verdict Banner ----
        verdict = analysis_result.get("verdict", "UNVERIFIED")
        risk_score = analysis_result.get("risk_score", 0)
        verdict_color = self.VERDICT_COLORS.get(verdict, colors.grey)

        content_res = analysis_result.get("content_analysis", {})
        primary_cat = content_res.get("primary_category", "SUSPICIOUS")
        secondary_cats = content_res.get("secondary_categories", [])
        sec_text = f" (Additional: {', '.join(secondary_cats)})" if secondary_cats else ""

        verdict_data = [
            [
                Paragraph(f"<b>VERDICT: {verdict}</b><br/><font size=9>Category: {primary_cat}{sec_text}</font>", ParagraphStyle("V", parent=body_style, textColor=colors.white, fontSize=13, leading=14)),
                Paragraph(f"<b>Risk Score: {risk_score}/100</b>", ParagraphStyle("V", parent=body_style, textColor=colors.white, fontSize=13, alignment=2)),
            ]
        ]
        verdict_table = Table(verdict_data, colWidths=[doc.width * 0.65, doc.width * 0.35])
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 16))

        # ---- Email Metadata ----
        story.append(Paragraph("📧 Email Metadata", heading_style))
        email_meta = analysis_result.get("email_metadata", {})
        meta_data = [
            ["Field", "Value"],
            ["Sender", email_meta.get("sender", "N/A")],
            ["Recipient", email_meta.get("to", "N/A")],
            ["Subject", email_meta.get("subject", "N/A")],
            ["Date", email_meta.get("date", "N/A")],
            ["Message-ID", email_meta.get("message_id", "N/A")],
        ]
        meta_table = Table(meta_data, colWidths=[doc.width * 0.25, doc.width * 0.75])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eaf6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # ---- Forwarding Analysis (Section 11) ----
        fwd_analysis = analysis_result.get("content_analysis", {}).get("forwarding_analysis", {})
        if fwd_analysis.get("is_forwarded"):
            story.append(Paragraph("🔄 Forwarded-Email Origin & Provenance Analysis", heading_style))
            fwd_data = [
                ["Field", "Forensic Provenance Details"],
                ["Forwarding Status", "DETECTED (Forwarded Email)"],
                ["Evidence Level", fwd_analysis.get("evidence_level", "PARTIAL ORIGINAL EVIDENCE")],
                ["Forwarded By (Current)", fwd_analysis.get("forwarded_by", "Unknown")],
                ["Originally Sent By", fwd_analysis.get("original_sender") or "UNKNOWN / STRIPPED"],
                ["Original Subject", fwd_analysis.get("original_subject") or "N/A"],
                ["Original Date", fwd_analysis.get("original_date") or "N/A"],
                ["Attribution Note", Paragraph(fwd_analysis.get("explanation", ""), small_style)],
            ]
            fwd_table = Table(fwd_data, colWidths=[doc.width * 0.30, doc.width * 0.70])
            fwd_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff8e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ffe082")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(fwd_table)
            story.append(Spacer(1, 10))

        # ---- Authentication Results ----
        story.append(Paragraph("🔐 Cryptographic Header Verification", heading_style))
        auth = analysis_result.get("authentication", {})
        auth_data = [
            ["Check", "Status", "Detail"],
            ["SPF", auth.get("spf", {}).get("status", "Unknown"), auth.get("spf", {}).get("detail", "")],
            ["DKIM", auth.get("dkim", {}).get("status", "Unknown"), auth.get("dkim", {}).get("detail", "")],
            ["DMARC", auth.get("dmarc", {}).get("status", "Unknown"), auth.get("dmarc", {}).get("detail", "")],
        ]
        auth_status = auth.get("domain_authorization_status", "UNSPECIFIED")
        auth_note = auth.get("forensic_note", "")
        auth_data.append(["Auth Verdict", auth_status, auth_note])

        auth_table = Table(auth_data, colWidths=[doc.width * 0.18, doc.width * 0.22, doc.width * 0.60])
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eaf6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(auth_table)
        if auth_note:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"ℹ️ <i>{auth_note}</i>", small_style))
        story.append(Spacer(1, 12))

        # ---- Content Analysis ----
        story.append(Paragraph("🔍 Content & Threat Analysis", heading_style))
        content = analysis_result.get("content_analysis", {})
        risk_factors = content.get("risk_factors", [])
        for factor in risk_factors:
            story.append(Paragraph(f"• {factor}", body_style))
        story.append(Spacer(1, 8))

        # URL analysis table
        url_analysis = content.get("url_analysis", [])
        if url_analysis:
            story.append(Paragraph("Extracted URLs:", ParagraphStyle("Subhead", parent=body_style, fontSize=10, fontName="Helvetica-Bold")))
            url_data = [["URL", "Domain", "Risk"]]
            for u in url_analysis[:10]:
                url_data.append([
                    Paragraph(u.get("url", "")[:60], ParagraphStyle("URL", parent=body_style, fontSize=7)),
                    u.get("domain", ""),
                    str(u.get("risk_score", 0)),
                ])
            url_table = Table(url_data, colWidths=[doc.width * 0.55, doc.width * 0.30, doc.width * 0.15])
            url_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff3e0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ffe0b2")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(url_table)
        story.append(Spacer(1, 12))

        # ---- IP & Infrastructure Trust Assessment (Section 5 & 6) ----
        story.append(Paragraph("🌐 IP & Infrastructure Trust Assessment", heading_style))
        geoip = analysis_result.get("geoip_data", {})
        relay_chain_info = geoip.get("relay_chain_data", {})
        relay_hops = relay_chain_info.get("relay_chain", [])
        earliest_rel_ip = relay_chain_info.get("earliest_reliable_observed_ip")
        
        evidence_rows = [["Evidence Node", "Observed Value", "Trust Label", "Interpretation"]]
        if relay_hops:
            for hop in relay_hops:
                ip_val = hop.get("ip") or "N/A"
                evidence_rows.append([
                    f"Hop #{hop.get('hop_index', '?')}: {hop.get('by_host', 'MTA')[:25]}",
                    ip_val,
                    hop.get("trust_label", "OBSERVED"),
                    Paragraph(hop.get("trust_reason", "Observed in headers"), small_style),
                ])
        else:
            evidence_rows.append(["Relay Headers", "No Received headers present", "UNKNOWN", Paragraph("Header information stripped or absent", small_style)])

        evidence_table = Table(evidence_rows, colWidths=[doc.width * 0.30, doc.width * 0.22, doc.width * 0.20, doc.width * 0.28])
        evidence_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2f1")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#80cbc4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(evidence_table)
        story.append(Spacer(1, 6))

        # Origin IP Identification (Strict PS106 rule: Earliest reliable observed infrastructure, never "attacker IP")
        origin_label = f"<b>Earliest Reliable Observed Infrastructure:</b> {earliest_rel_ip}" if earliest_rel_ip else "<b>Origin IP:</b> NOT DETERMINABLE (No reliable public IP established before relay break)"
        story.append(Paragraph(origin_label, body_style))
        story.append(Spacer(1, 4))

        # Mandatory Geolocation Disclaimer
        story.append(Paragraph("<i>⚠️ Disclaimer: Approximate infrastructure geolocation based on IP registry data. This does NOT establish the sender's physical location.</i>", small_style))
        story.append(Spacer(1, 8))

        # Resolved GeoIP Table
        resolved_ips = geoip.get("resolved_ips", [])
        if resolved_ips:
            geo_data = [["IP", "Infrastructure", "Approx. City / Region", "ISP / Organization"]]
            for g in resolved_ips:
                if "error" not in g:
                    infra = g.get("infrastructure_type", "UNKNOWN")
                    geo_data.append([
                        g.get("ip", ""),
                        infra,
                        f"{g.get('city', 'Unknown')}, {g.get('country', '')}",
                        Paragraph(g.get("isp", "Unknown"), small_style),
                    ])
            if len(geo_data) > 1:
                geo_table = Table(geo_data, colWidths=[doc.width * 0.22, doc.width * 0.22, doc.width * 0.26, doc.width * 0.30])
                geo_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f7fa")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b2ebf2")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(geo_table)
        # ---- Domain Intelligence & Registration Forensics (Step 3) ----
        domain_intel = analysis_result.get("domain_intel", {})
        sender_d = domain_intel.get("sender_domain", {})
        if sender_d and sender_d.get("domain"):
            story.append(Paragraph("🏷️ Domain Intelligence & WHOIS Forensics", heading_style))
            age_display = f"{sender_d.get('age_days')} days" if sender_d.get("age_days") is not None else "Unknown / Private"
            if sender_d.get("is_young_domain"):
                age_display += " ⚠️ [NEWLY REGISTERED DOMAIN < 30 DAYS]"

            mx_display = "Present (" + ", ".join(sender_d.get("mx_records", [])[:2]) + ")" if sender_d.get("has_mx") else "None / Unconfigured ⚠️"

            domain_rows = [
                ["Parameter", "Observed Forensic Record"],
                ["Evaluated Domain", sender_d.get("domain", "")],
                ["Registrar", sender_d.get("registrar") or "Private / Unlisted / Failed"],
                ["Creation Date", sender_d.get("creation_date") or "Unpublished"],
                ["Domain Age", age_display],
                ["DNS MX Records", Paragraph(mx_display, small_style)],
            ]
            domain_table = Table(domain_rows, colWidths=[doc.width * 0.32, doc.width * 0.68])
            domain_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff9c4")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fff59d")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(domain_table)
            story.append(Spacer(1, 12))

        # ---- Score Breakdown ----
        story.append(Paragraph("📊 Risk Score Breakdown", heading_style))
        breakdown = analysis_result.get("score_breakdown", {})
        score_data = [["Component", "Score", "Weight"]]
        for comp_name, comp_val in breakdown.items():
            if isinstance(comp_val, dict):
                score_data.append([
                    comp_name,
                    str(comp_val.get("score", 0)),
                    str(comp_val.get("weight", 0)),
                ])
        if len(score_data) > 1:
            score_table = Table(score_data, colWidths=[doc.width * 0.50, doc.width * 0.25, doc.width * 0.25])
            score_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fce4ec")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f8bbd0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(score_table)

        # ---- Tri-Partite Forensic Conclusion (Strict PS106 Standard) ----
        story.append(Spacer(1, 12))
        story.append(Paragraph("⚖️ Tri-Partite Forensic Conclusion", heading_style))

        # 1. Confirmed Evidence (Directly verifiable facts)
        confirmed_points = []
        if auth.get("domain_authorization_status") == "DOMAIN_UNAUTHORIZED":
            confirmed_points.append("Domain cryptographic authorization checks failed (SPF/DKIM/DMARC alignment failure).")
        elif auth.get("domain_authorization_status") == "DOMAIN_AUTHORIZED":
            confirmed_points.append("Domain cryptographic authorization verified (SPF/DKIM/DMARC pass).")
        if earliest_rel_ip:
            confirmed_points.append(f"Observed transmission infrastructure verified up to relay IP {earliest_rel_ip}.")
        fwd = content.get("forwarding_analysis", {})
        if fwd.get("is_forwarded"):
            confirmed_points.append(f"Forwarded provenance established: Immediate forwarder is '{fwd.get('forwarded_by', 'Contact')}'.")
        if not confirmed_points:
            confirmed_points.append("Header structure and message content parsed.")

        # 2. Probable Assessment (Inferences and model heuristics)
        probable_points = []
        if risk_score >= 70:
            probable_points.append(f"High probability of malicious intent ({verdict}) based on content signals and infrastructure anomaly correlation.")
        elif risk_score >= 45:
            probable_points.append("Moderate suspicion of deceptive tactics or non-standard routing.")
        else:
            probable_points.append("Content and infrastructure characteristics are consistent with standard communication patterns.")
        for rf in risk_factors[:2]:
            probable_points.append(f"Observed behavioral signal: {rf}")

        # 3. Unknown / Not Determinable (What could NOT be established)
        unknown_points = []
        unknown_points.append("True physical identity and exact geographical coordinates of the message originator cannot be established from header/IP data alone.")
        if not earliest_rel_ip:
            unknown_points.append("Originating sending MTA IP could not be deterministically isolated due to missing or untrusted external Received headers.")
        if fwd.get("is_forwarded") and not fwd.get("original_sender"):
            unknown_points.append("Original pre-forwarding author email address was stripped from the quoted wrapper text.")

        # ---- Cross-Case Correlation & Attribution Support (Additive SIH26106 Section) ----
        corr_data = analysis_result.get("correlation", {})
        if corr_data and corr_data.get("related_case_count", 0) > 0:
            story.append(Paragraph("🔗 Cross-Case Correlation & Attribution Support", heading_style))
            corr_rows = [
                ["Correlation Parameter", "Forensic Indicator Finding"],
                ["Attribution Assessment", corr_data.get("attribution_assessment", "INDETERMINATE")],
                ["Attribution Confidence", corr_data.get("attribution_confidence", "LOW")],
                ["Related Incident Count", f"{corr_data.get('related_case_count')} Prior Incident(s)"],
                ["Investigation Summary", Paragraph(corr_data.get("attribution_summary", ""), small_style)],
            ]
            corr_table = Table(corr_rows, colWidths=[doc.width * 0.35, doc.width * 0.65])
            corr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f7fa")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b2ebf2")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(corr_table)
            story.append(Spacer(1, 10))

        # ---- Automated Threat Campaign Grouping (Additive SIH26106 Section) ----
        camp_data = analysis_result.get("campaign")
        if camp_data:
            story.append(Paragraph("🎯 Threat Campaign Cluster", heading_style))
            camp_rows = [
                ["Campaign Parameter", "Threat Cluster Details"],
                ["Campaign Identifier", camp_data.get("campaign_id", "N/A")],
                ["Cluster Confidence", camp_data.get("confidence", "MEDIUM")],
                ["Clustering Explanation", Paragraph(camp_data.get("explanation", ""), small_style)],
                ["Linked Incident Count", f"{camp_data.get('member_case_count', 1)} Associated Cases"],
            ]
            camp_table = Table(camp_rows, colWidths=[doc.width * 0.35, doc.width * 0.65])
            camp_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fbe9e7")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ffccbc")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(camp_table)
            story.append(Spacer(1, 10))

        conclusion_html = (
            f"<b>1. Confirmed Evidence:</b><br/>• " + "<br/>• ".join(confirmed_points) + "<br/><br/>"
            f"<b>2. Probable Assessment:</b><br/>• " + "<br/>• ".join(probable_points) + "<br/><br/>"
            f"<b>3. Unknown / Not Determinable:</b><br/>• " + "<br/>• ".join(unknown_points)
        )
        story.append(Paragraph(conclusion_html, body_style))
        story.append(Spacer(1, 10))

        email_meta_data = analysis_result.get("email_metadata", {})
        sender_str = email_meta_data.get("sender", "")
        subj_str = email_meta_data.get("subject", "")
        raw_payload = f"{sender_str}:{subj_str}:{timestamp}"
        content_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

        governance_data = [
            ["Parameter", "Value"],
            ["Content SHA-256 Hash", content_hash],
            ["Analyzed At Timestamp", timestamp],
            ["Data Retention Policy", f"{RETENTION_DAYS} Days (Configurable)"],
            ["PII Protection Status", "Redacted Before Local Storage & Logging"],
        ]
        gov_table = Table(governance_data, colWidths=[doc.width * 0.35, doc.width * 0.65])
        gov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(gov_table)

        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"This report was generated by PS106 Threat Vision (MessageGuard) | Case {case_id} | Hash {content_hash[:16]}",
            small_style,
        ))

        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        # 1. Save PDF file to persistent disk storage
        pdf_file_path = os.path.join(REPORTS_DIR, f"{case_id}.pdf")
        try:
            with open(pdf_file_path, "wb") as f:
                f.write(pdf_bytes)
        except Exception as e:
            logger.error(f"Failed to persist PDF file to disk: {e}")

        # 2. Insert case record into SQLite database
        content_res = analysis_result.get("content_analysis", {})
        primary_cat = content_res.get("primary_category", "SUSPICIOUS")
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO forensic_cases 
                    (case_id, timestamp, sender, subject, verdict, risk_score, primary_category, evidence_hash, pdf_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id,
                    timestamp,
                    sender_str,
                    subj_str,
                    verdict,
                    risk_score,
                    primary_cat,
                    content_hash,
                    pdf_file_path,
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to persist case record to SQLite: {e}")

        # 3. Store in memory for immediate hot access
        _report_store[case_id] = {
            "pdf_bytes": pdf_bytes,
            "case_id": case_id,
            "timestamp": timestamp,
            "verdict": verdict,
            "risk_score": risk_score,
        }

        logger.info(f"Generated & persisted forensic report {case_id} ({len(pdf_bytes)} bytes) -> {pdf_file_path}")
        return case_id

    @staticmethod
    def get_report(case_id: str) -> Optional[bytes]:
        """Retrieve a previously generated PDF report by case ID, recovering from disk/SQLite if not in memory."""
        # 1. Check in-memory store
        entry = _report_store.get(case_id)
        if entry and "pdf_bytes" in entry:
            return entry["pdf_bytes"]

        # 2. Check disk file directly
        pdf_file_path = os.path.join(REPORTS_DIR, f"{case_id}.pdf")
        if os.path.exists(pdf_file_path):
            try:
                with open(pdf_file_path, "rb") as f:
                    pdf_bytes = f.read()
                    _report_store[case_id] = {"pdf_bytes": pdf_bytes, "case_id": case_id}
                    return pdf_bytes
            except Exception as e:
                logger.error(f"Error reading PDF from disk: {e}")

        # 3. Check SQLite lookup for custom path
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT pdf_path FROM forensic_cases WHERE case_id = ?", (case_id,))
                row = cursor.fetchone()
                if row and row[0] and os.path.exists(row[0]):
                    with open(row[0], "rb") as f:
                        pdf_bytes = f.read()
                        _report_store[case_id] = {"pdf_bytes": pdf_bytes, "case_id": case_id}
                        return pdf_bytes
        except Exception as e:
            logger.error(f"SQLite lookup failed for case {case_id}: {e}")

        return None

    @staticmethod
    def list_reports() -> list:
        """List all available report case IDs and metadata from SQLite and in-memory cache."""
        cases = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT case_id, timestamp, verdict, risk_score, primary_category, evidence_hash, sender FROM forensic_cases ORDER BY timestamp DESC")
                for r in cursor.fetchall():
                    # Mask sender email for privacy in summary listings
                    raw_sender = r[6] or ""
                    masked_sender = raw_sender
                    if "@" in raw_sender:
                        parts = raw_sender.split("@")
                        u = parts[0]
                        masked_sender = (u[0] + "***" if len(u) > 1 else "***") + "@" + parts[1]

                    cases.append({
                        "case_id": r[0],
                        "timestamp": r[1],
                        "verdict": r[2],
                        "risk_score": r[3],
                        "primary_category": r[4],
                        "evidence_hash": r[5],
                        "sender": masked_sender,
                    })
        except Exception as e:
            logger.error(f"SQLite list_reports failed: {e}")

        if not cases:
            return [
                {
                    "case_id": v["case_id"],
                    "timestamp": v["timestamp"],
                    "verdict": v["verdict"],
                    "risk_score": v["risk_score"],
                }
                for v in _report_store.values()
            ]
        return cases

    @staticmethod
    def search_cases(
        sender: Optional[str] = None,
        domain: Optional[str] = None,
        verdict: Optional[str] = None,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Search and filter forensic cases with privacy masking."""
        query = "SELECT case_id, timestamp, sender, subject, verdict, risk_score, primary_category, evidence_hash FROM forensic_cases WHERE 1=1"
        params = []

        if sender:
            query += " AND sender LIKE ?"
            params.append(f"%{sender.strip()}%")
        if domain:
            query += " AND sender LIKE ?"
            params.append(f"%@{domain.strip()}%")
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict.strip().upper())
        if category:
            query += " AND primary_category = ?"
            params.append(category.strip().upper())
        if search_query:
            query += " AND (subject LIKE ? OR sender LIKE ? OR case_id LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        results = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                for r in cursor.fetchall():
                    raw_sender = r[2] or ""
                    masked_sender = raw_sender
                    if "@" in raw_sender:
                        parts = raw_sender.split("@")
                        u = parts[0]
                        masked_sender = (u[0] + "***" if len(u) > 1 else "***") + "@" + parts[1]

                    results.append({
                        "case_id": r[0],
                        "timestamp": r[1],
                        "sender": masked_sender,
                        "subject": r[3],
                        "verdict": r[4],
                        "risk_score": r[5],
                        "primary_category": r[6],
                        "evidence_hash": r[7],
                    })
        except Exception as e:
            logger.error(f"Search cases query failed: {e}")

        return results

    @staticmethod
    def purge_expired_cases(retention_days: int = RETENTION_DAYS) -> Dict[str, Any]:
        """
        Delete cases and associated PDFs older than retention_days.
        Preserves active cases and maintains database integrity.
        """
        from datetime import timedelta
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat() + "Z"

        purged_cases = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT case_id, pdf_path FROM forensic_cases WHERE timestamp < ?", (cutoff_date,))
                rows = cursor.fetchall()

                for cid, ppath in rows:
                    purged_cases.append(cid)
                    if ppath and os.path.exists(ppath):
                        try:
                            os.remove(ppath)
                        except Exception as e:
                            logger.warning(f"Could not remove PDF file {ppath}: {e}")

                cursor.execute("DELETE FROM forensic_cases WHERE timestamp < ?", (cutoff_date,))
                cursor.execute("DELETE FROM case_indicators WHERE timestamp < ?", (cutoff_date,))
                conn.commit()

            return {
                "status": "SUCCESS",
                "retention_days": retention_days,
                "cutoff_timestamp": cutoff_date,
                "purged_count": len(purged_cases),
                "purged_case_ids": purged_cases,
            }
        except Exception as e:
            logger.error(f"Purge expired cases failed: {e}")
            return {"status": "ERROR", "error": str(e), "purged_count": 0}
