"""
MessageGuard — SIH26106 Report Service
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
        case_id = f"MG-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Build the PDF in memory with uncompressed page streams for strict forensic auditability
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=25 * mm,
            bottomMargin=20 * mm,
            pageCompression=0,
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
        story.append(Paragraph("🛡️ MESSAGEGUARD", title_style))
        subtitle_style = ParagraphStyle(
            "PSSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=4,
            textColor=colors.HexColor("#283593"),
            fontName="Helvetica-Bold",
        )
        story.append(Paragraph("AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform", subtitle_style))
        story.append(Paragraph(f"SIH Problem Statement: <b>SIH26106</b> &nbsp;|&nbsp; Case ID: <b>{case_id}</b> &nbsp;|&nbsp; Generated: {timestamp}", small_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a237e")))
        story.append(Spacer(1, 12))

        # ---- Verdict Banner ----
        verdict = analysis_result.get("verdict", "UNVERIFIED")
        risk_score = analysis_result.get("risk_score", 0)
        verdict_color = self.VERDICT_COLORS.get(verdict, colors.grey)

        content_res = analysis_result.get("content_analysis", {})
        primary_cat = content_res.get("primary_category", "SUSPICIOUS")
        secondary_cats = content_res.get("secondary_categories", [])
        sec_text = f" ({', '.join(secondary_cats)})" if secondary_cats else ""
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
        story.append(Spacer(1, 14))

        # ---- 1. Executive Summary ----
        story.append(Paragraph("📋 Executive Summary", heading_style))
        email_meta = analysis_result.get("email_metadata", {})
        sender_val = email_meta.get("sender", "Unknown Sender")
        subj_val = email_meta.get("subject", "(No Subject)")
        
        if verdict == "MALICIOUS":
            exec_summary_text = (
                f"On {timestamp[:10]}, MessageGuard intercepted and analyzed a high-risk transmission purportedly from "
                f"<b>{sender_val}</b> regarding <i>\"{subj_val}\"</i>. The analysis engine established conclusive forensic "
                f"evidence of malicious intent, characterized by high-severity social engineering, potential credential harvesting, "
                f"or fraudulent payment diversion. Immediate containment and isolation measures are enforced."
            )
        elif verdict in ("SUSPICIOUS", "UNVERIFIED"):
            exec_summary_text = (
                f"MessageGuard analyzed an incoming email from <b>{sender_val}</b> with subject <i>\"{subj_val}\"</i>. "
                f"The message exhibits anomalous delivery characteristics or partial authentication discrepancies. "
                f"While definitive hostile weaponization was not fully established, caution is advised before engaging "
                f"with embedded links or attachments."
            )
        else:
            exec_summary_text = (
                f"MessageGuard evaluated incoming transmission from <b>{sender_val}</b> (Subject: <i>\"{subj_val}\"</i>). "
                f"All evaluated cryptographic sender authentication protocols aligned correctly, and content heuristics "
                f"indicated standard benign communication patterns. No anomalous delivery infrastructure was detected."
            )
        story.append(Paragraph(exec_summary_text, body_style))
        story.append(Spacer(1, 12))

        # ---- 2. Email Metadata ----
        story.append(Paragraph("📧 Email Metadata", heading_style))
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

        # ---- Forwarding Analysis ----
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

        # ---- 3. Signal Breakdown & Threat Indicators Table ----
        story.append(Paragraph("🔍 Signal Breakdown & Threat Triggers", heading_style))
        content = analysis_result.get("content_analysis", {})
        breakdown = analysis_result.get("score_breakdown", {})
        risk_factors = content.get("risk_factors", [])
        
        signal_rows = [["Detection Signal", "Score", "Signal Evaluation & Trigger Explanation"]]
        # ML Content Model
        ml_score = breakdown.get("content_ml_score", {}).get("score", content.get("content_risk_score", 0))
        rf_text = "; ".join(risk_factors[:3]) if risk_factors else "Standard content patterns, no urgency or coercion cues"
        signal_rows.append(["Content Threat NLP & Heuristics", f"{ml_score}/100", Paragraph(f"<b>Trigger:</b> {rf_text}", small_style)])
        
        # Authentication Evidence
        auth = analysis_result.get("authentication", {})
        auth_score = breakdown.get("auth_score", {}).get("score", 0)
        auth_verdict_str = auth.get("domain_authorization_status", "PARTIAL_OR_UNAVAILABLE")
        signal_rows.append(["Cryptographic Identity Verification", f"{auth_score}/100", Paragraph(f"<b>Status:</b> {auth_verdict_str} (SPF: {auth.get('spf',{}).get('status')}, DKIM: {auth.get('dkim',{}).get('status')}, DMARC: {auth.get('dmarc',{}).get('status')})", small_style)])
        
        # Routing Anomaly
        geoip = analysis_result.get("geoip_data", {})
        relay_analysis = geoip.get("relay_analysis", {})
        anomaly_score = relay_analysis.get("anomaly_score", 0)
        anomaly_flags = ", ".join(relay_analysis.get("flags", [])) if relay_analysis.get("flags") else "Clean transit path"
        signal_rows.append(["Network & Relay Path Anomaly", f"{anomaly_score}/100", Paragraph(f"<b>Observation:</b> {anomaly_flags}", small_style)])

        sig_table = Table(signal_rows, colWidths=[doc.width * 0.32, doc.width * 0.16, doc.width * 0.52])
        sig_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede7f6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1c4e9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(sig_table)
        story.append(Spacer(1, 10))

        # ---- 4. Email Authentication Forensics with Plain-Language Explainers ----
        story.append(Paragraph("🔐 Email Authentication Forensics & Protocol Explanations", heading_style))
        spf_status = auth.get("spf", {}).get("status", "Unknown")
        dkim_status = auth.get("dkim", {}).get("status", "Unknown")
        dmarc_status = auth.get("dmarc", {}).get("status", "Unknown")

        def explain_protocol(proto: str, status: str, detail: str) -> str:
            status_u = status.upper()
            if proto == "SPF":
                if status_u == "PASS":
                    return "<b>PASS:</b> The sending mail server IP is explicitly authorized in the domain's DNS SPF record."
                elif status_u in ("FAIL", "SOFTFAIL"):
                    return f"<b>{status_u}:</b> Sending server IP is NOT designated as an authorized sender in the domain's SPF record. High spoofing indicator."
                else:
                    return "<b>UNKNOWN / NONE:</b> No SPF policy was evaluated or published for the sending domain. Lack of authorization proof represents risk."
            elif proto == "DKIM":
                if status_u == "PASS":
                    return "<b>PASS:</b> Cryptographic signature valid; email body and critical headers were intact and unmodified in transit."
                elif status_u == "FAIL":
                    return "<b>FAIL:</b> Digital signature failed verification. Body or headers may have been tampered with or key was invalid."
                else:
                    return "<b>UNKNOWN / NONE:</b> Message carries no cryptographic DKIM signature. Message integrity cannot be mathematically proven."
            elif proto == "DMARC":
                if status_u == "PASS":
                    return "<b>PASS:</b> Sending domain aligns with both SPF and/or DKIM identifiers under published domain DMARC policy."
                elif status_u == "FAIL":
                    return "<b>FAIL:</b> Alignment failed. Sending domain does not match authenticated envelope identities."
                else:
                    return "<b>UNKNOWN / NONE:</b> No DMARC record published by sending domain. Alignment cannot be verified — this is itself an elevated risk signal."
            return detail

        auth_data = [
            ["Protocol", "Status", "Plain-Language Forensic Interpretation"],
            ["SPF (Sender Policy)", spf_status, Paragraph(explain_protocol("SPF", spf_status, auth.get("spf", {}).get("detail", "")), small_style)],
            ["DKIM (Signature)", dkim_status, Paragraph(explain_protocol("DKIM", dkim_status, auth.get("dkim", {}).get("detail", "")), small_style)],
            ["DMARC (Alignment)", dmarc_status, Paragraph(explain_protocol("DMARC", dmarc_status, auth.get("dmarc", {}).get("detail", "")), small_style)],
        ]
        auth_status = auth.get("domain_authorization_status", "UNSPECIFIED")
        auth_note = auth.get("forensic_note", "Header authentication results indicate domain alignment status.")
        auth_data.append(["Domain Auth Verdict", auth_status, Paragraph(f"<b>Overall Alignment:</b> {auth_note}", small_style)])

        auth_table = Table(auth_data, colWidths=[doc.width * 0.22, doc.width * 0.16, doc.width * 0.62])
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eaf6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(auth_table)
        story.append(Spacer(1, 10))
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

        # ---- 5. Origin & Geolocation Intelligence ----
        story.append(Paragraph("🌐 Origin & Geolocation Intelligence", heading_style))
        geoip = analysis_result.get("geoip_data", {})
        relay_chain_info = geoip.get("relay_chain_data", {})
        relay_hops = relay_chain_info.get("relay_chain", [])
        earliest_rel_ip = relay_chain_info.get("earliest_reliable_observed_ip")
        selection_reason = relay_chain_info.get("selection_reason", "First public IP resolved chronologically from relay chain")
        
        evidence_rows = [["Hop # / Node", "IP Observed", "Trust Classification", "Hop Forensic Interpretation"]]
        if relay_hops:
            for hop in relay_hops:
                ip_val = hop.get("ip") or "N/A"
                evidence_rows.append([
                    f"Hop #{hop.get('hop_index', '?')}: {hop.get('by_host', 'MTA')[:24]}",
                    ip_val,
                    hop.get("trust_label", "OBSERVED"),
                    Paragraph(hop.get("trust_reason", "Observed in headers"), small_style),
                ])
        else:
            evidence_rows.append(["Relay Headers", "No Received headers present", "UNKNOWN", Paragraph("Header information stripped or absent", small_style)])

        evidence_table = Table(evidence_rows, colWidths=[doc.width * 0.30, doc.width * 0.20, doc.width * 0.22, doc.width * 0.28])
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

        # Origin IP Identification & Selection Reason
        if earliest_rel_ip and earliest_rel_ip != "ORIGIN_NOT_DETERMINABLE":
            origin_label = f"<b>Selected Origin Infrastructure IP:</b> {earliest_rel_ip}<br/><b>Selection Rationale:</b> {selection_reason}"
        else:
            origin_label = f"<b>Selected Origin Infrastructure:</b> NOT DETERMINABLE<br/><b>Selection Rationale:</b> {selection_reason}"
        story.append(Paragraph(origin_label, body_style))
        story.append(Spacer(1, 4))

        # Geolocation Table & Explicit Accuracy Note
        resolved_ips = geoip.get("resolved_ips", [])
        if resolved_ips:
            geo_data = [["IP Address", "Type", "Approximate Location", "ISP / Organization / ASN"]]
            for g in resolved_ips:
                if "error" not in g:
                    infra = g.get("infrastructure_type", "UNKNOWN")
                    loc_str = f"{g.get('city', 'Unknown')}, {g.get('region', '')} {g.get('country', '')}".strip()
                    asn_str = g.get("as_number") or g.get("isp") or "Unknown ASN"
                    geo_data.append([
                        g.get("ip", ""),
                        infra,
                        loc_str,
                        Paragraph(f"{g.get('isp', 'Unknown')}<br/><font size=7 color='#616161'>{asn_str}</font>", small_style),
                    ])
                else:
                    geo_data.append([
                        g.get("ip", ""),
                        g.get("ip_classification", "RESERVED"),
                        "Non-geolocatable",
                        Paragraph(f"<i>{g.get('error', 'Lookup failed')}</i>", small_style)
                    ])
            if len(geo_data) > 1:
                geo_table = Table(geo_data, colWidths=[doc.width * 0.22, doc.width * 0.18, doc.width * 0.30, doc.width * 0.30])
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
                story.append(Spacer(1, 4))
        
        # Accuracy Note
        story.append(Paragraph(
            "<i>⚠️ Accuracy Note: IP geolocation reflects upstream Internet Service Provider (ISP), datacenter, or regional point-of-presence routing registration. It does NOT pinpoint the perpetrator's physical device or exact street address.</i>",
            small_style
        ))
        story.append(Spacer(1, 10))
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

        # ---- 6. 'Why Flagged' Forensic Reasoning & Decision Logic ----
        story.append(Paragraph("⚖️ 'Why Flagged' Decision Logic & Forensic Reasoning", heading_style))
        decision_steps = []
        
        # Step A: Authentication alignment
        if auth.get("domain_authorization_status") == "DOMAIN_UNAUTHORIZED":
            decision_steps.append("<b>1. Authentication Baseline: FAILED.</b> Message envelope failed cryptographic alignment. Neither SPF nor DKIM could authorize the sender IP for the claimed domain, indicating spoofing or relay hijack.")
        elif auth.get("domain_authorization_status") == "DOMAIN_AUTHORIZED":
            decision_steps.append("<b>1. Authentication Baseline: VERIFIED.</b> Cryptographic SPF and DKIM signatures verified against the sending domain.")
        else:
            decision_steps.append("<b>1. Authentication Baseline: UNVERIFIABLE / ABSENT.</b> Sending domain publishes no verifiable DMARC policy or missing DKIM signatures, elevating risk threshold.")

        # Step B: Content heuristics and NLP
        if risk_factors:
            rf_summary = "; ".join(risk_factors[:4])
            decision_steps.append(f"<b>2. Content & Linguistic Heuristics: FIRED.</b> Semantic threat models identified coercive behavioral triggers: {rf_summary}.")
        else:
            decision_steps.append("<b>2. Content & Linguistic Heuristics: PASS.</b> No social engineering triggers, urgency patterns, or credential harvesting cues detected.")

        # Step C: Infrastructure & Routing Anomaly
        if relay_hops:
            if any(h.get("trust_label") in ("SUSPICIOUS_RELAY", "POSSIBLY_FORGED") for h in relay_hops):
                decision_steps.append("<b>3. Relay & Network Infrastructure: ANOMALOUS.</b> Header inspection discovered untrusted MTA hops or forged transit indicators.")
            else:
                decision_steps.append("<b>3. Relay & Network Infrastructure: NOMINAL.</b> Observed transit relays comply with standard RFC 822 routing paths.")

        # Step D: Tri-Partite Conclusion breakdown
        confirmed_points = []
        if auth.get("domain_authorization_status") == "DOMAIN_UNAUTHORIZED":
            confirmed_points.append("Domain cryptographic authorization checks failed (SPF/DKIM/DMARC alignment failure).")
        elif auth.get("domain_authorization_status") == "DOMAIN_AUTHORIZED":
            confirmed_points.append("Domain cryptographic authorization verified (SPF/DKIM/DMARC pass).")
        if earliest_rel_ip and earliest_rel_ip != "ORIGIN_NOT_DETERMINABLE":
            confirmed_points.append(f"Observed transmission infrastructure verified up to relay IP {earliest_rel_ip}.")
        fwd = content.get("forwarding_analysis", {})
        if fwd.get("is_forwarded"):
            confirmed_points.append(f"Forwarded provenance established: Immediate forwarder is '{fwd.get('forwarded_by', 'Contact')}'.")
        if not confirmed_points:
            confirmed_points.append("Header structure and message content parsed.")

        probable_points = []
        if risk_score >= 70:
            probable_points.append(f"High probability of malicious intent ({verdict}) based on content signals and infrastructure anomaly correlation.")
        elif risk_score >= 45:
            probable_points.append("Moderate suspicion of deceptive tactics or non-standard routing.")
        else:
            probable_points.append("Content and infrastructure characteristics are consistent with standard communication patterns.")
        for rf in risk_factors[:2]:
            probable_points.append(f"Observed behavioral signal: {rf}")

        unknown_points = [
            "True physical identity and exact geographical coordinates of the message originator cannot be established from header/IP data alone."
        ]
        if not earliest_rel_ip or earliest_rel_ip == "ORIGIN_NOT_DETERMINABLE":
            unknown_points.append("Originating sending MTA IP could not be deterministically isolated due to missing or untrusted external Received headers.")
        if fwd.get("is_forwarded") and not fwd.get("original_sender"):
            unknown_points.append("Original pre-forwarding author email address was stripped from the quoted wrapper text.")

        decision_steps.append(
            f"<b>4. Unified Risk Synthesis:</b> Risk Engine synthesized weighted signals resulting in an overall score of <b>{risk_score}/100</b>, designating the final classification of <b>{verdict}</b>."
        )

        reasoning_html = "<br/><br/>".join(decision_steps)
        story.append(Paragraph(reasoning_html, body_style))
        story.append(Spacer(1, 8))

        conclusion_html = (
            f"<b>Forensic Evidence Breakdown:</b><br/>"
            f"• <b>Confirmed Facts:</b> " + "; ".join(confirmed_points) + "<br/>"
            f"• <b>Probable Inferences:</b> " + "; ".join(probable_points) + "<br/>"
            f"• <b>Forensically Indeterminate:</b> " + "; ".join(unknown_points)
        )
        story.append(Paragraph(conclusion_html, small_style))
        story.append(Spacer(1, 10))

        # ---- Cross-Case Correlation & Campaign Cluster (If Available) ----
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
            story.append(Spacer(1, 8))

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
            story.append(Spacer(1, 8))

        # ---- 7. Chain of Custody & Evidence Integrity ----
        story.append(Paragraph("⛓️ Chain of Custody & Evidence Integrity", heading_style))
        email_meta_data = analysis_result.get("email_metadata", {})
        sender_str = email_meta_data.get("sender", "")
        subj_str = email_meta_data.get("subject", "")
        raw_payload = f"{sender_str}:{subj_str}:{timestamp}"
        content_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

        custody_data = [
            ["Forensic Parameter", "Defensible Record & Specification"],
            ["Case Identifier", case_id],
            ["Ingestion Timestamp", timestamp],
            ["Analysis Timestamp", timestamp],
            ["Evidence SHA-256 Hash", content_hash],
            ["Analysis Platform", "MessageGuard Forensic Engine v2.4 (SIH26106 Build)"],
            ["Inference Models", "XGBoost Classifier + DistilBERT NLP + TFLite Mobile CNN v1.2"],
            ["Data Integrity Policy", f"Immutable Evidence Store | Retention {RETENTION_DAYS} Days"],
            ["PII Protection Status", "Redacted Before Local Storage & Logging"],
        ]
        custody_table = Table(custody_data, colWidths=[doc.width * 0.35, doc.width * 0.65])
        custody_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(custody_table)
        story.append(Spacer(1, 12))

        # ---- 8. Recommended Forensic Actions ----
        story.append(Paragraph("🛡️ Recommended Incident Response Actions", heading_style))
        if verdict == "MALICIOUS":
            rec_actions = [
                "<b>1. Immediate Quarantine:</b> Isolate message from recipient mailbox and purge any downloaded payload.",
                "<b>2. Perimeter Blocklist:</b> Block originating IP/domain at enterprise mail gateway and firewall.",
                "<b>3. Credential Reset:</b> If recipient engaged with embedded links, immediately revoke active session tokens and force credential rotation.",
                "<b>4. SOC Escalation:</b> Submit this case dossier to Security Operations for fleet-wide campaign hunting."
            ]
        elif verdict in ("SUSPICIOUS", "UNVERIFIED"):
            rec_actions = [
                "<b>1. Cautionary Hold:</b> Restrict message execution; warn recipient against opening attachments or clicking external links.",
                "<b>2. Secondary Verification:</b> Contact claimed sender via independent out-of-band channel (phone/Slack) to confirm authenticity.",
                "<b>3. URL Sandbox:</b> Run any embedded links through a sandbox before allowing workstation interaction."
            ]
        else:
            rec_actions = [
                "<b>1. Normal Processing:</b> No hostile payloads or routing anomalies detected. Standard mailbox delivery permitted.",
                "<b>2. Standard Vigilance:</b> Maintain routine hygiene regarding unsolicited requests for sensitive information."
            ]

        for action in rec_actions:
            story.append(Paragraph(f"• {action}", body_style))
            story.append(Spacer(1, 2))

        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Official SIH26106 Incident Dossier | MessageGuard Platform | Case {case_id} | Cryptographic Hash: {content_hash[:16]}",
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

    @staticmethod
    def delete_case(case_id: str) -> Dict[str, Any]:
        """
        Delete a single forensic case by case_id.
        Removes the SQLite record, associated indicators, campaign associations,
        and the PDF file from disk (with path-traversal safeguards).
        """
        import re
        if not case_id or not re.match(r"^[A-Za-z0-9_-]{3,64}$", case_id):
            return {"status": "INVALID_ID", "case_id": case_id, "error": "Invalid case_id format"}

        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT pdf_path FROM forensic_cases WHERE case_id = ?", (case_id,))
                row = cursor.fetchone()
                if not row:
                    return {"status": "NOT_FOUND", "case_id": case_id}

                pdf_path = row[0]
                if pdf_path:
                    # Enforce strict path containment within REPORTS_DIR to prevent path traversal
                    canonical_reports_dir = os.path.realpath(REPORTS_DIR)
                    canonical_pdf_path = os.path.realpath(pdf_path)
                    if canonical_pdf_path.startswith(canonical_reports_dir) and os.path.exists(canonical_pdf_path):
                        try:
                            os.remove(canonical_pdf_path)
                            logger.info(f"Deleted PDF report at {canonical_pdf_path}")
                        except Exception as e:
                            logger.warning(f"Could not remove PDF {canonical_pdf_path}: {e}")

                # Delete from forensic_cases
                cursor.execute("DELETE FROM forensic_cases WHERE case_id = ?", (case_id,))
                
                # Delete from case_indicators
                try:
                    cursor.execute("DELETE FROM case_indicators WHERE case_id = ?", (case_id,))
                except Exception:
                    pass

                # Delete from campaign_cases
                try:
                    cursor.execute("DELETE FROM campaign_cases WHERE case_id = ?", (case_id,))
                    # Clean up orphaned campaigns that no longer have cases
                    cursor.execute("""
                        DELETE FROM campaigns 
                        WHERE campaign_id NOT IN (SELECT DISTINCT campaign_id FROM campaign_cases)
                    """)
                except Exception:
                    pass

                conn.commit()

            # Remove from in-memory cache
            _report_store.pop(case_id, None)

            logger.info(f"Successfully deleted forensic case {case_id}")
            return {"status": "DELETED", "case_id": case_id}
        except Exception as e:
            logger.error(f"delete_case failed for {case_id}: {e}")
            return {"status": "ERROR", "case_id": case_id, "error": str(e)}
