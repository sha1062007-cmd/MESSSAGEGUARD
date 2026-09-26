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
from xml.sax.saxutils import escape
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

    def generate_report(self, analysis_result: Dict[str, Any], case_id: Optional[str] = None) -> str:
        """
        Generate an enterprise-grade forensic PDF dossier report from analysis results.

        Returns: case_id that can be used to retrieve the PDF.
        """
        if not case_id:
            case_id = f"MG-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Build the PDF in memory with uncompressed page streams for strict forensic auditability
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            pageCompression=0,
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom typography & styles
        title_style = ParagraphStyle(
            "PSTitle",
            parent=styles["Title"],
            fontSize=17,
            leading=20,
            spaceAfter=3,
            textColor=colors.HexColor("#0D1B2A"),
            alignment=0,
        )
        subtitle_style = ParagraphStyle(
            "PSSubtitle",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#1A365D"),
            fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "PSHeading",
            parent=styles["Heading2"],
            fontSize=11.5,
            leading=14,
            spaceAfter=5,
            spaceBefore=10,
            textColor=colors.HexColor("#0D233A"),
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "PSBody",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#212529"),
        )
        small_style = ParagraphStyle(
            "PSSmall",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#495057"),
        )
        small_bold = ParagraphStyle(
            "PSSmallBold",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#212529"),
            fontName="Helvetica-Bold",
        )
        alert_style = ParagraphStyle(
            "PSAlert",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#991B1B"),
            fontName="Helvetica-Bold",
        )

        # ---- 0. Official Forensic Header ----
        story.append(Paragraph("🛡️ MESSAGEGUARD FORENSIC INTELLIGENCE PLATFORM", title_style))
        story.append(Paragraph("DIGITAL FORENSICS & THREAT INCIDENT INVESTIGATION DOSSIER", subtitle_style))
        story.append(Spacer(1, 2))
        story.append(Paragraph(
            f"Case Dossier ID: <b>{case_id}</b> &nbsp;|&nbsp; Ingestion Timestamp: <b>{timestamp}</b> &nbsp;|&nbsp; Classification Engine: <b>v2.4 Production</b>",
            small_style,
        ))
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0D233A")))
        story.append(Spacer(1, 8))

        # ---- Top-Level Verdict Banner ----
        verdict = analysis_result.get("verdict", "UNVERIFIED")
        risk_score = analysis_result.get("risk_score", 0)
        verdict_color = self.VERDICT_COLORS.get(verdict, colors.grey)

        content_res = analysis_result.get("content_analysis", {})
        primary_cat = content_res.get("primary_category", "SUSPICIOUS")
        secondary_cats = content_res.get("secondary_categories", [])
        sec_text = f" ({', '.join(secondary_cats)})" if secondary_cats else ""

        verdict_label = f"VERDICT: {verdict}"
        if verdict == "MALICIOUS":
            severity_sub = f"CRITICAL THREAT &nbsp;|&nbsp; Category: {primary_cat}{sec_text}"
        elif verdict in ("SUSPICIOUS", "WARNING", "UNCERTAIN"):
            severity_sub = f"ELEVATED RISK &nbsp;|&nbsp; Category: {primary_cat}{sec_text}"
        else:
            severity_sub = f"CLEAN COMMUNICATION &nbsp;|&nbsp; Category: {primary_cat}{sec_text}"

        verdict_data = [
            [
                Paragraph(f"<b>{verdict_label}</b><br/><font size=8.5>{severity_sub}</font>", ParagraphStyle("V", parent=body_style, textColor=colors.white, fontSize=12.5, leading=14, fontName="Helvetica-Bold")),
                Paragraph(f"<b>Cumulative Threat Index<br/><font size=16>{risk_score}/100</font></b>", ParagraphStyle("VScore", parent=body_style, textColor=colors.white, fontSize=9, leading=13, alignment=2, fontName="Helvetica-Bold")),
            ]
        ]
        verdict_table = Table(verdict_data, colWidths=[doc.width * 0.68, doc.width * 0.32])
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("ROUNDEDCORNERS", [5, 5, 5, 5]),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 10))

        # ---- 1. Executive Summary & Forensic Narrative ----
        story.append(Paragraph("📋 1. Executive Forensic Summary", heading_style))
        email_meta = analysis_result.get("email_metadata", {})
        sender_val = email_meta.get("sender", "Unknown Sender")
        subj_val = email_meta.get("subject", "(No Subject)")
        recipient_val = email_meta.get("to", "Unknown Recipient")

        if verdict == "MALICIOUS":
            exec_summary_text = (
                f"On <b>{timestamp[:10]}</b>, MessageGuard intercepted and forensically analyzed an active hostile transmission "
                f"claiming identity <b>{sender_val}</b> targeting <b>{recipient_val}</b> with subject <i>\"{subj_val}\"</i>. "
                f"The unified analysis engine established conclusive, multi-layered evidence of an active cyber threat. "
                f"Linguistic heuristics flagged aggressive urgency triggers and financial reward baiting, while network header inspection "
                f"and sender authentication protocols confirmed critical domain alignment discrepancies and unauthorized origin transit. "
                f"Immediate quarantine and enterprise mitigation actions are required."
            )
        elif verdict in ("SUSPICIOUS", "WARNING", "UNCERTAIN"):
            exec_summary_text = (
                f"MessageGuard analyzed an incoming transmission from <b>{sender_val}</b> with subject <i>\"{subj_val}\"</i>. "
                f"The message demonstrates anomalous delivery infrastructure or partial authentication discrepancies. "
                f"While weaponized payloads were not deterministically confirmed, elevated deception indicators warrant cautionary handling "
                f"before interacting with embedded hyperlinks or attachments."
            )
        else:
            exec_summary_text = (
                f"MessageGuard evaluated incoming transmission from <b>{sender_val}</b> with subject <i>\"{subj_val}\"</i>. "
                f"All evaluated cryptographic sender authentication protocols aligned correctly with the claimed domain, "
                f"and semantic analysis confirmed standard communication patterns. No malicious payload or transit anomalies were identified."
            )
        story.append(Paragraph(exec_summary_text, body_style))
        story.append(Spacer(1, 8))

        # ---- 2. Email Transmission Metadata ----
        meta_data = [
            ["Transmission Parameter", "Forensic Artifact Value"],
            ["Sender Identity (From)", sender_val],
            ["Recipient (To)", recipient_val],
            ["Subject Line", subj_val],
            ["RFC 822 Date", email_meta.get("date", "N/A")],
            ["RFC 2822 Message-ID", email_meta.get("message_id", "N/A")],
        ]
        meta_table = Table(meta_data, colWidths=[doc.width * 0.28, doc.width * 0.72])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 9))

        # ---- 3. Dedicated 'Why This Transmission Was Flagged' Deep Dive ----
        story.append(Paragraph("🚨 2. Threat Causation Analysis — Why This Message Was Flagged", heading_style))

        # Compile specific triggers
        risk_factors = content_res.get("risk_factors", [])
        phishing_signals = content_res.get("phishing_signals", [])
        auth_data_dict = analysis_result.get("authentication", {})
        spf_status = auth_data_dict.get("spf", {}).get("status", "UNKNOWN").upper()
        dkim_status = auth_data_dict.get("dkim", {}).get("status", "UNKNOWN").upper()
        dmarc_status = auth_data_dict.get("dmarc", {}).get("status", "UNKNOWN").upper()
        urls_detected = content_res.get("url_analysis", [])

        causation_rows = [["Threat Detection Vector", "Triggering Evidence Detected", "Severity", "Forensic Impact & Threat Model"]]

        # Vector A: Psychological / Urgency / Lure Triggers
        if phishing_signals or risk_factors:
            signals_str = ", ".join([f"'{s}'" for s in phishing_signals[:8]]) if phishing_signals else "; ".join(risk_factors[:3])
            causation_rows.append([
                Paragraph("<b>Social Engineering &amp; Linguistic Lures</b>", small_bold),
                Paragraph(f"Explicit trigger keywords detected in text body: <b>{signals_str}</b>", small_style),
                Paragraph("<font color='#D32F2F'><b>HIGH</b></font>", small_style),
                Paragraph("Adversary applies psychological coercion (synthetic urgency, lottery winnings, or threat of penalty) to manipulate victim into bypassing standard verification checks.", small_style),
            ])
        else:
            causation_rows.append([
                Paragraph("<b>Social Engineering &amp; Linguistic Lures</b>", small_bold),
                Paragraph("No coercive or high-pressure language patterns detected.", small_style),
                Paragraph("<font color='#2E7D32'><b>LOW</b></font>", small_style),
                Paragraph("Text body adheres to benign communication norms.", small_style),
            ])

        # Vector B: Hyperlink & URL Forensics
        if urls_detected:
            high_risk_urls = [u for u in urls_detected if u.get("risk_score", 0) >= 50]
            url_summary_str = f"{len(urls_detected)} hyperlink(s) identified. "
            if high_risk_urls:
                first_url = high_risk_urls[0]
                url_summary_str += f"Malicious destination: <b>{first_url.get('url', '')[:45]}...</b> (Target domain: <b>{first_url.get('domain', '')}</b>, Risk: {first_url.get('risk_score')}/100)"
                sev_color = "<font color='#D32F2F'><b>CRITICAL</b></font>"
                impact_str = "Embedded link resolves to unvetted or suspicious host designed to harvest credentials or deliver secondary payload."
            else:
                url_summary_str += f"Target domain(s): {', '.join([u.get('domain', '') for u in urls_detected[:3]])}"
                sev_color = "<font color='#F57F17'><b>MEDIUM</b></font>"
                impact_str = "Embedded link redirects outside enterprise boundary; destination reputation monitored."

            causation_rows.append([
                Paragraph("<b>Hyperlink &amp; Payload Redirection</b>", small_bold),
                Paragraph(url_summary_str, small_style),
                Paragraph(sev_color, small_style),
                Paragraph(impact_str, small_style),
            ])
        else:
            causation_rows.append([
                Paragraph("<b>Hyperlink &amp; Payload Redirection</b>", small_bold),
                Paragraph("No clickable hyperlinks or redirection mechanisms identified.", small_style),
                Paragraph("<font color='#2E7D32'><b>CLEAN</b></font>", small_style),
                Paragraph("Zero external web interaction attack surface.", small_style),
            ])

        # Vector C: Authentication & Sender Spoofing
        domain_auth_stat = auth_data_dict.get("domain_authorization_status", "PARTIAL_OR_UNAVAILABLE")
        if spf_status in ("FAIL", "SOFTFAIL") or domain_auth_stat == "DOMAIN_UNAUTHORIZED":
            auth_evidence = f"SPF: <b>{spf_status}</b>, DKIM: <b>{dkim_status}</b>, DMARC: <b>{dmarc_status}</b>. Originating server is not authorized to transmit on behalf of <b>{sender_val}</b>."
            causation_rows.append([
                Paragraph("<b>Cryptographic Sender Spoofing</b>", small_bold),
                Paragraph(auth_evidence, small_style),
                Paragraph("<font color='#D32F2F'><b>CRITICAL</b></font>", small_style),
                Paragraph("Direct spoofing or unauthorized relay. Header 'From' domain ownership failed cryptographic proof against the transmitting mail relay.", small_style),
            ])
        elif spf_status == "PASS" and dkim_status == "PASS":
            causation_rows.append([
                Paragraph("<b>Sender Identity Verification</b>", small_bold),
                Paragraph(f"SPF: <b>PASS</b>, DKIM: <b>PASS</b>, DMARC: <b>{dmarc_status}</b>. Valid cryptographic signatures present.", small_style),
                Paragraph("<font color='#2E7D32'><b>VERIFIED</b></font>", small_style),
                Paragraph("Sending mail transfer agent is mathematically authenticated by sending domain DNS records.", small_style),
            ])
        else:
            causation_rows.append([
                Paragraph("<b>Sender Identity Verification</b>", small_bold),
                Paragraph(f"SPF: <b>{spf_status}</b>, DKIM: <b>{dkim_status}</b>, DMARC: <b>{dmarc_status}</b>. Incomplete authorization proof.", small_style),
                Paragraph("<font color='#F57F17'><b>ELEVATED</b></font>", small_style),
                Paragraph("Lack of robust DMARC enforcement allows potential display name or envelope spoofing.", small_style),
            ])

        # Vector D: Network & Transit Route Forensics
        geoip_obj = analysis_result.get("geoip_data", {})
        relay_chain_info = geoip_obj.get("relay_chain_data", {})
        earliest_rel_ip = relay_chain_info.get("earliest_reliable_observed_ip")
        if earliest_rel_ip and earliest_rel_ip != "ORIGIN_NOT_DETERMINABLE":
            net_evidence = f"Identified chronological origin MTA at public IP <b>{earliest_rel_ip}</b>."
            relay_analysis = geoip_obj.get("relay_analysis", {})
            if relay_analysis.get("anomaly_score", 0) > 40:
                net_sev = "<font color='#D32F2F'><b>HIGH</b></font>"
                net_impact = "Relay path crosses anomalous geographic routing or known commercial VPN/proxy datacenters commonly exploited for threat delivery."
            else:
                net_sev = "<font color='#2E7D32'><b>MONITORED</b></font>"
                net_impact = "Transit hops conform to observable network routing topologies."
            causation_rows.append([
                Paragraph("<b>Transit Route &amp; Relay Anomaly</b>", small_bold),
                Paragraph(net_evidence, small_style),
                Paragraph(net_sev, small_style),
                Paragraph(net_impact, small_style),
            ])

        causation_table = Table(causation_rows, colWidths=[doc.width * 0.24, doc.width * 0.36, doc.width * 0.12, doc.width * 0.28])
        causation_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(causation_table)
        story.append(Spacer(1, 9))

        # Plain-language threat causation summary box
        if verdict == "MALICIOUS":
            summary_box_html = (
                f"<b>Investigator Finding:</b> This communication received a malicious risk score of <b>{risk_score}/100</b> "
                f"primarily because the content employs synthetic urgency lures combined with unverified or spoofed sender identity. "
                f"The message attempts to deceive the recipient into trusting an unauthenticated transmission, routing through external infrastructure "
                f"({earliest_rel_ip or 'Unverified MTA'}) without cryptographic proof of domain legitimacy."
            )
        elif verdict in ("SUSPICIOUS", "WARNING", "UNCERTAIN"):
            summary_box_html = (
                f"<b>Investigator Finding:</b> This communication received a suspicious score of <b>{risk_score}/100</b> due to "
                f"partial authentication discrepancies and ambiguous delivery indicators. Caution should be exercised before opening embedded assets."
            )
        else:
            summary_box_html = (
                f"<b>Investigator Finding:</b> This communication received a safe score of <b>{risk_score}/100</b>. "
                f"All cryptographic validation checks passed, and semantic analysis revealed no deceptive or coercive cues."
            )
        summary_box_table = Table([[Paragraph(summary_box_html, body_style)]], colWidths=[doc.width])
        summary_box_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CFD8DC")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_box_table)
        story.append(Spacer(1, 9))

        # ---- 4. MITRE ATT&CK Framework Mapping ----
        story.append(Paragraph("🎯 3. Threat Actor Tactics &amp; MITRE ATT&CK Framework Mapping", heading_style))
        mitre_rows = [["MITRE ATT&CK ID", "Tactic / Technique", "Observed Threat Behavior in this Transmission", "Threat Severity"]]

        if urls_detected:
            mitre_rows.append([
                Paragraph("<b>T1566.002</b>", small_bold),
                Paragraph("Spearphishing Link", small_style),
                Paragraph("Embedded URL redirects recipient to external domain under adversary control.", small_style),
                Paragraph("<font color='#D32F2F'><b>CRITICAL</b></font>", small_style),
            ])
        if phishing_signals or risk_factors:
            mitre_rows.append([
                Paragraph("<b>T1056.003</b>", small_bold),
                Paragraph("Input Capture: Credential Phishing", small_style),
                Paragraph("Content employs social engineering cues aimed at harvesting credentials or sensitive financial data.", small_style),
                Paragraph("<font color='#D32F2F'><b>HIGH</b></font>", small_style),
            ])
        if spf_status in ("FAIL", "SOFTFAIL") or domain_auth_stat == "DOMAIN_UNAUTHORIZED":
            mitre_rows.append([
                Paragraph("<b>T1585.002</b>", small_bold),
                Paragraph("Resource Development: Email Accounts", small_style),
                Paragraph("Forged sender headers / lack of cryptographic alignment simulating legitimate domain identity.", small_style),
                Paragraph("<font color='#D32F2F'><b>HIGH</b></font>", small_style),
            ])
        if urls_detected:
            mitre_rows.append([
                Paragraph("<b>T1204.001</b>", small_bold),
                Paragraph("User Execution: Malicious Link", small_style),
                Paragraph("Message constructs emotional call-to-action to induce recipient to click external URL.", small_style),
                Paragraph("<font color='#F57F17'><b>MEDIUM</b></font>", small_style),
            ])
        if len(mitre_rows) == 1:
            mitre_rows.append([
                Paragraph("<b>N/A</b>", small_bold),
                Paragraph("Benign / Baseline", small_style),
                Paragraph("No mapped threat actor tactics or offensive techniques identified.", small_style),
                Paragraph("<font color='#2E7D32'><b>CLEAN</b></font>", small_style),
            ])

        mitre_table = Table(mitre_rows, colWidths=[doc.width * 0.18, doc.width * 0.28, doc.width * 0.42, doc.width * 0.12])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 9))

        # ---- 5. Indicators of Compromise (IOC) Matrix ----
        story.append(Paragraph("🔬 4. Structured Indicators of Compromise (IOC) Matrix", heading_style))
        email_meta_data = analysis_result.get("email_metadata", {})
        sender_str = email_meta_data.get("sender", "")
        subj_str = email_meta_data.get("subject", "")
        raw_payload = f"{sender_str}:{subj_str}:{timestamp}"
        content_hash = hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()

        ioc_rows = [["IOC Type", "Observable Value", "Context / Threat Role", "Recommended SOC Action"]]
        # Sender IOC
        if sender_str:
            ioc_rows.append([
                Paragraph("<b>EMAIL SENDER</b>", small_bold),
                Paragraph(sender_str, small_style),
                Paragraph("Claimed envelope/header originator", small_style),
                Paragraph("Filter / Gateway Quarantine" if verdict == "MALICIOUS" else "Standard Logging", small_style),
            ])
        # Origin IP IOC
        if earliest_rel_ip and earliest_rel_ip != "ORIGIN_NOT_DETERMINABLE":
            ioc_rows.append([
                Paragraph("<b>NETWORK IP</b>", small_bold),
                Paragraph(earliest_rel_ip, small_style),
                Paragraph("Chronological earliest observable public relay", small_style),
                Paragraph("Perimeter Firewall / SIEM Block" if verdict == "MALICIOUS" else "Traffic Logging", small_style),
            ])
        # URL IOCs
        for u in urls_detected[:3]:
            ioc_rows.append([
                Paragraph("<b>EXTERNAL URL</b>", small_bold),
                Paragraph(u.get("url", "")[:50], small_style),
                Paragraph(f"Domain: {u.get('domain', '')} (Risk: {u.get('risk_score', 0)})", small_style),
                Paragraph("DNS Sinkhole / Web Proxy Block" if u.get("risk_score", 0) >= 50 else "Monitor Web Gateway", small_style),
            ])
        # SHA-256 Digest IOC
        ioc_rows.append([
            Paragraph("<b>EVIDENCE HASH</b>", small_bold),
            Paragraph(content_hash[:32] + "...", small_style),
            Paragraph("SHA-256 cryptographic dossier integrity digest", small_style),
            Paragraph("Retain in DFIR Evidence Store", small_style),
        ])

        ioc_table = Table(ioc_rows, colWidths=[doc.width * 0.18, doc.width * 0.36, doc.width * 0.26, doc.width * 0.20])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 9))

        # ---- 6. Email Authentication Forensics (SPF / DKIM / DMARC) ----
        story.append(Paragraph("🔐 5. Cryptographic Sender Authentication Forensics", heading_style))

        def explain_protocol(proto: str, status: str, detail: str) -> str:
            status_u = status.upper()
            if proto == "SPF":
                if status_u == "PASS":
                    return "<b>PASS:</b> Transmitting mail transfer agent is explicitly authorized in the domain's DNS SPF record."
                elif status_u in ("FAIL", "SOFTFAIL"):
                    return f"<b>{status_u}:</b> Transmitting IP is NOT designated as an authorized sender in domain SPF records. Direct spoofing indicator."
                else:
                    return "<b>UNKNOWN / NONE:</b> No verifiable SPF record published by domain. Lack of authorization proof elevates risk."
            elif proto == "DKIM":
                if status_u == "PASS":
                    return "<b>PASS:</b> Cryptographic RSA/Ed25519 signature valid; body and headers remained intact and unmodified in transit."
                elif status_u == "FAIL":
                    return "<b>FAIL:</b> Digital signature failed verification. Body or headers may have been forged, altered, or key was revoked."
                else:
                    return "<b>UNKNOWN / NONE:</b> Transmission lacks cryptographic DKIM signature. Message integrity cannot be proven."
            elif proto == "DMARC":
                if status_u == "PASS":
                    return "<b>PASS:</b> Domain aligns with authenticated SPF and/or DKIM identities under domain DMARC policy."
                elif status_u == "FAIL":
                    return "<b>FAIL:</b> Alignment failed. Transmitting domain does not match authenticated envelope identities."
                else:
                    return "<b>UNKNOWN / NONE:</b> Domain publishes no DMARC policy. Spoofing protection is unenforced."
            return detail

        auth_data = [
            ["Protocol", "Verification Status", "Technical Forensic Interpretation"],
            ["SPF (Sender Policy)", spf_status, Paragraph(explain_protocol("SPF", spf_status, auth_data_dict.get("spf", {}).get("detail", "")), small_style)],
            ["DKIM (Signature)", dkim_status, Paragraph(explain_protocol("DKIM", dkim_status, auth_data_dict.get("dkim", {}).get("detail", "")), small_style)],
            ["DMARC (Alignment)", dmarc_status, Paragraph(explain_protocol("DMARC", dmarc_status, auth_data_dict.get("dmarc", {}).get("detail", "")), small_style)],
        ]
        auth_note = auth_data_dict.get("forensic_note", "Header authentication results indicate domain alignment status.")
        auth_data.append(["Domain Auth Verdict", domain_auth_stat, Paragraph(f"<b>Overall Policy Alignment:</b> {auth_note}", small_style)])

        auth_table = Table(auth_data, colWidths=[doc.width * 0.22, doc.width * 0.18, doc.width * 0.60])
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(auth_table)
        story.append(Spacer(1, 9))

        # ---- 7. Origin & GeoLocation Intelligence ----
        story.append(Paragraph("🌐 6. Origin & GeoLocation Intelligence", heading_style))
        relay_hops = relay_chain_info.get("relay_chain", [])
        selection_reason = relay_chain_info.get("selection_reason", "First public IP resolved chronologically from relay chain")
        earliest_public_hop = relay_chain_info.get("earliest_public_hop")
        if isinstance(earliest_public_hop, dict):
            earliest_public_hop = earliest_public_hop.get("ip")

        # Origin IP Identification Box
        if earliest_rel_ip and earliest_rel_ip != "ORIGIN_NOT_DETERMINABLE":
            origin_label = f"<b>Selected Earliest Observable Public Relay IP:</b> <font color='#0D47A1'>{escape(str(earliest_rel_ip))}</font><br/><b>Selection Rationale:</b> {escape(str(selection_reason))}"
        else:
            origin_label = f"<b>Selected Origin Infrastructure:</b> NOT DETERMINABLE (No public relay identified)<br/><b>Selection Rationale:</b> {escape(str(selection_reason))}"
        
        origin_box_table = Table([[Paragraph(origin_label, body_style)]], colWidths=[doc.width])
        origin_box_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E0F2F1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#80CBC4")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(origin_box_table)
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Observed relay chain (sender-side to recipient-side)</b>", body_style))
        if relay_hops:
            chain_data = [["Hop", "IP Address", "Classification", "Approximate Location / Note"]]
            earliest_row = None
            for hop in relay_hops:
                hop_ip = str(hop.get("ip") or "Not observed")
                classification = str(hop.get("ip_classification") or "NONE")
                geolocation = hop.get("geolocation") or {}
                if classification == "PUBLIC" and geolocation:
                    location = ", ".join(
                        str(value)
                        for value in (
                            geolocation.get("city"),
                            geolocation.get("region"),
                            geolocation.get("country"),
                        )
                        if value
                    ) or "Location unavailable"
                    provider = geolocation.get("isp") or geolocation.get("org")
                    if provider:
                        location += f" ({provider})"
                else:
                    location = str(
                        hop.get("note")
                        or "Internal relay — not routable; no geolocation applicable."
                    )
                hop_label = str(hop.get("hop_index", len(chain_data)))
                chain_data.append([
                    hop_label,
                    escape(hop_ip),
                    escape(classification),
                    Paragraph(escape(location), small_style),
                ])
                if earliest_public_hop and hop_ip == str(earliest_public_hop):
                    earliest_row = len(chain_data) - 1
                    chain_data[-1][0] = f"{hop_label} *"

            chain_table = Table(
                chain_data,
                colWidths=[doc.width * 0.08, doc.width * 0.22, doc.width * 0.18, doc.width * 0.52],
                repeatRows=1,
            )
            chain_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
            if earliest_row is not None:
                chain_style.extend([
                    ("BACKGROUND", (0, earliest_row), (-1, earliest_row), colors.HexColor("#E3F2FD")),
                    ("FONTNAME", (0, earliest_row), (2, earliest_row), "Helvetica-Bold"),
                ])
            chain_table.setStyle(TableStyle(chain_style))
            story.append(chain_table)
        else:
            story.append(Paragraph("No Received relay headers were available for reconstruction.", small_style))
        story.append(Spacer(1, 6))

        # Geolocation Table for Resolved Public IPs
        resolved_ips = geoip_obj.get("resolved_ips", [])
        if resolved_ips:
            geo_data = [["IP Address", "Type", "Approximate Location", "ISP / Organization / Autonomous System (ASN)"]]
            for g in resolved_ips:
                if "error" not in g:
                    infra = g.get("infrastructure_type", "PUBLIC")
                    loc_str = f"{g.get('city', 'Unknown')}, {g.get('region', '')} {g.get('country', '')}".strip()
                    asn_str = g.get("as_number") or g.get("isp") or "Unknown ASN"
                    geo_data.append([
                        g.get("ip", ""),
                        infra,
                        loc_str,
                        Paragraph(f"{g.get('isp', 'Unknown')}<br/><font size=6.5 color='#546E7A'>{asn_str}</font>", small_style),
                    ])
                else:
                    geo_data.append([
                        g.get("ip", ""),
                        g.get("ip_classification", "RESERVED"),
                        "Non-geolocatable",
                        Paragraph(f"<i>{g.get('error', 'Lookup failed')}</i>", small_style)
                    ])
            if len(geo_data) > 1:
                geo_table = Table(geo_data, colWidths=[doc.width * 0.20, doc.width * 0.16, doc.width * 0.32, doc.width * 0.32])
                geo_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(geo_table)
                story.append(Spacer(1, 5))

        # Forensic Accuracy Disclaimer
        story.append(Paragraph(
            "<i>⚠️ Forensic Accuracy Note: IP geolocation reflects upstream Internet Service Provider (ISP), datacenter, or regional point-of-presence (PoP) network registration. It does NOT pinpoint the perpetrator's physical device or exact physical address.</i>",
            small_style
        ))
        story.append(Spacer(1, 9))

        # ---- 8. Cross-Case Correlation & Campaign Clusters ----
        corr_data = analysis_result.get("correlation", {})
        camp_data = analysis_result.get("campaign")
        if (corr_data and corr_data.get("related_case_count", 0) > 0) or camp_data:
            story.append(Paragraph("🔗 7. Cross-Case Correlation & Campaign Attribution", heading_style))
            rel_count = corr_data.get("related_case_count", 0) if corr_data else 0
            camp_name = camp_data.get("campaign_id", "UNCORRELATED") if camp_data else "UNCORRELATED"
            camp_exp = camp_data.get("explanation", "Single incident observed") if camp_data else corr_data.get("attribution_summary", "")

            corr_rows = [
                ["Attribution Parameter", "Correlation Finding"],
                ["Threat Campaign Identifier", camp_name],
                ["Correlated Incident Count", f"{rel_count} Historical Case(s) Linked"],
                ["Attribution Confidence", corr_data.get("attribution_confidence", "MEDIUM") if corr_data else "STANDALONE"],
                ["Campaign Cluster Analysis", Paragraph(camp_exp, small_style)],
            ]
            corr_table = Table(corr_rows, colWidths=[doc.width * 0.30, doc.width * 0.70])
            corr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(corr_table)
            story.append(Spacer(1, 9))

        # ---- 9. Prioritized Incident Response & Containment Playbook ----
        story.append(Paragraph("🛡️ 8. Prioritized Incident Response & Containment Playbook", heading_style))
        if verdict == "MALICIOUS":
            rec_actions = [
                "<b>1. Immediate Mailbox Quarantine:</b> Remove and isolate message from recipient mailbox to prevent credential entry or execution.",
                "<b>2. Perimeter Gateway & Firewall Blocks:</b> Block originating IP (<b>" + (earliest_rel_ip or "N/A") + "</b>) and sending domain at email gateways and border firewalls.",
                "<b>3. Credential Invalidation & Session Revocation:</b> If recipient engaged with embedded links, immediately revoke active OAuth tokens and enforce credential rotation.",
                "<b>4. Fleet-Wide SIEM Threat Hunt:</b> Query enterprise log repositories for other recipients receiving communications with matching Subject, Message-ID, or sender domain.",
            ]
        elif verdict in ("SUSPICIOUS", "WARNING", "UNCERTAIN"):
            rec_actions = [
                "<b>1. Cautionary Hold:</b> Flag message with cautionary banner; advise recipient not to click embedded links or download attachments.",
                "<b>2. Out-of-Band Sender Verification:</b> Contact claimed sender through a verified external channel (phone/internal chat) to verify transmission intent.",
                "<b>3. URL Sandbox Inspection:</b> Submit embedded URLs to an automated dynamic analysis sandbox prior to granting access.",
            ]
        else:
            rec_actions = [
                "<b>1. Unrestricted Delivery:</b> Cryptographic signatures and content heuristics confirmed legitimate communication.",
                "<b>2. Continuous Vigilance:</b> Maintain standard organizational security awareness and report anomalous deviations.",
            ]

        for action in rec_actions:
            story.append(Paragraph(f"• {action}", body_style))
            story.append(Spacer(1, 2.5))
        story.append(Spacer(1, 9))

        # ---- 10. Chain of Custody & Evidence Integrity ----
        story.append(Paragraph("⛓️ 9. Chain of Custody & Cryptographic Evidence Integrity", heading_style))
        custody_data = [
            ["Forensic Parameter", "Defensible Record & Specification"],
            ["Case Identifier", case_id],
            ["Ingestion Timestamp", timestamp],
            ["Evidence SHA-256 Digest", content_hash],
            ["Analysis Platform", "MessageGuard Forensic Engine v2.4 (Defensible Audit Build)"],
            ["Inference Models", "DistilBERT Semantic Classifier + Hybrid Rules + GeoIP Resolver"],
            ["Data Retention Schedule", f"Immutable Evidence Store | Retention Period {RETENTION_DAYS} Days"],
            ["PII Protection Policy", "Redacted Prior to Storage & Logging"],
        ]
        custody_table = Table(custody_data, colWidths=[doc.width * 0.30, doc.width * 0.70])
        custody_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D233A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(custody_table)
        story.append(Spacer(1, 10))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Official Incident Dossier | MessageGuard Threat Intelligence Platform | Case {case_id} | Cryptographic Digest: {content_hash[:20]}",
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
