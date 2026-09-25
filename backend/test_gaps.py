import sys
import os
sys.path.append(os.path.abspath("."))

from services.content_analyzer import ContentAnalyzer
from services.threat_intel_service import ThreatIntelService
from services.report_service import ReportService
from main import verify_authentication_headers

# --- Test Gap 1 ---
auth = verify_authentication_headers("spf=fail (sender IP 1.2.3.4 not permitted) smtp.mailfrom=paypal.com; dkim=fail; dmarc=fail")
print("=== GAP 1 TEST ===")
print("Status:", auth.get("domain_authorization_status"))
print("Note:", auth.get("forensic_note"))

# --- Test Gap 2 & 3 ---
intel = ThreatIntelService()
raw_received = [
    "by mx.google.com with ESMTPS id 123 for <target@gmail.com>; Wed, 24 Sep 2026 12:05:00 -0700",
    "from mail-relay.trustedmta.com (mail-relay.trustedmta.com [209.85.220.41]) by inbound.google.com with ESMTP; Wed, 24 Sep 2026 12:04:30 -0700",
    "from compromised.residential.isp (unknown [192.168.1.50]) by mail-relay.trustedmta.com with ESMTP; Wed, 24 Sep 2026 12:03:00 -0700"
]
chain = intel.build_relay_chain(raw_received)
print("\n=== GAP 2 & 3 TEST ===")
print("Earliest Reliable IP:", chain["earliest_reliable_observed_ip"])
print("Origin Not Determinable:", chain["origin_not_determinable"])
print("Reason:", chain["reason"])
for h in chain["relay_chain"]:
    print(f" Hop {h['hop_index']}: IP={h['ip']} ({h['ip_classification']}) -> {h['trust_label']} [{h['trust_reason']}]")

geo = intel.resolve_geoip("209.85.220.41")
print("Geo IP:", geo.get("ip"))
print("Infra Type:", geo.get("infrastructure_type"))
print("Disclaimer Attached:", "Approximate infrastructure geolocation" in geo.get("disclaimer", ""))

# --- Test Gap 4: Report Generation ---
report_service = ReportService()
analysis_payload = {
    "verdict": "MALICIOUS",
    "risk_score": 85,
    "email_metadata": {
        "sender": "Security Team <security@paypa1.com>",
        "to": "victim@example.com",
        "subject": "Urgent: Account locked",
        "date": "2026-09-24T12:00:00Z",
        "message_id": "<test-123@paypa1.com>"
    },
    "authentication": auth,
    "content_analysis": {
        "primary_category": "IMPERSONATION",
        "secondary_categories": ["PHISHING", "SPOOFED"],
        "content_risk_score": 85,
        "risk_factors": ["Lookalike domain paypa1.com", "Urgent pressure language"],
        "forwarding_analysis": {"is_forwarded": False}
    },
    "geoip_data": {
        "resolved_ips": [geo],
        "relay_chain_data": chain,
        "relay_analysis": {"anomaly_score": 10, "flags": ["Test relay normal"]}
    },
    "score_breakdown": {
        "content_score": {"score": 85, "weight": 60},
        "auth_score": {"score": 99, "weight": 40}
    }
}
case_id = report_service.generate_report(analysis_payload)
print("\n=== GAP 4 TEST ===")
print("Generated PDF Report Case ID:", case_id)
print("PDF Bytes Length:", len(report_service.get_report(case_id)))

# --- Test Gap 5: Fake Mail Types ---
analyzer = ContentAnalyzer()

# 1. Lookalike domain
res_lookalike = analyzer.analyze({
    "sender": "Security Team <security@paypa1.com>",
    "subject": "Urgent: Account locked",
    "text_body": "Please click here to verify your account immediately.",
    "urls": ["http://paypa1.com/login"]
})
print("\n=== GAP 5 TEST (Lookalike Domain) ===")
print("Primary:", res_lookalike["primary_category"])
print("Secondary:", res_lookalike["secondary_categories"])
print("Factors:", res_lookalike["risk_factors"])

# 2. Freemail brand impersonation
res_freemail = analyzer.analyze({
    "sender": "PayPal Support <paypal.helpdesk24@gmail.com>",
    "subject": "Verification Required",
    "text_body": "Please enter your password to confirm identity.",
    "urls": []
})
print("\n=== GAP 5 TEST (Freemail Brand Impersonation) ===")
print("Primary:", res_freemail["primary_category"])
print("Secondary:", res_freemail["secondary_categories"])
print("Factors:", res_freemail["risk_factors"])

# 3. BEC Wire Request
res_bec = analyzer.analyze({
    "sender": "CEO <ceo@partner-corp.com>",
    "subject": "Urgent Wire Transfer",
    "text_body": "Please process vendor payment immediately via urgent wire transfer.",
    "urls": []
})
print("\n=== GAP 5 TEST (BEC Wire Transfer) ===")
print("Primary:", res_bec["primary_category"])
print("Secondary:", res_bec["secondary_categories"])
print("Factors:", res_bec["risk_factors"])
