import sys
import os
import json
sys.path.append(os.path.abspath("."))

from services.domain_intel_service import DomainIntelService
from services.content_analyzer import ContentAnalyzer
from services.threat_intel_service import ThreatIntelService
from services.report_service import ReportService
from main import verify_authentication_headers, calculate_ps106_risk_score

domain_intel = DomainIntelService(timeout=3.0)
content_analyzer = ContentAnalyzer()
threat_intel = ThreatIntelService()
report_service = ReportService()

print("=== 1. TEST REAL DOMAIN (GOOGLE.COM) ===")
res_real = domain_intel.resolve_domain_intel("google.com")
print(f"Domain: {res_real['domain']}")
print(f"Registrar: {res_real['registrar']}")
print(f"Creation Date: {res_real['creation_date']}")
print(f"Age Days: {res_real['age_days']}")
print(f"Has MX: {res_real['has_mx']} -> {res_real['mx_records'][:2]}")
print(f"Is Young: {res_real['is_young_domain']}")

print("\n=== 2. TEST TIMEOUT / INVALID DOMAIN ===")
res_invalid = domain_intel.resolve_domain_intel("non-existent-gibberish-domain-123456789.xyz")
print(f"Status: {res_invalid['status']}")
print(f"WHOIS Status: {res_invalid['whois_status']}")
print(f"Has MX: {res_invalid['has_mx']}")

print("\n=== 3. TEST FIXTURE WITH SIMULATED YOUNG DOMAIN ===")
# Simulated newly registered domain registered 2 days ago
simulated_young_intel = {
    "sender_domain": {
        "domain": "secure-chase-verification-login.com",
        "status": "RESOLVED",
        "registrar": "NameCheap, Inc.",
        "creation_date": "2026-09-22",
        "age_days": 2,
        "is_young_domain": True,
        "has_mx": False,
        "mx_records": []
    },
    "url_domain": None
}

young_email = {
    "sender": "Chase Fraud Prevention <security@secure-chase-verification-login.com>",
    "to": "victim@example.com",
    "subject": "Urgent: Verify Account Immediately",
    "text_body": "Your bank account has been locked. Verify identity now at http://secure-chase-verification-login.com/login to restore access.",
    "urls": ["http://secure-chase-verification-login.com/login"],
    "authentication_results": "mx.google.com; spf=fail; dkim=none; dmarc=fail",
    "received_headers": [
        "by mx.google.com with ESMTPS; Wed, 24 Sep 2026 12:00:00 -0700",
        "from mail.secure-chase-verification-login.com (unknown [203.0.113.10]) by mx.google.com with ESMTP; Wed, 24 Sep 2026 11:59:00 -0700"
    ],
    "date": "2026-09-24T12:00:00Z",
    "message_id": "<chase-phish-young@secure-chase-verification-login.com>"
}

auth_res = verify_authentication_headers(young_email["authentication_results"])
content_res = content_analyzer.analyze(young_email, domain_intel=simulated_young_intel)
relay_chain_data = threat_intel.build_relay_chain(young_email["received_headers"])
relay_ips = threat_intel.extract_ips_from_email(young_email["received_headers"])
resolved_ips = threat_intel.resolve_all_ips(relay_ips)
relay_analysis = threat_intel.analyze_relay_path(resolved_ips)

geoip_data = {
    "relay_ips": relay_ips,
    "resolved_ips": resolved_ips,
    "relay_analysis": relay_analysis,
    "relay_chain_data": relay_chain_data,
}

score_res = calculate_ps106_risk_score(auth_res, content_res, geoip_data)

full_analysis = {
    "verdict": score_res["verdict"],
    "risk_score": score_res["risk_score"],
    "email_metadata": {
        "sender": young_email["sender"],
        "to": young_email["to"],
        "subject": young_email["subject"],
        "date": young_email["date"],
        "message_id": young_email["message_id"],
    },
    "authentication": auth_res,
    "content_analysis": content_res,
    "geoip_data": geoip_data,
    "domain_intel": simulated_young_intel,
    "score_breakdown": score_res["score_breakdown"],
}

case_id = report_service.generate_report(full_analysis)

print("Verdict:", score_res["verdict"])
print("Risk Score:", score_res["risk_score"])
print("Primary Category:", content_res["primary_category"])
print("Risk Factors:", content_res["risk_factors"])
print("Case ID with Domain Intel section:", case_id)
print("PDF Bytes Length:", len(report_service.get_report(case_id)))
