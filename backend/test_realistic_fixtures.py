import sys
import os
import json
sys.path.append(os.path.abspath("."))

from services.content_analyzer import ContentAnalyzer
from services.threat_intel_service import ThreatIntelService
from services.report_service import ReportService
from main import verify_authentication_headers, calculate_ps106_risk_score

content_analyzer = ContentAnalyzer()
threat_intel = ThreatIntelService()
report_service = ReportService()

def process_email_fixture(name, email_data):
    print(f"\n=======================================================")
    print(f"RUNNING: {name}")
    print(f"=======================================================")
    
    # 1. Auth check
    auth_result = verify_authentication_headers(email_data.get("authentication_results", ""))
    
    # 2. Content analysis
    content_result = content_analyzer.analyze(email_data)
    
    # 3. Relay chain & GeoIP
    received_hdrs = email_data.get("received_headers", [])
    relay_chain_data = threat_intel.build_relay_chain(received_hdrs)
    relay_ips = threat_intel.extract_ips_from_email(received_hdrs)
    resolved_ips = threat_intel.resolve_all_ips(relay_ips)
    relay_analysis = threat_intel.analyze_relay_path(resolved_ips)
    
    geoip_data = {
        "relay_ips": relay_ips,
        "resolved_ips": resolved_ips,
        "relay_analysis": relay_analysis,
        "relay_chain_data": relay_chain_data,
    }
    
    # 4. Risk score
    score_result = calculate_ps106_risk_score(auth_result, content_result, geoip_data)
    
    # 5. Generate PDF
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
        "score_breakdown": score_result["score_breakdown"],
    }
    case_id = report_service.generate_report(full_analysis)
    
    # Key Audit Outputs
    audit_output = {
        "case_id": case_id,
        "verdict": score_result["verdict"],
        "risk_score": score_result["risk_score"],
        "primary_category": content_result.get("primary_category"),
        "secondary_categories": content_result.get("secondary_categories"),
        "forwarding_analysis": content_result.get("forwarding_analysis"),
        "risk_factors": content_result.get("risk_factors"),
        "auth_status": auth_result.get("domain_authorization_status"),
        "auth_forensic_note": auth_result.get("forensic_note"),
        "earliest_reliable_observed_ip": relay_chain_data.get("earliest_reliable_observed_ip"),
        "origin_not_determinable": relay_chain_data.get("origin_not_determinable"),
        "relay_chain_reason": relay_chain_data.get("reason"),
        "relay_hops_count": len(relay_chain_data.get("relay_chain", [])),
    }
    
    print(json.dumps(audit_output, indent=2))
    return audit_output

# -------------------------------------------------------------
# FIXTURE A: Forwarded Phishing with Multi-Hop Relay
# -------------------------------------------------------------
fixture_a = {
    "sender": "Alice Trustworthy <alice@trustedcorp.com>",
    "to": "bob@trustedcorp.com",
    "subject": "Fwd: Urgent Account Suspension Notice",
    "text_body": """Hey Bob, can you look at this email I just received? Seems weird.

---------- Forwarded message ---------
From: Microsoft Security Team <alerts@micros0ft-support.com>
Date: Wed, Sep 24, 2026 at 11:20 AM
Subject: Urgent Account Suspension Notice
To: <alice@trustedcorp.com>

Dear User,
Your Microsoft 365 account will be suspended immediately due to unusual activity.
Please enter your password and verify your credentials now at:
http://micros0ft-support.com/login
""",
    "urls": ["http://micros0ft-support.com/login"],
    "authentication_results": "mx.google.com; spf=pass (google.com: domain of alice@trustedcorp.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=alice@trustedcorp.com; dkim=pass header.i=@trustedcorp.com; dmarc=pass",
    "received_headers": [
        "by mx.google.com with ESMTPS id abc123xyz for <bob@trustedcorp.com>; Wed, 24 Sep 2026 11:25:00 -0700",
        "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.google.com with SMTPS; Wed, 24 Sep 2026 11:24:58 -0700",
        "from suspicious-relay.external.net (unknown [185.220.101.5]) by corporate-mta.trustedcorp.com with ESMTP; Wed, 24 Sep 2026 11:19:30 -0700"
    ],
    "date": "2026-09-24T11:25:00Z",
    "message_id": "<forward-fwd-999@trustedcorp.com>"
}

# -------------------------------------------------------------
# FIXTURE B: Brand Impersonation on Freemail + Spoofed Auth
# -------------------------------------------------------------
fixture_b = {
    "sender": "PayPal Fraud Prevention <paypal.alert91@gmail.com>",
    "to": "target_user@domain.com",
    "subject": "Unauthorized transaction detected on your account",
    "text_body": "We detected an unauthorized transaction of $499.00. Enter your password and credit card number immediately to cancel this transfer.",
    "urls": ["http://198.51.100.42/paypal/verify"],
    "authentication_results": "mx.google.com; spf=fail (google.com: domain of paypal.com does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=alert@paypal.com; dkim=none; dmarc=fail (p=REJECT)",
    "received_headers": [
        "by mx.google.com with ESMTPS id ddd888; Wed, 24 Sep 2026 10:00:00 -0700",
        "from bad-actor.host (bad-actor.host [198.51.100.42]) by mx.google.com with ESMTP; Wed, 24 Sep 2026 09:59:45 -0700"
    ],
    "date": "2026-09-24T10:00:00Z",
    "message_id": "<spoofed-auth-111@paypal.com>"
}

# -------------------------------------------------------------
# FIXTURE C: High-Urgency BEC Wire Fraud (Clean Auth)
# -------------------------------------------------------------
fixture_c = {
    "sender": "John Doe CEO <john.doe@executive-acquisitions.com>",
    "to": "finance@executive-acquisitions.com",
    "subject": "Confidential: Urgent Wire Transfer Required",
    "text_body": "Are you at your desk? We need to complete an executive request for vendor payment today. Please process an urgent wire transfer of $78,500 immediately to the attached account details. Keep this strictly confidential until closing.",
    "urls": [],
    "authentication_results": "mx.google.com; spf=pass smtp.mailfrom=john.doe@executive-acquisitions.com; dkim=pass header.i=@executive-acquisitions.com; dmarc=pass",
    "received_headers": [
        "by mx.google.com with ESMTPS id bec777; Wed, 24 Sep 2026 08:30:00 -0700",
        "from mail-relay.executive-acquisitions.com (mail-relay.executive-acquisitions.com [54.240.8.1]) by mx.google.com with ESMTP; Wed, 24 Sep 2026 08:29:40 -0700"
    ],
    "date": "2026-09-24T08:30:00Z",
    "message_id": "<bec-wire-888@executive-acquisitions.com>"
}

# -------------------------------------------------------------
# FIXTURE D: Stripped Origin Forwarding (Origin Not Determinable)
# -------------------------------------------------------------
fixture_d = {
    "sender": "Colleague Dave <dave@workplace.org>",
    "to": "security-incident@workplace.org",
    "subject": "Fwd: suspicious notice",
    "text_body": """Forwarding this for investigation:
Begin forwarded message
From: Unknown System Administrator
Date: Unknown
Subject: System alert

Account access restricted.
""",
    "urls": [],
    "authentication_results": "mx.google.com; spf=pass smtp.mailfrom=dave@workplace.org; dkim=pass; dmarc=pass",
    "received_headers": [], # All external Received headers stripped by local forwarding agent
    "date": "2026-09-24T07:15:00Z",
    "message_id": "<stripped-headers-000@workplace.org>"
}

if __name__ == "__main__":
    process_email_fixture("FIXTURE A: Forwarded Phishing with Multi-Hop Relay", fixture_a)
    process_email_fixture("FIXTURE B: Brand Impersonation on Freemail + Spoofed Auth", fixture_b)
    process_email_fixture("FIXTURE C: High-Urgency BEC Wire Fraud (Clean Auth)", fixture_c)
    process_email_fixture("FIXTURE D: Stripped Origin Forwarding (Origin Not Determinable)", fixture_d)
