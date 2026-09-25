import urllib.request
import json
import time
import sys
import io

# Fix Windows console encoding for emoji/unicode output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

base_url = 'http://127.0.0.1:8000/api/analyze-trigger'

demos = [
    {
        'name': 'DEMO 1: SAFE LEGITIMATE EMAIL (GitHub)',
        'payload': {
            'sender': 'GitHub <notifications@github.com>',
            'subject': 'Your GitHub security alert digest',
            'body': 'All your repositories are up to date and dependencies have no known vulnerabilities. Have a productive day coding!',
            'urls': ['https://github.com/settings/security'],
            'authentication_results': 'spf=pass (google.com: domain of notifications@github.com designates 192.30.252.0 as permitted sender) smtp.mailfrom=notifications@github.com; dkim=pass header.i=@github.com; dmarc=pass action=none header.from=github.com',
            'received_headers': [
                'from smtp.github.com (smtp.github.com [192.30.252.206]) by mx.google.com with ESMTPS for <developer@example.com>'
            ]
        }
    },
    {
        'name': 'DEMO 2: PHISHING & CREDENTIAL HARVESTING (FAILED AUTH)',
        'payload': {
            'sender': 'PayPal Account Support <security-update@paypa1-security.com>',
            'subject': 'Urgent: Account Limited - Action Required Immediately',
            'body': 'Your account has been temporarily restricted due to unauthorized login attempts. Click below to enter your password, PIN and Social Security Number within 24 hours to avoid suspension: http://paypa1-security.com/login?token=abc',
            'urls': ['http://paypa1-security.com/login?token=abc'],
            'authentication_results': 'spf=fail smtp.mailfrom=paypa1-security.com; dkim=fail; dmarc=fail action=reject header.from=paypa1-security.com',
            'received_headers': [
                'from mail.paypa1-security.com (unknown [185.220.101.5]) by mx.google.com with ESMTPS for <victim@example.com>'
            ]
        }
    },
    {
        'name': 'DEMO 3: BRAND IMPERSONATION & TYPOSQUATTING',
        'payload': {
            'sender': 'Internal IT Support <it-helpdesk@legit-corp.com>',
            'subject': 'Mandatory Microsoft 365 Password Reset Required',
            'body': 'All employees must enter your password to re-authenticate Office 365 credentials immediately before 5 PM today. Visit http://login-microsoftonline-verify.net/auth',
            'urls': ['http://login-microsoftonline-verify.net/auth'],
            'authentication_results': 'spf=softfail smtp.mailfrom=it-helpdesk@legit-corp.com; dkim=none',
            'received_headers': [
                'from vps-relayer.malicious-host.com (vps-relayer.malicious-host.com [198.51.100.23]) by mail.legit-corp.com with ESMTP'
            ]
        }
    },
    {
        'name': 'DEMO 4: BEC / WIRE FRAUD WITH MULTI-HOP RELAY',
        'payload': {
            'sender': 'Richard Davies CEO <ceo.office.corp1@gmail.com>',
            'subject': 'Confidential: Urgent Wire Transfer for Acquisition Settlement',
            'body': 'I am currently in an all-day board meeting. Please process an urgent vendor invoice wire transfer of $48,500 immediately to the attached routing details before banking close. Keep this strictly confidential until press release.',
            'urls': [],
            'authentication_results': 'spf=pass smtp.mailfrom=ceo.office.corp1@gmail.com; dkim=pass header.i=@gmail.com',
            'received_headers': [
                'from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.google.com with SMTPS',
                'from [10.0.0.15] (relay-vpn.tor-exit.net [185.220.101.5]) by smtp.gmail.com with ESMTPSA'
            ]
        }
    },
    {
        'name': 'DEMO 5: SENSITIVE DATA EXPOSURE (Credential Leak)',
        'payload': {
            'sender': 'IT Admin <admin@legit-corp.com>',
            'subject': 'Login credentials for new employee',
            'body': 'Hi Team, new employee credentials:\nEmail: shahul@gmail.com\npassword: SuperSecret123\nPlease change after first login.',
            'urls': [],
            'authentication_results': 'spf=pass smtp.mailfrom=admin@legit-corp.com; dkim=pass header.i=@legit-corp.com; dmarc=pass',
            'received_headers': [
                'from smtp.legit-corp.com (smtp.legit-corp.com [203.0.113.10]) by mx.google.com with ESMTPS'
            ]
        }
    },
    {
        'name': 'DEMO 6: FORWARDED SPAM (Trust the Original, Not the Forwarder)',
        'payload': {
            'sender': 'Friend <friend@gmail.com>',
            'subject': 'Fwd: You won a lottery prize!',
            'body': 'Check this out, seems suspicious!\n\n---------- Forwarded message ---------\nFrom: Lottery Winner Notification <winner@lottery-scam.tk>\nDate: Mon, 25 Sep 2026 08:00:00 +0000\nSubject: You won a lottery prize!\n\nCongratulations! You have been selected for a prize of $1,000,000. Claim your prize now.',
            'urls': [],
            'authentication_results': 'spf=pass smtp.mailfrom=friend@gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass',
            'received_headers': [
                'from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.216.41]) by mx.google.com with SMTPS'
            ]
        }
    },
]

print("\n" + "="*80)
print(">>> RUNNING END-TO-END DEMO SCENARIOS AGAINST LIVE MESSAGEGUARD BACKEND")
print("="*80 + "\n")

for d in demos:
    t0 = time.time()
    req = urllib.request.Request(base_url, data=json.dumps(d['payload']).encode('utf-8'), headers={'Content-Type': 'application/json'})
    try:
        res = urllib.request.urlopen(req, timeout=15)
        data = json.loads(res.read().decode('utf-8'))
        elapsed = time.time() - t0
        print("=" * 10, d['name'], f"({elapsed:.2f}s)", "=" * 10)
        print("Case ID:          ", data.get('case_id'))
        print("Verdict:          ", data.get('verdict'), "| Risk Score:", data.get('risk_score'), f"({data.get('risk_band')})")
        print("Primary Category: ", data.get('primaryCategory'))
        print("Secondary Cats:   ", data.get('secondaryCategories'))
        print("Auth Status:      ", data.get('authentication', {}).get('domain_authorization_status'))
        print("Reliable Origin IP:", data.get('earliest_reliable_observed_ip'))
        print("Threat Indicators:", len(data.get('threatIndicators', [])), "detected")
        for factor in data.get('threatIndicators', [])[:5]:
            print("  ->", factor)
        
        # Sensitive data exposure check
        content = data.get('content_analysis', {})
        exposure = data.get('content_analysis', {}).get('sensitive_data_exposure', [])
        if exposure:
            print(f"  ⚠️  SENSITIVE DATA EXPOSURE: {len(exposure)} finding(s) — credentials MASKED")
        
        # Forwarding analysis
        fwd = data.get('forwardingAnalysis')
        if fwd and fwd.get('is_forwarded'):
            print(f"  📧 FORWARDED EMAIL: original sender = {fwd.get('original_sender', 'UNKNOWN')}")
        
        campaign = data.get('campaign') or {}
        print("Campaign ID:      ", campaign.get('campaign_id'), f"(Pattern: {campaign.get('campaign_type', 'N/A')})")
        
        correlation = data.get('correlation') or {}
        print("Related Cases:    ", len(correlation.get('related_case_ids', [])))
        
        graph_summary = data.get('investigation_graph_summary') or "N/A"
        print("Investigation Graph:", graph_summary)
        print("Forensic PDF URL: ", data.get('report_url'))
        print()
    except Exception as e:
        print(f"Error executing {d['name']}: {e}\n")
