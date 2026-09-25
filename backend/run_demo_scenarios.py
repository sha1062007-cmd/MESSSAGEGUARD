import urllib.request
import json

base_url = 'http://127.0.0.1:8000/analyze-email'

demos = [
    {
        'name': 'DEMO 1: SAFE EMAIL',
        'payload': {
            'sender': 'GitHub <notifications@github.com>',
            'subject': 'Your GitHub security alert digest',
            'body': 'All your repositories are up to date and dependencies have no known vulnerabilities. Have a productive day coding!',
            'urls': ['https://github.com/settings/security']
        }
    },
    {
        'name': 'DEMO 2: PHISHING EMAIL',
        'payload': {
            'sender': 'PayPal Account Support <security-update@paypa1-security.com>',
            'subject': 'Urgent: Account Limited - Action Required Immediately',
            'body': 'Your account has been temporarily restricted due to unauthorized login attempts. Click below to verify your password, PIN and Social Security Number within 24 hours to avoid suspension: http://paypa1-security.com/login?token=abc',
            'urls': ['http://paypa1-security.com/login?token=abc']
        }
    },
    {
        'name': 'DEMO 3: SPOOFING / IMPERSONATION EMAIL',
        'payload': {
            'sender': 'Internal IT Support <it-helpdesk@legit-corp.com>',
            'subject': 'Mandatory Microsoft 365 Password Reset Required',
            'body': 'All employees must re-authenticate their Office 365 credentials before 5 PM today. Visit http://login-microsoftonline-verify.net/auth',
            'urls': ['http://login-microsoftonline-verify.net/auth']
        }
    },
    {
        'name': 'DEMO 4: SCAM / BEC / WIRE FRAUD EMAIL',
        'payload': {
            'sender': 'Richard Davies CEO <ceo.office.corp1@gmail.com>',
            'subject': 'Confidential: Urgent Wire Transfer for Acquisition Settlement',
            'body': 'I am currently in an all-day board meeting. Please process an urgent vendor invoice wire transfer of $48,500 immediately to the attached routing details before banking close. Keep this strictly confidential until press release.',
            'urls': []
        }
    }
]

for d in demos:
    req = urllib.request.Request(base_url, data=json.dumps(d['payload']).encode('utf-8'), headers={'Content-Type': 'application/json'})
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode('utf-8'))
    print("=" * 10, d['name'], "=" * 10)
    print("Verdict:", data.get('verdict'), "| Risk Score:", data.get('risk_score'))
    print("Primary Category:", data.get('content_analysis', {}).get('primary_category'))
    print("Secondary Categories:", data.get('content_analysis', {}).get('secondary_categories'))
    print("Auth Status:", data.get('authentication', {}).get('domain_authorization_status'))
    print("Correlation ID:", data.get('correlation_id'), "| Campaign ID:", data.get('campaign_id'))
    print("Case ID:", data.get('case_id'))
    print("Report URL:", data.get('report_url'))
    print()
