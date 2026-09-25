import urllib.request
import json
import time

base = 'http://localhost:8000'

def post_json(path, data):
    url = f"{base}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return 0, str(e)

def get_req(path):
    url = f"{base}{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return 0, str(e)

print('=== 1. Testing fuzzing /api/analyze-trigger ===')
fuzz_cases = [
    {},
    {'sender': ''},
    {'sender': 12345},
    {'raw_email': 'x'*50000},
    {'headers': {'Received': ['malformed [999.999.999.999]']}},
    {'subject': None, 'body': None, 'sender': 'attacker@evil.com'}
]

for i, fc in enumerate(fuzz_cases):
    st, resp = post_json('/api/analyze-trigger', fc)
    print(f'Fuzz {i}: status {st}')

print('\n=== 2. Testing Case Persistence & Cross-Case Contamination ===')
payload_a = {
    'sender': 'ceo@spoofed-apple.com',
    'subject': 'URGENT: Wire Transfer A',
    'body': 'Wire 50000 USD to account 12345678 immediately.',
    'headers': {
        'From': 'Tim Cook <ceo@spoofed-apple.com>',
        'Received': ['from mail.attacker.com (mail.attacker.com [185.220.101.5]) by mx.google.com with ESMTP; Fri, 25 Sep 2026 10:00:00 +0000']
    }
}
payload_b = {
    'sender': 'newsletter@github.com',
    'subject': 'Your GitHub Digest B',
    'body': 'Check your repositories and stars today at https://github.com',
    'headers': {
        'From': 'GitHub <newsletter@github.com>',
        'Received': ['from smtp.github.com (smtp.github.com [140.82.112.4]) by mx.google.com with ESMTP; Fri, 25 Sep 2026 10:00:00 +0000']
    }
}

st_a, res_a = post_json('/api/analyze-trigger', payload_a)
st_b, res_b = post_json('/api/analyze-trigger', payload_b)

case_a = res_a.get('case_id') if isinstance(res_a, dict) else None
case_b = res_b.get('case_id') if isinstance(res_b, dict) else None

print(f"Case A: status {st_a}, ID {case_a}, Risk {res_a.get('risk_score')}, Verdict {res_a.get('verdict')}")
print(f"Case B: status {st_b}, ID {case_b}, Risk {res_b.get('risk_score')}, Verdict {res_b.get('verdict')}")

print('\n=== 3. Testing PDF Cross-Contamination ===')
st_pdf_a, pdf_a_bytes = get_req(f'/generate-report/{case_a}')
st_pdf_b, pdf_b_bytes = get_req(f'/generate-report/{case_b}')
print(f"PDF A: status {st_pdf_a}, size {len(pdf_a_bytes) if isinstance(pdf_a_bytes, bytes) else 0}")
print(f"PDF B: status {st_pdf_b}, size {len(pdf_b_bytes) if isinstance(pdf_b_bytes, bytes) else 0}")

if isinstance(pdf_a_bytes, bytes) and isinstance(pdf_b_bytes, bytes):
    has_b_in_a = b'github.com' in pdf_a_bytes
    has_a_in_b = b'spoofed-apple.com' in pdf_b_bytes
    has_ps106_a = b'PS106' in pdf_a_bytes
    has_ps106_b = b'PS106' in pdf_b_bytes
    print(f"Cross-contamination check: B in A={has_b_in_a}, A in B={has_a_in_b}")
    print(f"PS106 leak in PDF check: PS106 in A={has_ps106_a}, PS106 in B={has_ps106_b}")
