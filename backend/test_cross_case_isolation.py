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

print('=== 1. Creating 10 Isolated Unique Cases ===')
cases = []
for i in range(10):
    payload = {
        'sender': f'attacker_{i}@unique-threat-actor-{i}.xyz',
        'subject': f'Malicious Target Directive #{i}',
        'body': f'Click the malicious payload link: http://payload-{i}.xyz/download?token={i}',
        'received_headers': [
            f'from hop-attacker-{i} (185.220.101.{i+10}) by mx.google.com; Fri, 25 Sep 2026 12:00:00'
        ]
    }
    st, resp = post_json('/api/analyze-trigger', payload)
    cid = resp.get('case_id')
    cases.append((cid, i, payload))
    print(f"Created Case {i}: ID={cid}, Status={st}, Verdict={resp.get('verdict')}")

print('\n=== 2. Verifying Report Isolation across 10 cases ===')
cross_contamination_detected = False
for cid, idx, p in cases:
    st_pdf, pdf_bytes = get_req(f'/generate-report/{cid}')
    # Check that this report has ITS OWN sender
    own_sender = p['sender'].encode('utf-8')
    if own_sender not in pdf_bytes:
        print(f"WARNING: Case {cid} missing its own sender {p['sender']}")
    # Check that NO OTHER sender appears
    for o_cid, o_idx, o_p in cases:
        if o_idx != idx:
            other_sender = o_p['sender'].encode('utf-8')
            if other_sender in pdf_bytes:
                print(f"CRITICAL: Cross contamination! Case {cid} contains {o_p['sender']}")
                cross_contamination_detected = True

if not cross_contamination_detected:
    print('-> 10/10 Cases PASSED Cross-Case Isolation with ZERO Contamination!')
