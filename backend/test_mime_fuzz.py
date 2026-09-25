import urllib.request
import json
import urllib.error

base_url = 'http://localhost:8000'

mime_attacks = [
    ('Empty Payload', ''),
    ('Missing Headers', 'Subject: Test\n\nNo From header here.'),
    ('Unicode Chaos', 'From: =?utf-8?B?8J+UkQ==?= <target@evil.com>\nSubject: Emergency\n\nBody with null bytes and unicode \u2705.'),
    ('Truncated Multipart', 'Content-Type: multipart/mixed; boundary="B1"\n\n--B1\nContent-Type: text/plain\n\nTruncated without closing boundary'),
    ('Invalid Boundary Format', 'Content-Type: multipart/mixed; boundary=\n\nBody without proper boundary structure'),
    ('Nested Malformed Boundaries', 'Content-Type: multipart/mixed; boundary="B1"\n\n--B1\nContent-Type: multipart/alternative; boundary="B2"\n\n--B2\nContent-Type: text/plain\n\nNested unclosed'),
    ('Huge 500KB MIME Body', 'From: test@test.com\nSubject: Huge\n\n' + ('A'*500000))
]

for name, payload in mime_attacks:
    body_json = json.dumps({"raw_source": payload}).encode("utf-8")
    req = urllib.request.Request(
        f'{base_url}/api/ingest/raw',
        data=body_json,
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            st = r.status
            resp = json.loads(r.read().decode('utf-8'))
            print(f'MIME Test [{name:28s}]: Status={st}, Case={resp.get("case_id")}, Verdict={resp.get("verdict")}')
    except urllib.error.HTTPError as e:
        print(f'MIME Test [{name:28s}]: Handled with HTTP {e.code}')
    except Exception as e:
        print(f'MIME Test [{name:28s}]: Exception: {e}')
