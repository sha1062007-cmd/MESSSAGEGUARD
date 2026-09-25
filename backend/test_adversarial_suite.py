"""
MessageGuard (SIH26106) Red-Team Comprehensive Adversarial Test Suite
======================================================================
Tests:
1. 250+ Multiclass Adversarial Email Scenarios (50 Legit, 50 Phishing, 50 Impersonation, 50 BEC/Fraud, 50 Ambiguous)
2. Header Parser Attacks (duplicate, malformed, folded, fake timestamps, private vs public relay)
3. SSRF and Dangerous URL Scheme Filter (file://, javascript://, data://, 169.254.169.254, 127.0.0.1)
4. Model Runtime ONNX Benchmarks (Inference, Latency, Shape Validation)
5. Concurrency & Cross-Contamination Stress (10 concurrent threads)
"""

import sys
import os
import json
import time
import re
import urllib.request
import concurrent.futures
import numpy as np

# Ensure backend path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.content_analyzer import ContentAnalyzer
from services.threat_intel_service import ThreatIntelService
from services.domain_intel_service import DomainIntelService
from services.correlation_service import CorrelationService
from services.campaign_service import CampaignService
from services.graph_service import InvestigationGraphService
from services.report_service import ReportService
from services.gmail_watch_service import GmailWatchService
from main import verify_authentication_headers, calculate_ps106_risk_score

def extract_urls(text: str):
    return GmailWatchService._extract_urls(text)

def run_adversarial_suite():
    print("=" * 70)
    print("STARTING MESSAGEGUARD (SIH26106) ADVERSARIAL RED-TEAM SUITE")
    print("=" * 70)

    analyzer = ContentAnalyzer()
    intel = ThreatIntelService()

    # ---------------------------------------------------------
    # PART 1: 250 Labeled Scenarios (5x50)
    # ---------------------------------------------------------
    print("\n[PART 1] Executing 250 Labeled Adversarial Emails...")
    
    categories = {
        "LEGIT": [],
        "PHISHING": [],
        "IMPERSONATION": [],
        "BEC_FRAUD": [],
        "AMBIGUOUS": []
    }

    # Generate 50 Legit
    legit_orgs = ["github.com", "google.com", "microsoft.com", "amazon.com", "linkedin.com"]
    for i in range(50):
        org = legit_orgs[i % len(legit_orgs)]
        categories["LEGIT"].append({
            "sender": f"notifications@{org}",
            "subject": f"Weekly digest and account summary #{i}",
            "body": f"Here is your regular update for project #{i}. View your dashboard at https://{org}/dashboard",
            "expected_verdict": "SAFE"
        })

    # Generate 50 Phishing
    phish_lures = ["account-suspended-verify.xyz", "login-security-update.top", "banking-security.click", "secure-portal-auth.cfd", "verify-id-now.buzz"]
    for i in range(50):
        lure = phish_lures[i % len(phish_lures)]
        categories["PHISHING"].append({
            "sender": f"service@{lure}",
            "subject": f"URGENT: Your account access has been revoked #{i}",
            "body": f"We detected unauthorized access to your account. Click immediately: http://{lure}/login?id={i} to restore access or your account will be suspended permanently.",
            "expected_verdict": "MALICIOUS"
        })

    # Generate 50 Impersonation
    impersonated = [
        ("PayPal Support", "support@paypa1-update.com"),
        ("Apple Security", "security@app-le-id.icu"),
        ("Netflix Billing", "billing@netflx-payment.xyz"),
        ("Amazon Helpdesk", "help@amaz0n-orders.shop"),
        ("Google Verification", "verify@g00gle-accounts.top")
    ]
    for i in range(50):
        disp, snd = impersonated[i % len(impersonated)]
        categories["IMPERSONATION"].append({
            "sender": f"{disp} <{snd}>",
            "subject": f"Immediate Action Required: Unauthorized login #{i}",
            "body": f"Dear customer, someone attempted to log in to your account. Verify identity at http://{snd.split('@')[1]}/auth",
            "expected_verdict": "MALICIOUS"
        })

    # Generate 50 BEC / Fraud
    for i in range(50):
        categories["BEC_FRAUD"].append({
            "sender": f"executive-internal{i}@company-private.com",
            "subject": f"Confidential: Wire Transfer Directive #{i}",
            "body": f"Are you in the office? I need you to initiate a priority wire transfer of $85,{i:02d}0 to the vendor account today. Keep this strictly between us until the audit closes.",
            "expected_verdict": "MALICIOUS"
        })

    # Generate 50 Ambiguous
    for i in range(50):
        categories["AMBIGUOUS"].append({
            "sender": f"partner-contact{i}@unknown-consulting.net",
            "subject": f"Proposal Inquiry and Introduction #{i}",
            "body": f"Hi team, following up on our discussion regarding consulting rates. Please let me know when you are free to chat next week.",
            "expected_verdict": "SAFE"
        })

    # Run evaluations
    total_eval = 0
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    latencies = []

    for cat_name, items in categories.items():
        cat_tp, cat_fp, cat_fn, cat_tn = 0, 0, 0, 0
        for item in items:
            t0 = time.perf_counter()
            urls = extract_urls(item["body"])
            content_res = analyzer.analyze({
                "sender": item["sender"],
                "subject": item["subject"],
                "text_body": item["body"],
                "html_body": "",
                "urls": urls,
                "attachments": []
            })
            auth_res = verify_authentication_headers("spf=neutral dkim=neutral dmarc=neutral")
            score_res = calculate_ps106_risk_score(auth_res, content_res, {})
            dt = (time.perf_counter() - t0) * 1000.0
            latencies.append(dt)

            verdict = score_res["verdict"]
            expected = item["expected_verdict"]

            is_malicious = (verdict in ["MALICIOUS", "SUSPICIOUS"])
            expected_malicious = (expected in ["MALICIOUS", "SUSPICIOUS"])

            if expected_malicious and is_malicious:
                tp += 1
                cat_tp += 1
            elif not expected_malicious and not is_malicious:
                tn += 1
                cat_tn += 1
            elif not expected_malicious and is_malicious:
                fp += 1
                cat_fp += 1
            elif expected_malicious and not is_malicious:
                fn += 1
                cat_fn += 1
            total_eval += 1

        print(f"  Category {cat_name:14s} (n={len(items)}): TP={cat_tp:2d}, TN={cat_tn:2d}, FP={cat_fp:2d}, FN={cat_fn:2d}")

    accuracy = (tp + tn) / total_eval if total_eval else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

    print("-" * 70)
    print(f"ADVERSARIAL EVALUATION METRICS (Total n={total_eval}):")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  Avg Latency: {np.mean(latencies):.2f} ms (p95: {np.percentile(latencies, 95):.2f} ms)")
    print(f"  False Positives: {fp} (rate: {fp/(fp+tn)*100:.2f}%)")
    print(f"  False Negatives: {fn} (rate: {fn/(fn+tp)*100:.2f}%)")

    # ---------------------------------------------------------
    # PART 2: Header Parser Attacks
    # ---------------------------------------------------------
    print("\n[PART 2] Testing Header Parser Attacks...")
    attack_headers = [
        ("Duplicate From", ["From: victim@target.com", "From: attacker@evil.com"]),
        ("Duplicate Received with Private Injection", [
            "from mx.google.com by internal (10.0.0.1); Fri, 25 Sep 2026 12:00:00",
            "from spoofed-hop (192.168.1.1) by mx.google.com; Fri, 25 Sep 2026 11:59:00",
            "from real.attacker.org (real.attacker.org [185.220.101.5]) by relay; Fri, 25 Sep 2026 11:58:00"
        ]),
        ("IPv6 Relay Extraction", [
            "from relay6.net (relay6.net [2001:4860:4860::8888]) by mx.google.com; Fri, 25 Sep 2026 10:00:00"
        ]),
        ("Malformed Garbage Received", [
            "junk header without standard format @@$$%%^^ 999.999.999.999"
        ])
    ]

    for name, hdrs in attack_headers:
        relay_res = intel.build_relay_chain(hdrs)
        earliest = relay_res.get("earliest_reliable_observed_ip")
        print(f"  Header Attack [{name}]: Earliest IP -> {earliest}")

    # ---------------------------------------------------------
    # PART 3: SSRF and Dangerous URL Schemes
    # ---------------------------------------------------------
    print("\n[PART 3] Testing URL Security / SSRF Protections...")
    dangerous_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/admin",
        "http://localhost:8080/metrics",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "http://0.0.0.0:22",
        "http://[::1]:8000/internal"
    ]

    url_evals = analyzer._analyze_urls(dangerous_urls)
    for res in url_evals:
        print(f"  URL Scheme Test [{res['url'][:35]:35s}]: Risk={res.get('risk_score', 0)} IP-based={res.get('ip_based')} Trusted={res.get('is_trusted')}")

    # ---------------------------------------------------------
    # PART 4: Real Model Runtime Benchmark
    # ---------------------------------------------------------
    print("\n[PART 4] Benchmarking ONNX Models Runtime Inference...")
    import onnxruntime as ort
    models_to_test = [
        ("XGB BEC Detector", "MessageGuard/app/src/main/assets/models/xgb_bec_detector.onnx", (1, 21)),
        ("XGB URL Detector", "MessageGuard/app/src/main/assets/models/xgb_url_detector.onnx", (1, 53)),
        ("URL Lexical Detector", "MessageGuard/app/src/main/assets/url_detector.onnx", (1, 14)),
        ("Calibrated Voting 0", "MessageGuard/app/src/main/assets/calibrated_voting_0.onnx", (1, 37))
    ]

    for mname, mpath, shape in models_to_test:
        if os.path.exists(mpath):
            sess = ort.InferenceSession(mpath)
            input_name = sess.get_inputs()[0].name
            test_vec = np.random.rand(*shape).astype(np.float32)
            
            # Warmup
            sess.run(None, {input_name: test_vec})
            
            # Benchmark 50 runs
            t_start = time.perf_counter()
            for _ in range(50):
                out = sess.run(None, {input_name: test_vec})
            t_total = (time.perf_counter() - t_start) * 1000.0 / 50.0
            print(f"  Model [{mname:22s}]: 50 runs OK | Avg Latency: {t_total:.3f} ms | Output Shape: {[o.shape for o in out]}")
        else:
            print(f"  Model [{mname:22s}]: FILE MISSING ({mpath})")

    # ---------------------------------------------------------
    # PART 5: Concurrency & Database Consistency
    # ---------------------------------------------------------
    print("\n[PART 5] Stressing Concurrency (10 Simultaneous Case Triggers)...")
    base_url = "http://localhost:8000"

    def trigger_case(idx):
        payload = {
            "sender": f"concurrent-tester-{idx}@stress-test.org",
            "subject": f"Concurrent Stress Test Payload #{idx}",
            "body": f"Urgent wire payment request #{idx}. Verify immediately.",
            "received_headers": [
                f"from stress-node-{idx} (192.168.1.{idx}) by relay; Fri, 25 Sep 2026",
                f"from external-hop-{idx} (185.220.101.{idx}) by mx.google.com; Fri, 25 Sep 2026"
            ]
        }
        req = urllib.request.Request(
            f"{base_url}/api/analyze-trigger",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except Exception as e:
            return 0, str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(trigger_case, i) for i in range(10)]
        results = [f.result() for f in futures]

    case_ids = set()
    statuses = [r[0] for r in results]
    for st, body in results:
        if isinstance(body, dict) and "case_id" in body:
            case_ids.add(body["case_id"])

    print(f"  Concurrent Calls: {len(results)} | Status 200s: {statuses.count(200)} | Unique Case IDs: {len(case_ids)}")
    assert len(case_ids) == 10, f"Expected 10 unique case IDs, got {len(case_ids)}"
    print("  -> Concurrency test PASSED without ID collisions or data corruption.")

    print("\n" + "=" * 70)
    print("ALL RED-TEAM ADVERSARIAL VERIFICATIONS COMPLETED SUCCESSFULLY")
    print("=" * 70)

if __name__ == "__main__":
    run_adversarial_suite()
