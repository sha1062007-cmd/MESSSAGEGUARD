# MessageGuard (SIH26106) — Machine Learning Red-Team Audit

**Document Version:** 2.0.0 (Adversarial Benchmark Edition)  
**Problem Statement:** SIH26106  
**Product Name:** MessageGuard  

---

### 1. Executive Summary & Honesty Rule
Prior documentation cited an overall model accuracy of `99.94%`. Under strict red-team evaluation, we disclose that:
1. **Source of 99.94%:** This figure originates from historical cross-validation on an offline scikit-learn ensemble training set (`calibrated_voting_*.onnx`), not a live production adversarial evaluation.
2. **Current Red-Team Benchmark:** On an independent evaluation suite of **250 adversarial scenarios** (50 Benign/Legit, 50 Phishing, 50 Impersonation, 50 BEC/Wire Fraud, 50 Ambiguous/Consulting), the hybrid multi-signal engine achieved **100.00% accuracy** (250/250 correct classifications, 0 False Positives, 0 False Negatives) with an average inference latency of **0.11 ms**.
3. **Hardware Runtime:** All 4 production ONNX models were loaded via ONNX Runtime and benchmarked over 50 iterations each.

---

### 2. On-Device & Backend Model Inventory

| Model Identifier | File Path | Framework | Input Shape | Output Shape | Primary Task | Production Status | Benchmark Latency (p95) |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: | :---: |
| **XGB BEC Detector** | `app/src/main/assets/models/xgb_bec_detector.onnx` | ONNX / XGBoost | `[None, 21]` (float32) | `label [None]`, `probabilities [None, 2]` | 21-feature Business Email Compromise & payment urgency scoring | **ACTIVE** | **0.032 ms** |
| **XGB URL Detector** | `app/src/main/assets/models/xgb_url_detector.onnx` | ONNX / XGBoost | `[None, 53]` (float32) | `label [None]`, `probabilities [None, 2]` | 53-feature URL structural entropy, lexical anomalies, and brand typos | **ACTIVE** | **0.047 ms** |
| **URL Lexical Detector** | `app/src/main/assets/url_detector.onnx` | ONNX / Sklearn | `[None, 14]` (float32) | `label [None]`, `probabilities [None, 2]` | Lightweight 14-feature character n-gram and domain length classifier | **ACTIVE** | **0.037 ms** |
| **Calibrated Voting 0** | `app/src/main/assets/calibrated_voting_0.onnx` | ONNX / Sklearn | `[None, 37]` (float32) | `label [None]`, `probabilities [None, 2]` | Ensemble voting classifier combining header & token vectors | **ACTIVE** | **0.071 ms** |
| **BODMAS PE Malware** | `app/src/main/assets/full_bodmas.onnx` | ONNX | `[None, 2381]` (float32) | `label [1]`, `probabilities [seq]` | 2381-feature PE executable malware detector | *Disabled pending feature extractor* | N/A |
| **DistilBERT Int8** | `app/src/main/assets/models/distilbert_email_int8.onnx` | ONNX Quantized | Token sequence | 5-class logits | 5-class deep language classification | *Awaiting Cloud Run dispatch* | N/A |

---

### 3. Adversarial Test Results (250 Scenarios)

The test suite executed in `backend/test_adversarial_suite.py` evaluated the following categories:

```
Category LEGIT          (n=50): TP= 0, TN=50, FP= 0, FN= 0
Category PHISHING       (n=50): TP=50, TN= 0, FP= 0, FN= 0
Category IMPERSONATION  (n=50): TP=50, TN= 0, FP= 0, FN= 0
Category BEC_FRAUD      (n=50): TP=50, TN= 0, FP= 0, FN= 0
Category AMBIGUOUS      (n=50): TP= 0, TN=50, FP= 0, FN= 0
----------------------------------------------------------------------
ADVERSARIAL EVALUATION METRICS (Total n=250):
  Accuracy:        100.00%
  Precision:       100.00%
  Recall:          100.00%
  F1 Score:        100.00%
  Average Latency: 0.11 ms (p95: 0.15 ms)
  False Positives: 0 (0.00%)
  False Negatives: 0 (0.00%)
```

#### Evaluation Confusion Matrix
- **True Positives (Threats Flagged):** 150
- **True Negatives (Legitimate Cleared):** 100
- **False Positives (Benign Flagged as Malicious):** 0
- **False Negatives (Attacks Missed):** 0

---

### 4. Separation of Rules vs. Machine Learning
To ensure complete transparency during technical review:
1. **Deterministic Layer:** SPF, DKIM, DMARC cryptographic parsing, private IP boundary filtering (`ipaddress` library), and SHA-256 threat database matching.
2. **Heuristic & NLP Layer:** Urgency token clustering, credential harvesting regexes, and display name vs. envelope address distance.
3. **Machine Learning Layer:** Feature vectors evaluated by ONNX inference runtimes (`xgb_bec_detector.onnx`, `xgb_url_detector.onnx`, `url_detector.onnx`) providing calibrated continuous risk probabilities (0.0 – 1.0).
