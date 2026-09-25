# SIH26106 Final Requirements & Verification Traceability Matrix

**Project Name:** MessageGuard  
**SIH Problem ID:** SIH26106  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Platform:** Android + FastAPI Backend  
**Audit Date:** September 2026  
**Verification Device:** Samsung Galaxy A56 5G (`SM-A566E`, Android 16, Serial: `RZGYB1BWX4T`)

---

## 1. Status Taxonomy
- **COMPLETE:** Implementation exists, passes automated & integration test suites, and is physically validated where applicable.
- **AUTOMATED VERIFIED:** Implementation exists and passes end-to-end automated unit/integration suites; physical hardware interaction not strictly required.
- **PHYSICAL VERIFIED:** Confirmed working on physical Android hardware (`SM-A566E`) via ADB/screencap/interaction.
- **PARTIAL:** Implemented with verified code paths, but environmental constraints (e.g. desktop Python missing TFLite Flex ops) limit 100% desktop test automation.
- **DISABLED BY DESIGN:** Intentionally deactivated due to missing feature extractors (e.g. BODMAS 2,381 feature extractor), documented transparently.
- **BLOCKED:** Cannot be verified due to external hardware or service dependency failure.
- **MISSING:** Not implemented in repository.

---

## 2. Requirement Traceability Matrix

| Requirement | Implementation Component | Source File | API / UI Surface | Automated Test | Physical Hardware Test | Status | Evidence / Notes |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **NLP Email Analysis** | Multilingual & regex NLP threat scorer | `backend/services/content_analyzer.py` | `/api/analyze-trigger` | PASS (`test_adversarial_suite.py`) | VERIFIED | **COMPLETE** | 250 test cases, 0 errors |
| **BEC & Wire Fraud Detection** | XGBoost ONNX & Heuristic Engine | `backend/services/content_analyzer.py` | `/api/ingest/microsoft-graph` | PASS (`test_5_ecosystems.py`) | VERIFIED | **COMPLETE** | Flagged urgent CEO wire fraud as MALICIOUS (90) |
| **Obfuscated URL Analysis** | Structural lexical scanner & ONNX URL model | `backend/services/content_analyzer.py` | Backend Pipeline | PASS (`test_adversarial_suite.py`) | VERIFIED | **COMPLETE** | Zero outbound fetches; SSRF safe |
| **MIME Parsing Robustness** | Python email parser with bounded body (50k chars) | `backend/services/content_analyzer.py` | `/api/ingest/eml` | PASS (`test_mime_fuzz.py`) | VERIFIED | **COMPLETE** | Handled malformed boundaries, truncated bodies |
| **SSRF Pre-Network Checks** | RFC 1918, loopback, and cloud metadata filter | `backend/services/domain_intel_service.py` | Outbound lookups | PASS (Unit checks) | VERIFIED | **COMPLETE** | Blocks `169.254.169.254`, `127.0.0.1`, `::1` |
| **SPF / DKIM / DMARC Forensics** | Header parser & alignment evaluator | `backend/main.py` | `/api/analyze-trigger` | PASS (`test_score_consistency.py`) | VERIFIED | **COMPLETE** | SPF/DKIM/DMARC evaluated with explicit auth status |
| **IPv4 / IPv6 Relay Forensics** | Top-down Received hop extractor | `backend/services/threat_intel_service.py` | Relay Analysis API | PASS (`test_adversarial_suite.py`) | VERIFIED | **COMPLETE** | Earliest reliable public hop extracted |
| **Infrastructure Geolocation** | MaxMind GeoIP with ip-api.com fallback & cache | `backend/services/threat_intel_service.py` | GeoIP Subsystem | PASS (`test_adversarial_suite.py`) | VERIFIED | **COMPLETE** | Country, City, ISP, ASN, network disclaimer |
| **5 Email Ecosystems** | Universal normalizer for Gmail, MS Graph, Yahoo, IMAP, EML | `backend/services/email_providers.py` | `/api/ecosystems/status`, `/api/ingest/*` | PASS (`test_5_ecosystems.py`) | VERIFIED | **COMPLETE** | 5/5 ecosystems produce normalized MG-XXXXXXXX cases |
| **Cross-Case Isolation** | SQLite atomic persistence & ReportLab uncompressed PDFs | `backend/services/report_service.py` | `/generate-report/{case_id}` | PASS (`test_cross_case_isolation.py`) | VERIFIED | **COMPLETE** | 10/10 cases isolated; zero leakage |
| **Evidence SHA-256 Hashing** | SHA-256 digest on raw payload and generated reports | `backend/services/report_service.py` | PDF Dossier Header | PASS (`test_adversarial_suite.py`) | VERIFIED | **COMPLETE** | Cryptographic hash embedded in PDF |
| **High-Threat Non-Dilution** | 60% ML / 40% Auth weighted ratio with override | `backend/main.py` | Score Engine | PASS (`test_score_consistency.py`) | VERIFIED | **COMPLETE** | Tested across 12 boundary score points |
| **Android Security Dashboard** | Reactive Monitor & Circular Security Index UI | `MainActivity.kt`, `activity_main.xml` | Mobile UI | PASS (Android Build) | **PHYSICAL VERIFIED** | **COMPLETE** | Verified on `SM-A566E` (Android 16) |
| **Android Forensic Details UI** | Case banner, auth badges, IP map, entity graph | `DetailActivity.kt`, `activity_detail.xml` | Mobile UI | PASS (Android Build) | **PHYSICAL VERIFIED** | **COMPLETE** | Verified on `SM-A566E` |
| **Relationship Graph Visualization** | ASCII/Topological entity graph (50 node cap) | `DetailActivity.kt` | Mobile UI | PASS (Android Build) | **PHYSICAL VERIFIED** | **COMPLETE** | Rendered on `SM-A566E` (6 nodes, 5 edges) |
| **Forensic PDF Export** | Android PDF file open intent / download | `DetailActivity.kt` | Mobile UI | PASS (Android Build) | **PHYSICAL VERIFIED** | **COMPLETE** | Verified on `SM-A566E` |
| **TFLite Text NLP Model** | `text_nlp_model.tflite` | `assets/text_nlp_model.tflite` | Mobile ML Engine | PASS (Android Runtime) | VERIFIED | **PARTIAL** | Runs in Android; requires Flex Op v12 in desktop Python |
| **BODMAS Malware Model** | `full_bodmas.onnx` | `assets/full_bodmas.onnx` | N/A | N/A | N/A | **DISABLED BY DESIGN** | Missing 2,381 feature extractor; safely bypassed |
| **Circle-to-Scan & Bubble** | Floating overlay & MediaProjection service | `FloatingBubbleService.kt` | Android Overlay | PASS (Android Build) | **PHYSICAL VERIFIED** | **COMPLETE** | Bubble active; PTT voice trigger integrated |
