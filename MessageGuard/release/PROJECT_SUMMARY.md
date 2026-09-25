# MessageGuard (Threat Vision) v1.0 — Project Summary & Architecture Overview

## Executive Summary
MessageGuard (Threat Vision) is a privacy-first, on-device AI security product built for Android. It addresses mobile cyber fraud, SMS phishing, WhatsApp malicious attachments, and Trojanized APK installers by delivering 100% edge-capable ML detection without uploading user message content or screen pixels to cloud servers.

---

## Headline Features

1. **Real-Time Passive Accessibility Protection:** Node-tree inspection across supported messaging apps with 1000ms debouncing, SHA-256 deduplication, and local TFLite NLP inference.
2. **Circle-to-Scan Region Crop:** User-initiated screen capture combining Google ML Kit OCR/Barcode scanning with TFLite CNN URL classifiers.
3. **Pre-Download Preliminary AI+ML Scanner:** Evaluates file download notifications, double extensions, and link reputation before payload completion on disk.
4. **Multi-Model Soft-Voting ONNX Ensemble:** Combines Random Forest ONNX and Malware ONNX models ($0.60 \times \text{RF} + 0.40 \times \text{Malware}$) at a calibrated `0.72f` threat boundary for document analysis.

---

## Accuracy & Scoring Rebalance Narrative

### The Original Issue
Early heuristic iterations suffered from false-positive `MALICIOUS` blocks on clean PDFs. The root cause was twofold:
1. FlateDecode zlib stream compression in clean PDFs produces normal whole-file entropy between 7.5 and 7.85 bits/byte, which was being misclassified as malware packing.
2. Uncorroborated structural findings were overriding the ML ensemble score rather than blending with it.

### The Resolution
1. **Weighted Score Synthesis:** Rebuilt the scoring pipeline into an explicit weighted formula:
   $$\text{finalScore} = (w_{\text{structural}} \cdot \text{structuralScore}) + (w_{\text{ml}} \cdot \text{ensembleScore})$$
2. **Corroboration Capping:** Uncorroborated single-signal findings (like standalone `/AA` actions or ordinary FlateDecode compression) are strictly capped below `SANDBOX_MALICIOUS_MIN` ($< 60$). Only corroborated findings or verified hard exploit triggers (`/Launch`, `/JS` + `/OpenAction`) can initiate a `MALICIOUS` verdict.

---

## Disclosed Known Limitations

- **Debug-Signed Package:** Signed using the standard debug keystore (`signingConfigs.debug`) for sideload evaluation and USB debugging installation.
- **Distribution Model:** Distributed via standalone APK sideloading rather than Google Play Store.
- **Target Architecture:** Compiled specifically for 64-bit ARM devices (`ARM64-v8a`), covering modern Android smartphones running API 26+ (Android 8.0 to Android 15).
