# MessageGuard (Threat Vision) v1.0 — Reviewer Installation Guide

MessageGuard is a privacy-first, on-device AI security suite for Android. It monitors incoming messages, screen selections, and file downloads in real time to intercept phishing links, malware attachments, and scam text patterns with sub-30ms latency.

---

## Installation Steps

1. **Transfer File:** Download or transfer `MessageGuard-v1.0-release.apk` to your ARM64 Android device (Android 8.0+ / API 26+).
2. **Enable Unknown Sources:** If prompted by Android OS, tap **Settings** on the prompt and enable *"Allow from this source"*.
3. **Install App:** Open `MessageGuard-v1.0-release.apk` in your file manager and tap **Install**.

---

## Required Permissions & Rationale

- **Accessibility Service:** Used strictly to inspect incoming message node text across WhatsApp, Gmail, Telegram, and SMS in real time for phishing links. *No screen pixels are recorded or uploaded.*
- **Screen Share (MediaProjection):** Used only when you tap the floating bubble to perform a manual **Circle-to-Scan** region crop. *Activated strictly on explicit user gesture.*
- **Overlay Permission ("Draw Over Other Apps"):** Displays the floating green scanner bubble and instant threat alert cards on screen.
- **Notification Listener Access:** Intercepts background download notifications to perform pre-download risk checks.

---

## 5-Step Evaluation Checklist

Once installed, try these 5 core interactions:

1. **Dashboard Check:** Open Threat Vision $\rightarrow$ Observe the animated circular **Security Index Gauge** and status indicator.
2. **Circle-to-Scan:** Tap the floating green bubble on screen $\rightarrow$ Draw a gesture box around any message or link $\rightarrow$ Confirm ML Kit OCR & TFLite threat evaluation completes in sub-30ms.
3. **Quick Settings Tile Sync:** Pull down Android Quick Settings $\rightarrow$ Tap the **MessageGuard** tile to toggle protection OFF $\rightarrow$ Open the app to confirm status reflects OFF immediately.
4. **MediaProjection Token Teardown:** Toggle protection OFF $\rightarrow$ Observe status bar cast icon disappear immediately. Toggle ON $\rightarrow$ Confirm system screen-share consent dialog reappears.
5. **Detailed Forensic Breakdown:** Tap any item in File Sandbox or Log History $\rightarrow$ Expand *"Technical Details"* to view the blended **Structural + ML Ensemble Score Breakdown**.
