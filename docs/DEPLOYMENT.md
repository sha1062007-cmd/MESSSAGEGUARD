# MessageGuard — Deployment & Configuration Guide (SIH26106)

---

### 1. Prerequisites & Environment Matrix

| Component | Minimum Version | Recommended | Notes |
| :--- | :--- | :--- | :--- |
| **Android OS** | Android 8.0 (API 26) | Android 14+ (API 34) | Tested on physical Android devices & emulators |
| **JDK** | OpenJDK 17 | Eclipse Temurin 17 / Zulu 17 | Required for Gradle 8.13 + AGP 8.8+ |
| **Android Studio** | Android Studio Giraffe | Android Studio Koala / Ladybug | ViewBinding, Material 3, NDK |
| **Python** | Python 3.10 | Python 3.11.x | Required for FastAPI backend & ReportLab |
| **Node / Web** | Node.js 18 LTS | Node.js 20 LTS | Extension / Web Dashboard assets |

---

### 2. Backend Deployment

#### Step 1: Environment Configuration (`backend/.env`)
Create or verify `c:/POC2/backend/.env` using secure placeholders:

```ini
PORT=8000
NODE_ENV=development

# Google Workspace / Gmail OAuth2 Credentials
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/gmail/oauth2callback
GMAIL_REFRESH_TOKEN=your-gmail-refresh-token
GMAIL_USER_EMAIL=analyst@example.com

# Database & Storage
DATABASE_URL=./backend/database.sqlite
REPORTS_STORAGE_DIR=./backend/reports_storage
RETENTION_DAYS=90

# Optional Resend Alert API
ALERT_EMAIL=security-team@example.com
ALERT_FROM=alerts@messageguard.security
RESEND_API_KEY=re_placeholder_key
```

#### Step 2: Virtual Environment Setup & Dependencies
```powershell
cd c:\POC2\backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

#### Step 3: Run the Backend Service
```powershell
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```
Verify health:
```powershell
curl http://localhost:8000/health
```
Expected output:
```json
{
  "status": "ok",
  "service": "MessageGuard Threat Vision Backend",
  "version": "1.0.0",
  "gmail_configured": true
}
```

---

### 3. Android Application Compilation & Packaging

The active production Android codebase is located at:
`c:\POC2\MessageGuard`

#### Step 1: Verify `local.properties`
Ensure your Android SDK path is specified:
```properties
sdk.dir=C\:\\Users\\lenovo\\AppData\\Local\\Android\\Sdk
```

#### Step 2: Build Debug APK
```powershell
cd c:\POC2\MessageGuard
.\gradlew.bat assembleDebug --no-daemon
```
The output APK will be generated at:
`c:\POC2\MessageGuard\app\build\outputs\apk\debug\app-universal-debug.apk`

#### Step 3: Build Release APK
```powershell
.\gradlew.bat assembleRelease --no-daemon
```
The optimized release APK will be generated at:
`c:\POC2\MessageGuard\app\build\outputs\apk\release\app-universal-release.apk`

#### Step 4: Install onto Connected Physical Device via ADB
```powershell
adb devices
adb install -r app\build\outputs\apk\debug\app-universal-debug.apk
```

---

### 4. Android Runtime Permissions Checklist
For complete real-time protection, grant the following permissions:
1. **Notification Listener Service:** `Settings > Apps > Special app access > Notification access > MessageGuard` (Enables automatic suppression & scanning of incoming emails).
2. **Display over other apps (SYSTEM_ALERT_WINDOW):** Enables the floating security shield bubble and Circle-to-Scan trigger.
3. **Record Audio (Microphone):** Enables hands-free Threat Vision Voice Assistant.
4. **MediaProjection:** Screen capture permission requested when the user taps Circle-to-Scan on the floating bubble.
