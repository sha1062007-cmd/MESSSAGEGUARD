# Gmail/Universal Real-time Threat Detector Extension - Complete Creation Prompt

Create a Chrome extension that provides real-time threat detection across Gmail and all websites with the following exact specifications:

## 🎯 **Core Requirements**

### **Extension Structure:**
```
extension/
├── manifest.json
├── background.js
├── content.js (for Gmail)
├── universal-scanner.js (for all other websites)
├── popup.html
├── popup.js
├── style.css
└── icons/
    ├── safe.png
    └── warning.png
```

### **Manifest (manifest.json):**
```json
{
  "manifest_version": 3,
  "name": "Real-time Threat Detector",
  "version": "1.0",
  "description": "Real-time AI-powered threat detection for Gmail and all websites",
  "permissions": [
    "storage",
    "downloads",
    "activeTab", 
    "scripting",
    "notifications"
  ],
  "host_permissions": [
    "https://mail.google.com/*",
    "http://localhost:5000/*",
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/*"],
      "js": ["content.js"]
    },
    {
      "matches": ["<all_urls>"],
      "js": ["universal-scanner.js"],
      "exclude_matches": ["https://mail.google.com/*"]
    }
  ],
  "action": {
    "default_popup": "popup.html"
  },
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}
```

## ⚡ **Real-time Features**

### **Gmail Scanner (content.js):**
- **Hover Detection**: Instant threat analysis on email hover
- **Real-time Scanning**: Every 1 second for opened emails
- **Attachment Analysis**: Scan all email attachments
- **Threat Percentages**: Show exact risk levels (0-100%)
- **Smart Extraction**: Extract subject, sender, preview, attachments
- **Auto-dismiss**: Alerts disappear after 5 seconds

### **Universal Scanner (universal-scanner.js):**
- **Page Load**: Scan within 0.5 seconds
- **Continuous Monitoring**: Every 2 seconds
- **Input Detection**: Scan when user types in forms (0.5 second delay)
- **Dynamic Content**: Respond to page changes in 1 second
- **Multi-platform**: Works on all websites except Gmail
- **Content Analysis**: Extract text, title, URL for threat detection

### **Background Service (background.js):**
- **Download Monitoring**: Real-time file analysis on download
- **Universal Coverage**: Works across all websites
- **Threat Percentages**: Show exact risk levels
- **Smart Notifications**: Browser + on-page alerts
- **File Analysis**: Check extensions, sizes, sources, MIME types

### **Popup Interface (popup.html + popup.js):**
- **Real-time Status**: "⚡ Real-time Protection Active"
- **Backend Check**: "🟢 Real-time Backend Connected" status
- **Feature List**: Show all active protections
- **Visual Indicators**: Lightning bolt icons for speed

## 🧠 **Backend Requirements**

### **Flask Server (server.py):**
```python
# Required endpoints:
@app.route("/scan", methods=["POST"])  # Gmail/content scanning
@app.route("/scan-download", methods=["POST"])  # Download analysis  
@app.route("/scan-universal", methods=["POST"])  # Website scanning

# Features needed:
- 7-point threat analysis system
- Threat percentage calculation (0-100%)
- Multiple file type detection
- URL pattern analysis
- Content quality assessment
- Suspicious keyword detection
- Financial request monitoring
- Technical threat identification
```

### **Threat Detection Logic:**
```python
# Gmail/Email Analysis:
1. Sensitive Words (password, otp, bank, verify, login)
2. Urgency (urgent, immediately, action required)
3. Suspicious Links (http:// vs https:// count)
4. Financial Keywords (payment, transfer, invoice, billing)
5. Generic Greeting (Dear User, Valued Customer)
6. Attachment Risk (.zip, .exe, .scr, .js)
7. Attachment Count

# Universal Website Analysis:
1. Suspicious Keywords (phishing, malware, scam, hack)
2. URL Suspicion (shorteners, suspicious domains)
3. Title Analysis (clickbait, suspicious phrases)
4. Content Quality (excessive caps, poor grammar)
5. Personal Info Requests (passwords, SSN, credit card)
6. Financial Requests (payment, transfer, donate)
7. Technical Threats (download, install, execute)

# Download Analysis:
1. File Extension Risk (.exe, .scr, .bat, .com, .pif, .vbs, .js)
2. File Size Analysis (<1KB or >100MB suspicious)
3. Suspicious URL Patterns (bit.ly, tinyurl.com, etc.)
4. MIME Type Risk (application/x-executable, etc.)
5. Filename Suspiciousness (setup, crack, keygen, patch)
6. Chrome Danger Assessment
7. Domain Reputation (suspicious TLDs)
```

## 🎨 **UI/UX Requirements**

### **Alert System:**
- **Color Coding**: Red (#ff4d4d) for threats, Green (#28a745) for safe
- **Threat Meter**: Visual percentage bars
- **Auto-dismiss**: All alerts disappear after exactly 5 seconds
- **Positioning**: Fixed top-right, z-index 9999
- **Responsive**: Max-width 350-450px
- **Icons**: ⚠️ for threats, ✔️ for safe

### **Real-time Performance:**
- **Gmail**: Scan every 1 second
- **Websites**: Scan every 2 seconds  
- **Page Load**: Initial scan within 0.5 seconds
- **Content Changes**: Respond within 1 second
- **User Input**: Respond within 0.5 seconds
- **Hover**: Instant analysis on mouse over

## 🔧 **Technical Specifications**

### **Dependencies:**
```json
{
  "frontend": "Vanilla JavaScript (ES6+)",
  "backend": "Python 3.7+",
  "frameworks": {
    "frontend": "None (pure JS)",
    "backend": "Flask 2.3.3"
  },
  "libraries": {
    "backend": ["flask==2.3.3", "numpy==1.24.3", "flask-cors==4.0.0"]
  }
}
```

### **Performance Targets:**
- **Initial Load**: <1 second
- **Scan Response**: <500ms
- **Memory Usage**: <50MB
- **CPU Impact**: <5%
- **Network Requests**: Optimized with caching

## 🚀 **Installation Instructions**

### **For Users:**
1. **Backend Setup**:
   ```bash
   cd backend
   pip install flask flask-cors numpy
   python server.py
   ```

2. **Extension Loading**:
   - Open Chrome → chrome://extensions
   - Enable Developer Mode
   - Click "Load unpacked"
   - Select extension folder
   - Verify all permissions

3. **Testing**:
   - Visit Gmail → Hover over emails
   - Visit any website → See real-time alerts
   - Download files → Get instant threat analysis

## 🎯 **Success Metrics**

### **Key Performance Indicators:**
- ✅ Real-time detection (<1 second latency)
- ✅ Universal coverage (all websites)
- ✅ Accurate threat percentages (0-100%)
- ✅ Minimal false positives
- ✅ Smooth user experience
- ✅ Resource efficient operation

### **User Experience Goals:**
- 🚀 Instant threat visibility
- 🛡️ Comprehensive protection
- ⚡ Real-time responsiveness
- 🎨 Clean, non-intrusive UI
- 🔒 Privacy-focused operation

---

**Create this extension with all features exactly as specified. The key is REAL-TIME operation - everything must respond instantly with threat percentages and visual indicators.**
