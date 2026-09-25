# SafeScan - AI-Powered Security Extension

## Overview

SafeScan is a comprehensive Chrome extension that provides real-time protection against malicious URLs, files, and phishing emails using advanced AI models and multiple security APIs.

## Features

### 1. **URL Protection**
- Real-time URL scanning before navigation
- AI-powered phishing detection
- VirusTotal integration for global threat intelligence
- URLScan.io for comprehensive analysis
- AbuseIPDB for malicious IP/domain detection
- Automatic blocking of high-risk URLs

### 2. **File Security**
- Pre-download file scanning
- PE file analysis using EMBER-based models
- VirusTotal hash checking
- Heuristic analysis for suspicious patterns
- User confirmation before downloading risky files

### 3. **Email Protection**
- Gmail integration for real-time email scanning
- AI-powered phishing detection
- Sender reputation analysis
- Content-based threat detection
- Visual warnings for suspicious emails

## Architecture

### Core Components

1. **Background Service Worker** (`background.js`)
   - Central scanning engine
   - API coordination
   - Download interception
   - Navigation monitoring

2. **Content Scripts**
   - `content.js`: Main content script for all URLs
   - `email_scanner.js`: Gmail-specific email scanning
   - `overlay.js`: UI overlay for scan results

3. **API Integration** (`external_apis.js`)
   - VirusTotal API integration
   - URLScan.io integration
   - AbuseIPDB integration
   - Result fusion logic

4. **Helper Functions** (`helpers.js`)
   - File hash calculation
   - Heuristic analysis
   - Storage management
   - URL validation

5. **Configuration** (`config.js`)
   - API keys and endpoints
   - Scan thresholds
   - Extension settings

## API Keys and Services

### Required API Keys

1. **VirusTotal API**
   - Purpose: URL and file hash checking
   - Get key: https://www.virustotal.com/gui/join-us
   - Free tier: 500 requests/day
   - Rate limit: 4 requests/minute

2. **URLScan.io API**
   - Purpose: Comprehensive URL analysis
   - Get key: https://urlscan.io/user/signup
   - Free tier: 1000 scans/month
   - Rate limit: 1 request/second

3. **AbuseIPDB API**
   - Purpose: IP/domain reputation
   - Get key: https://www.abuseipdb.com/account/register
   - Free tier: 1000 requests/day
   - Rate limit: 1 request/second

### Optional Services

4. **WHOIS API**
   - Purpose: Domain age and ownership information
   - Get key: Various providers available
   - Recommended: WhoisXML API

## Installation

### Prerequisites

1. Python 3.8+ with required packages:
   ```bash
   pip install flask flask-cors pyngrok numpy xgboost requests lief beautifulsoup4
   ```

2. Trained AI models:
   - `XGBoostClassifier.pickle.dat` (URL detection)
   - `phishing_detector.pkl` (Email detection)
   - `preprocessed_data.pkl` (Email vectorizer)
   - `xgb_malware_model.json` (File detection)

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SafeScan_Extension
   ```

2. **Start the API server**
   ```bash
   cd extension
   python colab_api.py
   ```

3. **Update configuration**
   - Open `config.js`
   - Update `BASE_API_URL` with your ngrok URL
   - Add API keys for external services

4. **Load extension in Chrome**
   - Open Chrome and go to `chrome://extensions/`
   - Enable Developer mode
   - Click "Load unpacked"
   - Select the `extension` folder

## Usage

### URL Scanning
- Extension automatically scans URLs before navigation
- High-risk URLs are blocked with warning page
- Medium-risk URLs show warning notifications
- Safe URLs proceed normally

### File Downloads
- Downloads are automatically paused for scanning
- Results show AI confidence and VirusTotal hits
- User can choose to download or cancel
- Suspicious files require explicit confirmation

### Email Protection
- Works automatically in Gmail
- Shows scanning indicator during analysis
- Displays results overlay with confidence scores
- Phishing emails show prominent warnings

## Configuration Options

### Scan Thresholds
```javascript
THRESHOLDS: {
    FILE_HIGH_RISK: 0.80,    // Files above 80% risk are blocked
    URL_HIGH_RISK: 0.70,     // URLs above 70% risk are blocked
    EMAIL_PHISHING: 0.60     // Emails above 60% risk are flagged
}
```

### File Size Limits
```javascript
MAX_SCAN_SIZE_MB: 50  // Maximum file size for scanning
```

### Feature Toggles
```javascript
ENABLE_VIRUSTOTAL: true,
ENABLE_URLSCAN: true,
ENABLE_ABUSEIPDB: true,
ENABLE_HEURISTICS: true,
ENABLE_AI_SCANNING: true
```

## Model Integration

### URL Detection Model
- **Input**: 17 URL features (IP address, length, depth, etc.)
- **Model**: XGBoost Classifier
- **Output**: Phishing probability

### File Detection Model
- **Input**: PE file features (EMBER-based)
- **Model**: XGBoost Booster
- **Output**: Malware probability

### Email Detection Model
- **Input**: Text vectorization (TF-IDF)
- **Model**: Scikit-learn Classifier
- **Output**: Phishing probability

## Security Considerations

### Privacy
- All scanning happens locally or via secure APIs
- No personal data is stored permanently
- API keys are encrypted in storage

### Performance
- Caching prevents redundant scans
- Asynchronous processing avoids blocking
- Rate limiting respects API constraints

### Reliability
- Graceful fallback if APIs are unavailable
- Local AI models work offline
- Multiple threat sources reduce false positives

## Troubleshooting

### Common Issues

1. **Extension not loading**
   - Check manifest.json syntax
   - Ensure all files are present
   - Verify permissions

2. **API connection errors**
   - Verify ngrok URL is current
   - Check API keys are valid
   - Ensure firewall allows connections

3. **Models not loading**
   - Verify model file paths
   - Check file permissions
   - Ensure dependencies are installed

### Debug Mode
Enable console logging:
```javascript
// In config.js
DEBUG_MODE: true
```

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

### Code Style
- Use ES6+ features
- Follow JavaScript Standard Style
- Add comprehensive comments
- Include error handling

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review GitHub issues
3. Create new issue with details

## Changelog

### v1.0.0
- Initial release
- URL, file, and email protection
- Multiple API integrations
- AI-powered threat detection
