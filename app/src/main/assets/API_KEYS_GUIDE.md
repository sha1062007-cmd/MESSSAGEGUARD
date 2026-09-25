# SafeScan API Keys Guide

## Overview

SafeScan integrates with multiple external security APIs to provide comprehensive threat detection. This guide explains how to obtain and configure API keys for each service.

## 1. VirusTotal API

### Purpose
- URL reputation checking
- File hash analysis
- Global threat intelligence

### How to Get API Key
1. Visit https://www.virustotal.com/gui/join-us
2. Create a free account
3. Go to your API key section: https://www.virustotal.com/gui/join-us/newsletter
4. Copy your API key

### Rate Limits
- **Free Tier**: 500 requests/day, 4 requests/minute
- **Premium Tier**: Higher limits available

### Configuration
```javascript
// In config.js
API_KEYS: {
    VIRUSTOTAL: "your-api-key-here"
}
```

## 2. URLScan.io API

### Purpose
- Comprehensive URL analysis
- Screenshot capture
- Technology stack detection
- Malicious URL identification

### How to Get API Key
1. Visit https://urlscan.io/user/signup
2. Create a free account
3. Go to your dashboard
4. Copy your API key

### Rate Limits
- **Free Tier**: 1000 scans/month, 1 request/second
- **Premium Tier**: Higher limits available

### Configuration
```javascript
// In config.js
API_KEYS: {
    URLSCAN: "your-api-key-here"
}
```

## 3. AbuseIPDB API

### Purpose
- IP address reputation
- Malicious IP detection
- Abuse reporting
- Geographic information

### How to Get API Key
1. Visit https://www.abuseipdb.com/account/register
2. Create a free account
3. Verify your email
4. Go to your account dashboard
5. Copy your API key

### Rate Limits
- **Free Tier**: 1000 requests/day
- **Premium Tier**: Higher limits available

### Configuration
```javascript
// In config.js
API_KEYS: {
    ABUSEIPDB: "your-api-key-here"
}
```

## 4. WHOIS API (Optional)

### Purpose
- Domain age verification
- Ownership information
- Registration details

### Recommended Services
1. **WhoisXML API**
   - Visit: https://whoisxmlapi.com/
   - Free tier: 1000 requests/month
   - API key provided after registration

2. **JSON WHOIS**
   - Visit: https://jsonwhois.com/
   - Free tier: 1000 requests/month
   - Simple REST API

### Configuration
```javascript
// In config.js
API_KEYS: {
    WHOIS: "your-whois-api-key-here"
}
```

## 5. Additional Security APIs (Optional)

### Shodan API
- Purpose: Internet-connected device detection
- Website: https://www.shodan.io/
- Free tier: 100 requests/month

### IPQualityScore API
- Purpose: IP/URL reputation and fraud scoring
- Website: https://www.ipqualityscore.com/
- Free tier: 5000 requests/month

### Google Safe Browsing API
- Purpose: Malicious URL detection
- Website: https://developers.google.com/safe-browsing/
- Free tier: 10,000 requests/day

## API Key Security

### Best Practices
1. **Never commit API keys to version control**
2. **Use environment variables in production**
3. **Rotate keys regularly**
4. **Monitor usage for anomalies**
5. **Use least privilege principle**

### Storage Options
```javascript
// Option 1: Direct in config.js (development only)
API_KEYS: {
    VIRUSTOTAL: "your-key-here"
}

// Option 2: Chrome Storage (recommended)
chrome.storage.sync.set({
    apiKeys: {
        VIRUSTOTAL: "your-key-here"
    }
});

// Option 3: Environment variables (production)
process.env.VIRUSTOTAL_API_KEY
```

## Rate Limiting Strategy

### Implementation
SafeScan implements intelligent rate limiting:

```javascript
// Built-in rate limiting
const RATE_LIMITS = {
    VIRUSTOTAL: { requests: 4, window: 60000 },  // 4/min
    URLSCAN: { requests: 1, window: 1000 },      // 1/sec
    ABUSEIPDB: { requests: 1, window: 1000 }     // 1/sec
};
```

### Caching Strategy
- URL results cached for 24 hours
- File hash results cached permanently
- Email results cached per session

## Cost Estimation

### Free Tier Usage
- **VirusTotal**: 500 requests/day = ~15,000 requests/month
- **URLScan**: 1000 requests/month
- **AbuseIPDB**: 1000 requests/day = ~30,000 requests/month
- **Total**: ~46,000 requests/month at no cost

### Premium Tiers (if needed)
- **VirusTotal Premium**: ~$2,500/year
- **URLScan Premium**: ~$50/month
- **AbuseIPDB Premium**: ~$50/month

## Testing API Keys

### VirusTotal Test
```bash
curl -X GET "https://www.virustotal.com/api/v3/domains/google.com" \
  -H "x-apikey: your-api-key"
```

### URLScan Test
```bash
curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com", "visibility": "public"}'
```

### AbuseIPDB Test
```bash
curl -X POST "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: your-api-key" \
  -H "Accept: application/json" \
  -d "maxAgeInDays=90&ipAddress=8.8.8.8"
```

## Troubleshooting

### Common Issues
1. **Invalid API Key**
   - Verify key is correct
   - Check for extra spaces/characters
   - Ensure account is active

2. **Rate Limit Exceeded**
   - Check current usage
   - Implement caching
   - Upgrade to premium tier

3. **Network Issues**
   - Verify firewall allows API calls
   - Check DNS resolution
   - Test with curl commands

### Debug Mode
Enable API debugging:
```javascript
// In config.js
DEBUG_APIS: true,
LOG_API_RESPONSES: true
```

## Monitoring and Analytics

### Usage Tracking
```javascript
// Built-in usage tracking
const apiUsage = {
    VIRUSTOTAL: { requests: 0, lastReset: Date.now() },
    URLSCAN: { requests: 0, lastReset: Date.now() },
    ABUSEIPDB: { requests: 0, lastReset: Date.now() }
};
```

### Alert Thresholds
- 80% of rate limit reached: Warning
- 95% of rate limit reached: Critical
- API key invalid: Immediate alert

## Compliance

### Data Protection
- All API calls use HTTPS
- No personal data transmitted
- GDPR compliant
- CCPA compliant

### Terms of Service
Each API provider has specific terms:
- VirusTotal: Acceptable use policy
- URLScan: Data usage terms
- AbuseIPDB: Reporting guidelines

## Support

### Getting Help
1. Check provider documentation
2. Review API status pages
3. Contact provider support
4. Check community forums

### Status Pages
- VirusTotal: https://status.virustotal.com/
- URLScan: https://status.urlscan.io/
- AbuseIPDB: No dedicated status page

## Summary

With proper API key configuration, SafeScan provides enterprise-grade security using multiple threat intelligence sources. Start with free tiers and upgrade as needed based on usage patterns.
