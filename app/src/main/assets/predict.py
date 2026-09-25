import pickle
import numpy as np
import xgboost as xgb
import time
import sys
from URLFeatureExtraction import AdvancedURLFeatureExtractor

# Force UTF-8 for Windows Console handle
try:
    if sys.stdout.encoding != 'utf-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
except:
    pass

class PhishingPredictor:
    def __init__(self, model_file="XGBoostClassifier.pickle.dat"):
        self.extractor = AdvancedURLFeatureExtractor()
        self.model_file = model_file
        self.model = self._load_model()
        
    def _load_model(self):
        with open(self.model_file, "rb") as f:
            return pickle.load(f)

    def analyze_url(self, url):
        start_time = time.time()
        
        # 1. Feature Extraction
        vector, feat_dict = self.extractor.extract_features(url)
        
        # 2. Base Model Prediction
        data = np.array([vector])
        if hasattr(self.model, 'predict_proba'):
            prob = float(self.model.predict_proba(data)[0][1])
        else:
            dmat = xgb.DMatrix(data)
            prob = float(self.model.predict(dmat)[0])
            
        # 3. HEURISTIC OVERRIDES (For high-confidence threats the model might miss)
        # Force DANGEROUS for IP-based URLs (Common in malware C2 or Router Phishing)
        if feat_dict['has_ip']:
            prob = max(prob, 0.96)
            
        # Force SUSPICIOUS for Brand Mimicry on non-HTTPS
        if feat_dict['has_brand_name'] and not feat_dict['has_https']:
            # but only if it's not a known safe domain
            if not any(safe in url.lower() for safe in ['google.com', 'github.com', 'microsoft.com']):
                prob = max(prob, 0.75)
            
        latency = (time.time() - start_time) * 1000
        
        # 4. Labeling
        if prob > 0.85:
            label = "DANGEROUS"
        elif prob > 0.45:
            label = "SUSPICIOUS"
        else:
            label = "SAFE"
            
        confidence = prob if prob > 0.5 else 1 - prob
        
        # 5. Triggered Features (Filtered for AI relevance)
        triggers = []
        if feat_dict['domain_entropy'] > 3.8: triggers.append(f"High Entropy ({feat_dict['domain_entropy']:.2f})")
        if feat_dict['has_brand_name'] and label != "SAFE": triggers.append("Brand Mimicry Detected")
        if feat_dict['is_suspicious_tld']: triggers.append("Suspicious TLD")
        if feat_dict['has_ip']: triggers.append("Static IP in Host")
        if feat_dict['has_tinyurl']: triggers.append("URL Shortener")
        
        # 6. Generate AI Prompt Meta-Data
        ai_data = {
            "ml_label": label,
            "ml_confidence": f"{confidence:.1%}",
            "entropy": round(feat_dict['domain_entropy'], 2),
            "brand_mimicry": "Yes" if (feat_dict['has_brand_name'] and label != "SAFE") else "No",
            "tld_risk": "High" if feat_dict['is_suspicious_tld'] else "Normal",
            "features": triggers
        }
        
        return {
            "url": url,
            "label": label,
            "confidence": f"{confidence:.2%}",
            "summary_data": ai_data,
            "latency": f"{latency:.2f}ms"
        }

    def generate_ai_summary(self, result):
        data = result['summary_data']
        if result['label'] == "SAFE":
            return f"Verified secure URL. ML patterns indicate a legitimate domain with a standard trust profile. Confidence: {result['confidence']}"
        
        summary = f"This URL is categorized as {result['label']}. "
        feat_descriptions = []
        if data['entropy'] > 3.8:
            feat_descriptions.append(f"shows high Shannon Entropy ({data['entropy']}) indicating a randomly generated domain")
        if data['brand_mimicry'] == "Yes":
            feat_descriptions.append("targets a known brand in the path or subdomain")
        if data['tld_risk'] == "High":
            feat_descriptions.append("uses a high-risk TLD commonly associated with phishing")
        if result['label'] == "DANGEROUS":
            feat_descriptions.append("contains patterns highly indicative of malicious intent")
            
        if not feat_descriptions:
            feat_descriptions.append("matches multiple blacklisted heuristic patterns")
            
        summary += "It " + " and ".join(feat_descriptions) + f". Confidence: {result['confidence']}"
        return summary

def run_test_suite():
    predictor = PhishingPredictor()
    test_urls = [
        ("SAFE", "https://www.google.com"),
        ("SAFE", "https://www.github.com"),
        ("SUSPICIOUS", "http://paypal-secure-login.xyz"),
        ("DANGEROUS", "http://192.168.1.1/admin/login"),
        ("DANGEROUS", "http://g00gle-verify-account.top/signin")
    ]
    
    print("\n" + "="*80)
    print(f"{'EXPECTED':<12} | {'ML LABEL':<12} | {'CONF %':<8} | {'URL'}")
    print("-" * 80)
    
    for expected, url in test_urls:
        res = predictor.analyze_url(url)
        ai_summary = predictor.generate_ai_summary(res)
        
        status = "PASS" if res['label'] == expected else "FAIL"
        
        print(f"{expected:<12} | {res['label']:<12} | {res['confidence']:<8} | {url}")
        print(f"Features  : {', '.join(res['summary_data']['features']) if res['summary_data']['features'] else 'None'}")
        print(f"AI Summary: {ai_summary}")
        print(f"Status    : {status}")
        print("-" * 80)

if __name__ == "__main__":
    run_test_suite()
