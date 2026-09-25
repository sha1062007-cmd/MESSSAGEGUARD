import numpy as np
import xgboost as xgb
import pickle
import time
from URLFeatureExtraction_v2 import AdvancedURLFeatureExtractor

class OptimizedPhishingPredictor:
    def __init__(self, model_path='XGBoostClassifier.pickle.dat'):
        self.extractor = AdvancedURLFeatureExtractor()
        self.model_path = model_path
        self.model = self._load_model()
        
    def _load_model(self):
        """Robust model loading with fallback."""
        try:
            with open(self.model_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Warning: Could not load primary model ({e}). Using Heuristic Fallback Engine.")
            return None

    def predict(self, url):
        start_time = time.time()
        
        # 1. Feature Extraction (V2)
        vector, feat_dict = self.extractor.extract_features(url)
        
        # 2. Heuristic Pre-Check (Super Fast)
        if feat_dict['is_suspicious_tld'] and feat_dict['has_ip']:
            return self._format_result(1.0, 1.0, "High Risk", "Suspicious TLD + IP Address", time.time() - start_time)
            
        # 3. Model Prediction
        if self.model:
            try:
                # Prepare input
                data = np.array([vector])
                
                # Check if it's a Booster or a Scikit-Learn wrapper
                if hasattr(self.model, 'predict_proba'):
                    prob = self.model.predict_proba(data)[0][1]
                else:
                    dmat = xgb.DMatrix(data)
                    prob = self.model.predict(dmat)[0]
                
                verdict = "Phishing" if prob > 0.5 else "Safe"
                confidence = prob if prob > 0.5 else 1 - prob
                
                return self._format_result(prob, confidence, verdict, "AI Model Scan", time.time() - start_time)
            except Exception as e:
                return self._format_result(0.5, 0.0, "Error", f"Prediction failed: {e}", time.time() - start_time)
        
        # 4. Fallback Heuristic Score (If model unavailable)
        heuristic_score = self._calculate_heuristic_score(feat_dict)
        verdict = "Suspicious" if heuristic_score > 0.6 else "Safe"
        return self._format_result(heuristic_score, heuristic_score, verdict, "Heuristic Engine (Fallback)", time.time() - start_time)

    def _calculate_heuristic_score(self, feats):
        score = 0
        if feats['is_suspicious_tld']: score += 0.4
        if feats['has_ip']: score += 0.5
        if feats['url_length'] > 75: score += 0.2
        if feats['digit_ratio'] > 0.3: score += 0.3
        if feats['domain_entropy'] > 4.0: score += 0.3
        if feats['has_brand_name'] and not feats['has_https']: score += 0.4
        return min(1.0, score)

    def _format_result(self, prob, conf, verdict, method, duration):
        return {
            "url": "",
            "verdict": verdict,
            "probability": f"{prob:.2%}",
            "confidence": f"{conf:.2%}",
            "method": method,
            "latency": f"{duration*1000:.2f}ms"
        }

if __name__ == "__main__":
    predictor = OptimizedPhishingPredictor()
    urls = [
        "https://www.google.com",
        "http://security-update-amazon.net.xyz/login.php?user=admin",
        "http://192.168.1.1/setup",
        "https://bit.ly/3xYzR2"
    ]
    
    print(f"{'URL':<60} | {'Verdict':<10} | {'Prob':<8} | {'Latency':<10}")
    print("-" * 95)
    for u in urls:
        res = predictor.predict(u)
        print(f"{u:<60} | {res['verdict']:<10} | {res['probability']:<8} | {res['latency']:<10}")
