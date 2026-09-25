import re
import math
from urllib.parse import urlparse
import ipaddress

class AdvancedURLFeatureExtractor:
    def __init__(self):
        # List of suspicious TLDs
        self.suspicious_tlds = {
            'xyz', 'top', 'tk', 'zip', 'bit', 'click', 'gq', 'cyou', 'icu', 
            'cc', 'pw', 'ga', 'cf', 'ml', 'loan', 'men', 'win', 'bid', 'best'
        }
        
        # List of sensitive brand names frequently phished
        self.brands = {
            'google', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 
            'facebook', 'instagram', 'twitter', 'linkedin', 'bankofamerica', 
            'chase', 'wellsfargo', 'citibank', 'adobe', 'dropbox', 'github'
        }

    def get_entropy(self, text):
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def extract_features(self, url):
        """Extract ~30 features for improved accuracy."""
        features = {}
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except:
            return None

        # 1. Basic Lexical Features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        
        # 2. Count Features
        features['count_dots'] = url.count('.')
        features['count_hyphens'] = url.count('-')
        features['count_underscores'] = url.count('_')
        features['count_at'] = url.count('@')
        features['count_percent'] = url.count('%')
        features['count_query_marks'] = url.count('?')
        features['count_ampersand'] = url.count('&')
        features['count_equal'] = url.count('=')
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_letters'] = sum(c.isalpha() for c in url)
        features['count_subdomains'] = domain.count('.')
        
        # 3. Ratio Features
        features['digit_ratio'] = features['count_digits'] / (features['url_length'] + 1)
        features['letter_ratio'] = features['count_letters'] / (features['url_length'] + 1)
        
        # 4. Binary Features
        features['has_ip'] = 1 if self._is_ip(domain) else 0
        features['has_at'] = 1 if '@' in url else 0
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_tinyurl'] = 1 if self._is_shortened(url) else 0
        features['has_prefix_suffix'] = 1 if '-' in domain else 0
        features['has_punycode'] = 1 if 'xn--' in domain else 0
        
        # 5. Advanced Lexical Features
        features['url_entropy'] = self.get_entropy(url)
        features['domain_entropy'] = self.get_entropy(domain)
        
        # 6. Content/Brand Mimicry
        features['is_suspicious_tld'] = 1 if self._check_tld(domain) else 0
        features['has_brand_name'] = 1 if self._check_brands(url) else 0
        features['count_non_alphanumeric'] = sum(not c.isalnum() for c in url)
        
        # 7. Security Heuristics
        features['is_encoded'] = 1 if '%' in url else 0
        features['double_slash_redirection'] = 1 if url.rfind('//') > 7 else 0
        
        return list(features.values()), features

    def _is_ip(self, domain):
        try:
            ipaddress.ip_address(domain)
            return True
        except:
            return False

    def _is_shortened(self, url):
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                              r"bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com"
        return re.search(shortening_services, url) is not None

    def _check_tld(self, domain):
        tld = domain.split('.')[-1]
        return tld in self.suspicious_tlds

    def _check_brands(self, url):
        return any(brand in url.lower() for brand in self.brands)

if __name__ == "__main__":
    extractor = AdvancedURLFeatureExtractor()
    test_url = "https://secure-login-paypal.com.xyz/update?id=123"
    vector, feat_dict = extractor.extract_features(test_url)
    print("Extracted Features:")
    for k, v in feat_dict.items():
        print(f" - {k}: {v}")
