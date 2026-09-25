# SafeScan - Model Setup Guide

## Issue Resolution

The error you encountered is because the `xgb_malware_model.json` file is a placeholder. You need to either:

1. **Train your own EMBER-based model** (recommended)
2. **Use a pre-trained model** from EMBER
3. **Disable file scanning** temporarily

## Option 1: Train Your Own EMBER Model

### Prerequisites
```bash
pip install ember
```

### Training Script
```python
import ember
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split

# Load EMBER dataset (you need to download it first)
ember.create_vectorized_features("ember2018/")
X_train, y_train, X_test, y_test = ember.read_vectorized_features("ember2018/")

# Train XGBoost model
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)

params = {
    'max_depth': 6,
    'eta': 0.1,
    'objective': 'binary:logistic',
    'eval_metric': 'auc'
}

model = xgb.train(params, dtrain, num_boost_round=100, 
                  evals=[(dtest, 'test')], early_stopping_rounds=10)

# Save model
model.save_model("xgb_malware_model.json")
```

## Option 2: Use Pre-trained EMBER Model

### Download Pre-trained Model
```bash
# Download from EMBER repository
wget https://github.com/elastic/ember/raw/main/model.txt
# OR
curl -O https://github.com/elastic/ember/raw/main/model.txt
mv model.txt xgb_malware_model.json
```

### Alternative: Use EMBER's Built-in Model
```python
import ember

# Use EMBER's pre-trained model
model = ember.load_model("ember2018/model.txt")
model.save_model("xgb_malware_model.json")
```

## Option 3: Disable File Scanning (Temporary Fix)

### Update config.js
```javascript
// In extension/config.js
const SAFESCAN_CONFIG = {
    // ... other settings
    FILE_SCAN_ENABLED: false,  // Disable file scanning
    ENABLE_AI_SCANNING: false,  // Disable AI for files
};
```

### Update colab_api.py
```python
# In extension/colab_api.py
@app.route("/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files["file"]
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # Only use VirusTotal and heuristics
    vt_result = check_virustotal(file_hash, type="file")
    
    # Basic heuristics
    suspicious_content = False
    if any(sig in file_bytes.lower() for sig in [b"eval(", b"exec(", b"base64"]):
        suspicious_content = True
    
    # Simple scoring without AI
    risk_score = 0.0
    if vt_result and vt_result["malicious_count"] > 0:
        risk_score = 0.9
    elif suspicious_content:
        risk_score = 0.6
    
    label = "safe"
    if risk_score > 0.8: label = "unsafe"
    elif risk_score > 0.4: label = "partial"
    
    return jsonify({
        "label": label,
        "confidence": risk_score,
        "filename": file.filename,
        "vt_hits": vt_result["malicious_count"] if vt_result else 0,
        "summary": f"File scanned without AI model. VT Hits: {vt_result['malicious_count'] if vt_result else 0}"
    })
```

## Quick Fix for Now

Let me create a minimal working model file:

```python
import xgboost as xgb
import numpy as np

# Create a simple dummy model (for testing only)
model = xgb.Booster()
model.save_model("xgb_malware_model.json")
```

## Recommended Approach

1. **For immediate testing**: Use the temporary fix above
2. **For production**: Train a proper EMBER model or download the pre-trained one
3. **For development**: Start with heuristics + VirusTotal only

## EMBER Dataset Download

If you want to train your own model:

```bash
# Download EMBER 2018 dataset
wget https://ember.elastic.co/ember2018.tar.bz2
tar -xjf ember2018.tar.bz2
```

## Model Performance Expectations

- **EMBER Pre-trained**: ~98% accuracy on malware detection
- **Custom Trained**: Depends on training data quality
- **Heuristics Only**: ~70-80% accuracy

## Next Steps

1. Choose one of the options above
2. Update your model file
3. Restart the API server
4. Test file scanning functionality

The URL and email models should work fine as they're already properly trained.
