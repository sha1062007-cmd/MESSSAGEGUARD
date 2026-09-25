import json
import pickle
import numpy as np
import xgboost as xgb
import onnxruntime as ort
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from pathlib import Path

BASE_DIR = Path(r"c:\POC2\incoming_models\mlzip\ml\models")
BEC_DIR = BASE_DIR / "bec_detector"
URL_DIR = BASE_DIR / "url_detector"

print("--- 1. Converting BEC XGBoost to ONNX ---")
with open(BEC_DIR / "model_meta.json", "r") as f:
    bec_meta = json.load(f)
with open(BEC_DIR / "scaler.pkl", "rb") as f:
    bec_scaler = pickle.load(f)

bec_booster = xgb.Booster()
bec_booster.load_model(str(BEC_DIR / "xgb_bec_detector.json"))

# Convert using onnxmltools
initial_type = [('float_input', FloatTensorType([None, 21]))]
bec_onnx = onnxmltools.convert_xgboost(bec_booster, initial_types=initial_type, target_opset=12)
onnx_bec_path = BEC_DIR / "xgb_bec_detector.onnx"
with open(onnx_bec_path, "wb") as f:
    f.write(bec_onnx.SerializeToString())
print(f"Saved BEC ONNX to {onnx_bec_path}")

np.random.seed(42)
raw_bec_samples = np.random.uniform(0, 10, size=(5, 21)).astype(np.float32)
scaled_bec_samples = bec_scaler.transform(raw_bec_samples).astype(np.float32)

dmat_bec = xgb.DMatrix(scaled_bec_samples)
xgb_bec_preds = bec_booster.predict(dmat_bec)

sess_bec = ort.InferenceSession(str(onnx_bec_path))
input_name_bec = sess_bec.get_inputs()[0].name
onnx_bec_raw = sess_bec.run(None, {input_name_bec: scaled_bec_samples})

onnx_bec_probs = onnx_bec_raw[1]
if isinstance(onnx_bec_probs, list) and isinstance(onnx_bec_probs[0], dict):
    onnx_bec_probs = np.array([p[1] for p in onnx_bec_probs])
elif isinstance(onnx_bec_probs, np.ndarray) and onnx_bec_probs.ndim == 2:
    onnx_bec_probs = onnx_bec_probs[:, 1]

print("BEC Comparison (XGBoost vs ONNX):")
for i in range(len(xgb_bec_preds)):
    print(f"Sample {i+1}: XGBoost = {xgb_bec_preds[i]:.6f}, ONNX = {onnx_bec_probs[i]:.6f}, Diff = {abs(xgb_bec_preds[i] - onnx_bec_probs[i]):.6e}")

print("\n--- 2. Converting URL XGBoost to ONNX ---")
with open(URL_DIR / "model_meta.json", "r") as f:
    url_meta = json.load(f)
with open(URL_DIR / "scaler.pkl", "rb") as f:
    url_scaler = pickle.load(f)

url_booster = xgb.Booster()
url_booster.load_model(str(URL_DIR / "xgb_url_detector.json"))

# Reset booster feature names to f0, f1, ..., f52 so onnxmltools can map them
url_booster.feature_names = [f"f{i}" for i in range(53)]

initial_type_url = [('float_input', FloatTensorType([None, 53]))]
url_onnx = onnxmltools.convert_xgboost(url_booster, initial_types=initial_type_url, target_opset=12)
onnx_url_path = URL_DIR / "xgb_url_detector.onnx"
with open(onnx_url_path, "wb") as f:
    f.write(url_onnx.SerializeToString())
print(f"Saved URL ONNX to {onnx_url_path}")

raw_url_samples = np.random.uniform(0, 10, size=(5, 53)).astype(np.float32)
scaled_url_samples = url_scaler.transform(raw_url_samples).astype(np.float32)

dmat_url = xgb.DMatrix(scaled_url_samples, feature_names=[f"f{i}" for i in range(53)])
xgb_url_preds = url_booster.predict(dmat_url)

sess_url = ort.InferenceSession(str(onnx_url_path))
input_name_url = sess_url.get_inputs()[0].name
onnx_url_raw = sess_url.run(None, {input_name_url: scaled_url_samples})
onnx_url_probs = onnx_url_raw[1]
if isinstance(onnx_url_probs, list) and isinstance(onnx_url_probs[0], dict):
    onnx_url_probs = np.array([p[1] for p in onnx_url_probs])
elif isinstance(onnx_url_probs, np.ndarray) and onnx_url_probs.ndim == 2:
    onnx_url_probs = onnx_url_probs[:, 1]

print("URL Comparison (XGBoost vs ONNX):")
for i in range(len(xgb_url_preds)):
    print(f"Sample {i+1}: XGBoost = {xgb_url_preds[i]:.6f}, ONNX = {onnx_url_probs[i]:.6f}, Diff = {abs(xgb_url_preds[i] - onnx_url_probs[i]):.6e}")
