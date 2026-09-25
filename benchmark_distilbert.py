import time
import os
import torch
from transformers import DistilBertForSequenceClassification, DistilBertTokenizer
from pathlib import Path

MODEL_DIR = Path(r"c:\POC2\incoming_models\mlzip\ml\models\email_nlp")
ONNX_PATH = MODEL_DIR / "distilbert_email.onnx"

print("--- 1. Measuring Original DistilBERT (PyTorch) ---")
tokenizer = DistilBertTokenizer.from_pretrained(str(MODEL_DIR))
model = DistilBertForSequenceClassification.from_pretrained(str(MODEL_DIR))
model.eval()

# Original safetensors file size
safetensors_size = (MODEL_DIR / "model.safetensors").stat().st_size / (1024 * 1024)
print(f"Original PyTorch safetensors size: {safetensors_size:.2f} MB")

# Test text
sample_texts = [
    "Urgent: Your account has been suspended. Please click here to verify your credentials immediately.",
    "Hey, let's meet up for lunch tomorrow around 1 PM at the cafeteria.",
    "Invoice #98234 attached. Please wire the payment to the updated account details ASAP.",
    "Your package delivery failed. Confirm your shipping address by entering your credit card details.",
    "Weekly project status update: Sprint 4 backlog refinement is completed."
]

inputs = tokenizer(sample_texts, padding=True, truncation=True, max_length=128, return_tensors="pt")

# Measure inference latency on CPU
with torch.no_grad():
    # Warmup
    for _ in range(3):
        _ = model(**inputs)
    t0 = time.time()
    iters = 10
    for _ in range(iters):
        orig_out = model(**inputs)
    t1 = time.time()
    orig_latency = (t1 - t0) / (iters * len(sample_texts)) * 1000
    orig_probs = torch.softmax(orig_out.logits, dim=-1).numpy()

print(f"Original PyTorch CPU Latency per sample: {orig_latency:.2f} ms")

print("\n--- 2. Exporting to ONNX ---")
dummy_input = (inputs["input_ids"], inputs["attention_mask"])
input_names = ["input_ids", "attention_mask"]
output_names = ["logits"]
dynamic_axes = {
    "input_ids": {0: "batch_size", 1: "seq_len"},
    "attention_mask": {0: "batch_size", 1: "seq_len"},
    "logits": {0: "batch_size"}
}

torch.onnx.export(
    model,
    dummy_input,
    str(ONNX_PATH),
    input_names=input_names,
    output_names=output_names,
    dynamic_axes=dynamic_axes,
    opset_version=14,
    do_constant_folding=True
)

onnx_size = ONNX_PATH.stat().st_size / (1024 * 1024)
print(f"Exported ONNX model size: {onnx_size:.2f} MB")

# ONNX INT8 Quantization
print("\n--- 3. Applying Dynamic INT8 Quantization via onnxruntime ---")
import onnxruntime as ort
from onnxruntime.quantization import quantize_dynamic, QuantType

QUANT_ONNX_PATH = MODEL_DIR / "distilbert_email_int8.onnx"
quantize_dynamic(
    model_input=str(ONNX_PATH),
    model_output=str(QUANT_ONNX_PATH),
    weight_type=QuantType.QInt8
)

quant_size = QUANT_ONNX_PATH.stat().st_size / (1024 * 1024)
print(f"Quantized INT8 ONNX model size: {quant_size:.2f} MB")

# Benchmark Quantized ONNX
sess = ort.InferenceSession(str(QUANT_ONNX_PATH), providers=["CPUExecutionProvider"])
ort_inputs = {
    "input_ids": inputs["input_ids"].numpy(),
    "attention_mask": inputs["attention_mask"].numpy()
}

# Warmup
for _ in range(3):
    _ = sess.run(None, ort_inputs)

t0 = time.time()
for _ in range(iters):
    ort_out = sess.run(None, ort_inputs)[0]
t1 = time.time()
quant_latency = (t1 - t0) / (iters * len(sample_texts)) * 1000

# Compute softmax on quantized logits
import numpy as np
def softmax(x):
    e_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return e_x / e_x.sum(axis=-1, keepdims=True)

quant_probs = softmax(ort_out)
print(f"Quantized INT8 ONNX CPU Latency per sample: {quant_latency:.2f} ms")

print("\n--- 4. Prediction / Accuracy Delta (PyTorch vs Quantized INT8) ---")
labels = ["legitimate", "phishing", "social_eng", "credential_theft", "financial_fraud"]
for i, text in enumerate(sample_texts):
    orig_top = np.argmax(orig_probs[i])
    quant_top = np.argmax(quant_probs[i])
    print(f"\nText {i+1}: {text[:65]}...")
    print(f"  PyTorch FP32 : Pred={labels[orig_top]} ({orig_probs[i][orig_top]*100:.1f}%), Top-3: {[f'{labels[k]}:{orig_probs[i][k]*100:.1f}%' for k in np.argsort(-orig_probs[i])[:3]]}")
    print(f"  INT8 ONNX    : Pred={labels[quant_top]} ({quant_probs[i][quant_top]*100:.1f}%), Top-3: {[f'{labels[k]}:{quant_probs[i][k]*100:.1f}%' for k in np.argsort(-quant_probs[i])[:3]]}")
    diff = np.max(np.abs(orig_probs[i] - quant_probs[i]))
    print(f"  Max Prob Delta: {diff:.4f}")
