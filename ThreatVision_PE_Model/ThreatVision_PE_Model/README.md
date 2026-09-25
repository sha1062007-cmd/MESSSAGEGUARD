*# Threat Vision - PE Malware Detection Model*



*## Purpose*



*This package contains the trained PE malware detection model used by Threat Vision.*



*The model performs static malware detection on Windows PE files without executing them.*



*Supported PE examples:*



*- .exe*

*- .dll*

*- .sys*



*---*



*## Model*



*Model file:*



*`lightgbm\_target95.pkl`*



*Feature mask:*



*`feature\_mask.npy`*



*The model was trained using EMBER2024 PE features.*



*Original feature count:*



*2568*



*Selected feature count:*



*2528*



*---*



*## Inference Pipeline*



*The required pipeline is:*



*PE file*

*→ read file bytes*

*→ EMBER2024 PEFeatureExtractor*

*→ 2568 features*

*→ feature\_mask.npy*

*→ 2528 features*

*→ LightGBM model*

*→ malware probability*

*→ BENIGN / MALICIOUS*



*Do not bypass the feature extraction step.*



*Do not pass arbitrary or manually created features to the model.*



*---*



*## Python Usage*



*```python*

*from pe\_predictor import predict\_pe*



*result = predict\_pe("sample.exe")*



*print(result)*

