import os
import numpy as np
import joblib
from thrember import PEFeatureExtractor


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "lightgbm_target95.pkl"
)

FEATURE_MASK_PATH = os.path.join(
    BASE_DIR,
    "feature_mask.npy"
)


# ---------------------------------------------------------
# Load model and feature mask
# ---------------------------------------------------------

_model = joblib.load(MODEL_PATH)
_feature_mask = np.load(FEATURE_MASK_PATH)

_extractor = PEFeatureExtractor()


# ---------------------------------------------------------
# Prediction function
# ---------------------------------------------------------

def predict_pe(file_path):
    """
    Analyze a Windows PE file and return malware prediction.

    Parameters
    ----------
    file_path : str
        Path to a PE file such as .exe or .dll

    Returns
    -------
    dict
        Prediction result containing:
        - prediction
        - malicious_probability
        - benign_probability
    """

    # Check file exists
    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    # Read PE file bytes
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # Extract official EMBER features
    features = _extractor.feature_vector(file_bytes)

    # Convert to numpy array
    X = np.asarray(
        features,
        dtype=np.float32
    ).reshape(1, -1)

    # Validate original feature count
    if X.shape[1] != 2568:
        raise ValueError(
            f"Expected 2568 features, "
            f"but received {X.shape[1]}"
        )

    # Apply the same feature mask used during training
    X = X[:, _feature_mask]

    # Validate selected feature count
    if X.shape[1] != 2528:
        raise ValueError(
            f"Expected 2528 selected features, "
            f"but received {X.shape[1]}"
        )

    # Predict probability
    probabilities = _model.predict_proba(X)[0]

    benign_probability = float(probabilities[0])
    malicious_probability = float(probabilities[1])

    # Classification threshold
    prediction = (
        "MALICIOUS"
        if malicious_probability >= 0.5
        else "BENIGN"
    )

    return {
        "prediction": prediction,
        "malicious_probability": malicious_probability,
        "benign_probability": benign_probability
    }


# ---------------------------------------------------------
# Command-line testing
# ---------------------------------------------------------

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:
        print(
            "Usage:\n"
            "python pe_predictor.py <path_to_pe_file>"
        )
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        result = predict_pe(file_path)

        print("=" * 60)
        print("Threat Vision - PE Malware Detection")
        print("=" * 60)

        print(
            f"Prediction            : "
            f"{result['prediction']}"
        )

        print(
            f"Malicious probability : "
            f"{result['malicious_probability'] * 100:.2f}%"
        )

        print(
            f"Benign probability    : "
            f"{result['benign_probability'] * 100:.2f}%"
        )

        print("=" * 60)

    except Exception as e:

        print(
            f"[ERROR] {type(e).__name__}: {e}"
        )

        sys.exit(1)