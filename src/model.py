import joblib
import pandas as pd
from pathlib import Path

from .features import extract_url_features


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Model paths
MODEL_PATH = BASE_DIR / "models" / "phishing_rf_model.joblib"
FEATURE_COLUMNS_PATH = BASE_DIR / "models" / "feature_columns.joblib"



# Load saved artifacts
model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_COLUMNS_PATH)



def predict_url(url):
    """
    Extract features from a URL and return
    the model prediction and probabilities.
    """

    # Extract features
    features = extract_url_features(url)

    # Convert to DataFrame
    X = pd.DataFrame([features])

    # Make sure feature order matches training
    X = X[feature_columns]

    # Prediction
    prediction = model.predict(X)[0]

    # Probabilities
    probabilities = model.predict_proba(X)[0]

    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])

    # Label
    label = "Phishing" if prediction == 1 else "Legitimate"

    return {
        "url": url,
        "prediction": label,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "features": features,
    }