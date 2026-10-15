"""Model loading and prediction (with optional SHAP explanation)."""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from .explain import build_explanation, phishing_base_value, phishing_contributions
from .features import extract_url_features

logger = logging.getLogger("phishing_api.model")

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "phishing_rf_model.joblib"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.joblib"
EXPLAINER_PATH = MODELS_DIR / "shap_explainer.joblib"

# If SHAP's reconstructed probability differs from the model's by more than
# this, the explainer probably was not built from this exact model file.
ADDITIVITY_WARN_THRESHOLD = 0.05


def _raw_shap_values(explainer: Any, X: pd.DataFrame) -> Any:
    """Call whichever SHAP API the pickled explainer offers."""
    if hasattr(explainer, "shap_values"):
        try:
            return explainer.shap_values(X, check_additivity=False)
        except TypeError:  # explainer type without that keyword
            return explainer.shap_values(X)
    return explainer(X).values  # new-style callable explainers


class PhishingModel:
    """Random Forest classifier plus (optionally) its SHAP explainer."""

    def __init__(self, model: Any, feature_columns: list[str], explainer: Any | None = None):
        self.model = model
        self.feature_columns = list(feature_columns)
        self.explainer = explainer

    @classmethod
    def load(
        cls,
        models_dir: Path = MODELS_DIR,
        load_explainer: bool = True,
    ) -> "PhishingModel":
        model = joblib.load(models_dir / MODEL_PATH.name)
        feature_columns = list(joblib.load(models_dir / FEATURE_COLUMNS_PATH.name))

        explainer = None
        if load_explainer:
            try:
                explainer = joblib.load(models_dir / EXPLAINER_PATH.name)
            except Exception:  # missing file, missing `shap` package, version mismatch...
                logger.warning(
                    "SHAP explainer could not be loaded; predictions will be returned "
                    "without explanations.",
                    exc_info=True,
                )
        return cls(model, feature_columns, explainer)

    @property
    def explainer_loaded(self) -> bool:
        return self.explainer is not None

    def predict(self, url: str, explain: bool = True) -> dict[str, Any]:
        """Score ``url``. ``url`` must already be validated (see validation.py)."""
        features = extract_url_features(url)

        # Make sure feature order matches training
        X = pd.DataFrame([features])[self.feature_columns]

        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        phishing_probability = float(probabilities[1])
        legitimate_probability = float(probabilities[0])

        result: dict[str, Any] = {
            "url": url,
            "prediction": "Phishing" if prediction == 1 else "Legitimate",
            "phishing_probability": phishing_probability,
            "legitimate_probability": legitimate_probability,
            "features": features,
            "contributions": None,
            "explanation": None,
        }

        if explain and self.explainer is not None:
            try:
                raw = _raw_shap_values(self.explainer, X)
                values = phishing_contributions(raw, len(self.feature_columns))
                base = phishing_base_value(getattr(self.explainer, "expected_value", None))
                contributions, explanation = build_explanation(
                    self.feature_columns, features, values, base
                )
                output = explanation["output_value"]
                if output is not None and abs(output - phishing_probability) > ADDITIVITY_WARN_THRESHOLD:
                    logger.warning(
                        "SHAP output (%.3f) does not match the model probability (%.3f); "
                        "is shap_explainer.joblib built from phishing_rf_model.joblib?",
                        output,
                        phishing_probability,
                    )
                result["contributions"] = contributions
                result["explanation"] = explanation
            except Exception:
                # An explanation failure must never break the prediction itself.
                logger.exception("SHAP explanation failed")

        return result


@lru_cache(maxsize=1)
def get_model() -> PhishingModel:
    """Process-wide model instance (loaded on first use)."""
    return PhishingModel.load()


def predict_url(url: str, explain: bool = True) -> dict[str, Any]:
    """Backwards-compatible helper: score a URL with the shared model."""
    return get_model().predict(url, explain=explain)
