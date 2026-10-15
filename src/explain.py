"""SHAP helpers: turn raw explainer output into a small, stable JSON structure.

Different ``shap`` versions return different shapes for a binary classifier:

* older releases: a list ``[class0_values, class1_values]``, each ``(n_samples, n_features)``
* newer releases: one array ``(n_samples, n_features, n_classes)``

``phishing_contributions`` normalises all of them to a 1-D array holding the
contribution of each feature toward the **phishing** class (class index 1).
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

import numpy as np

PHISHING_CLASS_INDEX = 1

# Plain-language names, kept in sync with the frontend's table.
FEATURE_LABELS: dict[str, str] = {
    "url_length": "URL length",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "num_dots": "Number of dots",
    "num_hyphens": "Number of hyphens",
    "num_slashes": "Number of slashes",
    "num_digits": "Number of digits",
    "num_special_chars": "Special characters",
    "has_https": "Uses HTTPS",
    "has_at_symbol": "Contains @",
    "has_query": "Has a query string",
    "has_ip": "Host is an IP address",
    "num_subdomains": "Number of subdomains",
    "has_suspicious_keyword": "Suspicious keyword",
}


def phishing_contributions(raw: Any, n_features: int) -> np.ndarray:
    """Return a 1-D array of length ``n_features`` (phishing-class SHAP values)."""
    if isinstance(raw, (list, tuple)):
        if len(raw) <= PHISHING_CLASS_INDEX:
            raise ValueError("SHAP output has no phishing-class entry.")
        arr = np.asarray(raw[PHISHING_CLASS_INDEX], dtype=float)
        if arr.ndim == 2 and arr.shape[0] == 1 and arr.shape[1] == n_features:
            return arr[0]
        if arr.ndim == 1 and arr.shape[0] == n_features:
            return arr
        raise ValueError(f"Unexpected SHAP list element shape {arr.shape}.")

    arr = np.asarray(raw, dtype=float)
    if arr.ndim == 3:
        if arr.shape[0] == 1 and arr.shape[1] == n_features and arr.shape[2] > PHISHING_CLASS_INDEX:
            return arr[0, :, PHISHING_CLASS_INDEX]  # (samples, features, classes)
        if arr.shape[1] == 1 and arr.shape[2] == n_features and arr.shape[0] > PHISHING_CLASS_INDEX:
            return arr[PHISHING_CLASS_INDEX, 0, :]  # (classes, samples, features)
    elif arr.ndim == 2 and arr.shape[0] == 1 and arr.shape[1] == n_features:
        return arr[0]  # single-output explainer
    elif arr.ndim == 1 and arr.shape[0] == n_features:
        return arr
    raise ValueError(f"Unexpected SHAP output shape {arr.shape}.")


def phishing_base_value(expected_value: Any) -> float | None:
    """Pick the phishing-class baseline out of ``explainer.expected_value``."""
    if expected_value is None:
        return None
    arr = np.asarray(expected_value, dtype=float).reshape(-1)
    if arr.size == 0:
        return None
    if arr.size > PHISHING_CLASS_INDEX:
        return float(arr[PHISHING_CLASS_INDEX])
    return float(arr[0])


def build_explanation(
    feature_names: Sequence[str],
    feature_values: Mapping[str, Any],
    contributions: np.ndarray,
    base_value: float | None,
    top_k: int = 5,
) -> tuple[dict[str, float], dict[str, Any]]:
    """Return ``(contributions_by_feature, explanation)``.

    ``explanation["base_value"] + sum(contributions)`` is the explainer's
    estimate of the phishing probability (that is what SHAP's additivity means
    for a random forest's probability output).
    """
    by_feature = {name: round(float(c), 6) for name, c in zip(feature_names, contributions)}

    ranked = sorted(by_feature.items(), key=lambda item: abs(item[1]), reverse=True)
    top_factors = [
        {
            "feature": name,
            "label": FEATURE_LABELS.get(name, name.replace("_", " ")),
            "value": feature_values.get(name),
            "contribution": c,
            "direction": "toward_phishing" if c > 0 else "toward_legitimate",
        }
        for name, c in ranked
        if abs(c) >= 1e-6
    ][:top_k]

    explanation: dict[str, Any] = {
        "method": "shap_tree",
        "target_class": "phishing",
        "base_value": None if base_value is None else round(base_value, 6),
        "output_value": None
        if base_value is None
        else round(base_value + float(np.sum(contributions)), 6),
        "top_factors": top_factors,
    }
    return by_feature, explanation
