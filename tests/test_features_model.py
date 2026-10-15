import unittest
import warnings

import numpy as np

from src.explain import build_explanation, phishing_base_value, phishing_contributions
from src.features import extract_url_features
from src.model import MODELS_DIR, PhishingModel

N = 14
NAMES = [f"f{i}" for i in range(N)]


class FeatureTests(unittest.TestCase):
    def test_readme_example_is_stable(self):
        # Guards against accidental changes: the model was trained on exactly these numbers.
        self.assertEqual(extract_url_features("https://example.com/login"), {
            "url_length": 25, "hostname_length": 11, "path_length": 6, "num_dots": 1,
            "num_hyphens": 0, "num_slashes": 3, "num_digits": 0, "num_special_chars": 5,
            "has_https": 1, "has_at_symbol": 0, "has_query": 0, "has_ip": 0,
            "num_subdomains": 0, "has_suspicious_keyword": 1,
        })

    def test_ip_and_subdomains(self):
        f = extract_url_features("http://192.168.4.20/secure/login/verify-account.php")
        self.assertEqual((f["has_ip"], f["has_https"]), (1, 0))
        self.assertEqual(extract_url_features("https://a.b.c.example.com/")["num_subdomains"], 3)


class ShapShapeTests(unittest.TestCase):
    def setUp(self):
        self.v = np.linspace(-0.1, 0.1, N)

    def test_all_known_layouts_give_same_vector(self):
        zeros = np.zeros((1, N))
        layouts = {
            "list_of_classes": [zeros, self.v.reshape(1, N)],
            "samples_features_classes": np.stack([np.zeros((1, N)), self.v.reshape(1, N)], axis=-1),
            "classes_samples_features": np.stack([zeros, self.v.reshape(1, N)], axis=0),
            "single_output": self.v.reshape(1, N),
        }
        for name, raw in layouts.items():
            with self.subTest(layout=name):
                np.testing.assert_allclose(phishing_contributions(raw, N), self.v)

    def test_unexpected_shapes_raise(self):
        for raw in (np.zeros((3, N)), np.zeros((1, 5, 2)), [np.zeros((1, N))]):
            with self.subTest(shape=getattr(raw, "shape", len(raw))):
                with self.assertRaises(ValueError):
                    phishing_contributions(raw, N)

    def test_base_value_variants(self):
        self.assertEqual(phishing_base_value([0.4, 0.6]), 0.6)
        self.assertEqual(phishing_base_value(np.array([0.4, 0.6])), 0.6)
        self.assertEqual(phishing_base_value(0.5), 0.5)
        self.assertIsNone(phishing_base_value(None))

    def test_build_explanation_orders_and_labels(self):
        contributions = np.zeros(N)
        contributions[3], contributions[7], contributions[1] = 0.30, -0.45, 0.05
        by_feature, expl = build_explanation(NAMES, {n: i for i, n in enumerate(NAMES)}, contributions, 0.4, top_k=2)
        self.assertEqual([t["feature"] for t in expl["top_factors"]], ["f7", "f3"])
        self.assertEqual(expl["top_factors"][0]["direction"], "toward_legitimate")
        self.assertEqual(expl["top_factors"][1]["direction"], "toward_phishing")
        self.assertEqual(expl["top_factors"][0]["value"], 7)
        self.assertAlmostEqual(expl["output_value"], 0.4 + 0.30 - 0.45 + 0.05)
        self.assertEqual(len(by_feature), N)

    def test_zero_contributions_are_not_listed(self):
        _, expl = build_explanation(NAMES, {}, np.zeros(N), 0.5)
        self.assertEqual(expl["top_factors"], [])


class FakeSkModel:
    def __init__(self, p_phish):
        self.p = p_phish

    def predict(self, X):
        return np.array([1 if self.p >= 0.5 else 0])

    def predict_proba(self, X):
        return np.array([[1 - self.p, self.p]])


class FakeExplainer:
    def __init__(self, raw, expected):
        self._raw, self.expected_value = raw, expected

    def shap_values(self, X, check_additivity=True):
        self.last_X = X
        return self._raw


def _columns():
    return list(extract_url_features("https://example.com").keys())


class PredictWithExplanationTests(unittest.TestCase):
    def test_contributions_reach_the_response(self):
        cols = _columns()
        v = np.zeros(len(cols))
        v[cols.index("has_suspicious_keyword")] = 0.30
        v[cols.index("has_https")] = -0.10
        raw = np.stack([-v.reshape(1, -1), v.reshape(1, -1)], axis=-1)
        model = PhishingModel(FakeSkModel(0.6), cols, FakeExplainer(raw, [0.5, 0.4]))

        result = model.predict("https://example.com/login")
        self.assertEqual(result["prediction"], "Phishing")
        self.assertAlmostEqual(result["contributions"]["has_suspicious_keyword"], 0.30)
        top = result["explanation"]["top_factors"]
        self.assertEqual(top[0]["feature"], "has_suspicious_keyword")
        self.assertEqual(top[0]["value"], 1)
        self.assertAlmostEqual(result["explanation"]["output_value"], 0.6)
        self.assertEqual(list(model.explainer.last_X.columns), cols)

    def test_explain_false_skips_shap(self):
        model = PhishingModel(FakeSkModel(0.2), _columns(), FakeExplainer(None, 0.1))
        result = model.predict("https://example.com", explain=False)
        self.assertIsNone(result["contributions"])
        self.assertIsNone(result["explanation"])
        self.assertFalse(hasattr(model.explainer, "last_X"))

    def test_explainer_failure_does_not_break_prediction(self):
        class Broken:
            def shap_values(self, X, **kw):
                raise RuntimeError("boom")

        model = PhishingModel(FakeSkModel(0.9), _columns(), Broken())
        with self.assertLogs("phishing_api.model", level="ERROR"):
            result = model.predict("https://example.com/login")
        self.assertEqual(result["prediction"], "Phishing")
        self.assertIsNone(result["explanation"])

    def test_no_explainer_still_predicts(self):
        result = PhishingModel(FakeSkModel(0.1), _columns(), None).predict("https://example.com")
        self.assertEqual(result["prediction"], "Legitimate")
        self.assertIsNone(result["explanation"])


class RealArtifactTests(unittest.TestCase):
    """Uses the model files that ship in models/."""

    @classmethod
    def setUpClass(cls):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cls.model = PhishingModel.load(MODELS_DIR, load_explainer=False)

    def test_feature_columns_match_extractor(self):
        self.assertEqual(sorted(self.model.feature_columns), sorted(extract_url_features("https://example.com")))

    def test_probabilities_are_consistent(self):
        for url in ("https://example.com", "http://192.168.4.20/secure/login/verify-account.php"):
            with self.subTest(url=url):
                r = self.model.predict(url, explain=False)
                self.assertAlmostEqual(r["phishing_probability"] + r["legitimate_probability"], 1.0, places=6)
                self.assertIn(r["prediction"], ("Phishing", "Legitimate"))
                self.assertEqual(set(r["features"]), set(self.model.feature_columns))

    def test_obvious_cases(self):
        self.assertEqual(self.model.predict("https://example.com", explain=False)["prediction"], "Legitimate")
        self.assertEqual(
            self.model.predict("http://192.168.4.20/secure/login/verify-account.php", explain=False)["prediction"],
            "Phishing",
        )

    def test_full_load_degrades_gracefully_without_shap(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with self.assertLogs("phishing_api.model", level="WARNING") if _no_shap() else _null():
                model = PhishingModel.load(MODELS_DIR, load_explainer=True)
        result = model.predict("https://example.com/login")
        if model.explainer_loaded:
            self.assertIsNotNone(result["explanation"])
            # SHAP is additive: baseline + contributions should land near the model's probability.
            self.assertAlmostEqual(result["explanation"]["output_value"], result["phishing_probability"], delta=0.05)
        else:
            self.assertIsNone(result["explanation"])


def _no_shap():
    try:
        import shap  # noqa: F401
        return False
    except ImportError:
        return True


class _null:
    def __enter__(self):
        return None

    def __exit__(self, *a):
        return False


if __name__ == "__main__":
    unittest.main()
