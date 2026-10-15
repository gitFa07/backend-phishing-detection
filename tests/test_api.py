"""HTTP-level tests. They need FastAPI's test client (``pip install httpx``) and are skipped otherwise."""
import unittest

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except Exception:  # fastapi / httpx not installed
    HAVE_FASTAPI = False

from src.config import Settings

ORIGIN = "http://127.0.0.1:5500"


class FakeModel:
    explainer_loaded = True

    def __init__(self):
        self.calls = []

    def predict(self, url, explain=True):
        self.calls.append((url, explain))
        return {
            "url": url,
            "prediction": "Legitimate",
            "phishing_probability": 0.1,
            "legitimate_probability": 0.9,
            "features": {"url_length": len(url)},
            "contributions": {"url_length": -0.05} if explain else None,
            "explanation": {"method": "shap_tree", "top_factors": []} if explain else None,
        }


def make_client(**overrides):
    from src.app import create_app
    model = FakeModel()
    settings = Settings(**{"rate_limit_per_minute": 1000, **overrides})
    return TestClient(create_app(settings, model=model)), model


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def test_root_health_ready(self):
        client, _ = make_client()
        self.assertEqual(client.get("/").json(), {"message": "Phishing Detection API is running"})
        self.assertEqual(client.get("/health").json(), {"status": "ok"})
        ready = client.get("/ready").json()
        self.assertEqual((ready["status"], ready["model_loaded"], ready["explainer_loaded"]), ("ready", True, True))

    def test_predict_returns_prediction_explanation_and_signals(self):
        client, model = make_client()
        r = client.post("/predict", json={"url": "  https://paypal-login.top/verify  "})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "https://paypal-login.top/verify")  # trimmed, nothing else
        self.assertEqual(body["prediction"], "Legitimate")
        self.assertIn("contributions", body)
        self.assertFalse(body["signals"]["deep_scan"])
        self.assertIn("brand_impersonation", [f["code"] for f in body["signals"]["flags"]])
        self.assertEqual(body["request_id"], r.headers["x-request-id"])
        self.assertEqual(model.calls, [("https://paypal-login.top/verify", True)])

    def test_explain_false(self):
        client, model = make_client()
        body = client.post("/predict", json={"url": "https://example.com", "explain": False}).json()
        self.assertIsNone(body["explanation"])
        self.assertEqual(model.calls[-1][1], False)

    def test_old_request_shape_still_works(self):
        client, _ = make_client()
        self.assertEqual(client.post("/predict", json={"url": "https://example.com"}).status_code, 200)

    def test_invalid_urls_get_a_readable_422(self):
        client, model = make_client()
        for url in ("example.com", "ftp://example.com", "http://localhost/", "http://exa mple.com", ""):
            with self.subTest(url=url):
                r = client.post("/predict", json={"url": url})
                self.assertEqual(r.status_code, 422)
                self.assertIsInstance(r.json()["detail"], str)
        self.assertEqual(model.calls, [])

    def test_malformed_bodies_get_a_string_detail(self):
        client, _ = make_client()
        for payload in ({}, {"url": 123}, {"url": None}):
            with self.subTest(payload=payload):
                r = client.post("/predict", json=payload)
                self.assertEqual(r.status_code, 422)
                self.assertIsInstance(r.json()["detail"], str)

    def test_request_id_is_echoed_when_safe_and_replaced_when_not(self):
        client, _ = make_client()
        ok = client.get("/health", headers={"X-Request-ID": "abc-123"})
        self.assertEqual(ok.headers["x-request-id"], "abc-123")
        bad = client.get("/health", headers={"X-Request-ID": "bad id with spaces"})
        self.assertNotEqual(bad.headers["x-request-id"], "bad id with spaces")

    def test_rate_limit(self):
        client, _ = make_client(rate_limit_per_minute=2)
        codes = [client.post("/predict", json={"url": "https://example.com"}).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        r = client.post("/predict", json={"url": "https://example.com"})
        self.assertGreaterEqual(int(r.headers["retry-after"]), 1)
        self.assertIn("Try again", r.json()["detail"])
        self.assertEqual(client.get("/health").status_code, 200)  # health checks are never limited

    def test_rate_limit_counts_invalid_requests_too(self):
        client, _ = make_client(rate_limit_per_minute=1)
        self.assertEqual(client.post("/predict", json={"url": "nope"}).status_code, 422)
        self.assertEqual(client.post("/predict", json={"url": "https://example.com"}).status_code, 429)

    def test_forwarded_for_only_trusted_when_configured(self):
        client, _ = make_client(rate_limit_per_minute=1, trusted_proxy_count=1)
        post = lambda ip: client.post("/predict", json={"url": "https://example.com"},
                                      headers={"X-Forwarded-For": f"6.6.6.6, {ip}"}).status_code
        self.assertEqual([post("1.1.1.1"), post("1.1.1.1"), post("2.2.2.2")], [200, 429, 200])

        spoofed, _ = make_client(rate_limit_per_minute=1, trusted_proxy_count=0)
        post2 = lambda ip: spoofed.post("/predict", json={"url": "https://example.com"},
                                        headers={"X-Forwarded-For": ip}).status_code
        self.assertEqual([post2("1.1.1.1"), post2("2.2.2.2")], [200, 429])  # header ignored -> same client

    def test_cors_allows_only_configured_origins(self):
        client, _ = make_client(cors_allow_origins=(ORIGIN,))
        ok = client.get("/health", headers={"Origin": ORIGIN})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), ORIGIN)
        other = client.get("/health", headers={"Origin": "https://evil.example"})
        self.assertIsNone(other.headers.get("access-control-allow-origin"))

    def test_cors_preflight(self):
        client, _ = make_client(cors_allow_origins=(ORIGIN,))
        r = client.options("/predict", headers={
            "Origin": ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["access-control-allow-origin"], ORIGIN)
        bad = client.options("/predict", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertEqual(bad.status_code, 400)

    def test_error_responses_still_carry_cors_headers(self):
        client, _ = make_client(cors_allow_origins=(ORIGIN,), rate_limit_per_minute=1)
        client.post("/predict", json={"url": "https://example.com"}, headers={"Origin": ORIGIN})
        r = client.post("/predict", json={"url": "https://example.com"}, headers={"Origin": ORIGIN})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.headers.get("access-control-allow-origin"), ORIGIN)

    def test_oversized_body_is_rejected(self):
        client, model = make_client(max_request_body_bytes=1024)
        r = client.post("/predict", json={"url": "https://example.com/" + "a" * 2000})
        self.assertEqual(r.status_code, 413)
        self.assertEqual(model.calls, [])

    def test_deep_scan_disabled_degrades_gracefully(self):
        client, _ = make_client(enable_deep_scan=False)
        body = client.post("/predict", json={"url": "https://example.com", "deep_scan": True}).json()
        self.assertFalse(body["signals"]["deep_scan"])
        self.assertIn("disabled", body["signals"]["deep_scan_note"])

    def test_deep_scan_has_its_own_stricter_limit(self):
        from unittest import mock
        client, _ = make_client(deep_scan_rate_limit_per_minute=1)
        fake = {"deep_scan": True, "domain_reputation": {}, "dns": None, "certificate": None,
                "domain_age": None, "safe_browsing": None, "content": None, "flags": []}
        with mock.patch("src.app.collect_signals", return_value=fake) as collect:
            codes = [client.post("/predict", json={"url": "https://example.com", "deep_scan": True}).status_code
                     for _ in range(2)]
            plain = client.post("/predict", json={"url": "https://example.com"}).status_code
        self.assertEqual(codes, [200, 429])
        self.assertEqual(plain, 200)
        self.assertEqual(collect.call_count, 2)  # the limited request never reached the scanner

    def test_unhandled_errors_return_json_500_with_request_id(self):
        from unittest import mock
        client, model = make_client()
        with mock.patch.object(model, "predict", side_effect=RuntimeError("kaboom")):
            r = client.post("/predict", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json()["detail"], "Internal server error.")
        self.assertNotIn("kaboom", r.text)


if __name__ == "__main__":
    unittest.main()
