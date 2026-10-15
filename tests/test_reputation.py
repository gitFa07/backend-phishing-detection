import unittest
from datetime import datetime, timezone
from unittest import mock

import requests

from src.signals.reputation import check_domain_age, check_safe_browsing

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, status=200, payload=None, raises=False):
        self.status_code, self._payload, self._raises = status, payload, raises
        self.content = b"{}"

    def json(self):
        if self._raises:
            raise ValueError("bad json")
        return self._payload


def rdap(date):
    return FakeResponse(200, {"events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
                                         {"eventAction": "registration", "eventDate": date}]})


class DomainAgeTests(unittest.TestCase):
    def age(self, response, domain="example.com"):
        return check_domain_age(domain, 3, get=lambda *a, **k: response, now=NOW)

    def test_very_new_domain_is_high(self):
        block, flags = self.age(rdap("2026-10-12T10:00:00Z"))
        self.assertEqual(block["age_days"], 2)
        self.assertEqual([(f["code"], f["severity"]) for f in flags], [("domain_very_new", "high")])

    def test_new_domain_is_warning(self):
        _, flags = self.age(rdap("2026-09-25T00:00:00Z"))
        self.assertEqual([f["code"] for f in flags], ["domain_new"])

    def test_old_domain_has_no_flag(self):
        block, flags = self.age(rdap("1995-08-14T04:00:00Z"))
        self.assertEqual((block["status"], block["registered"], flags), ("ok", "1995-08-14", []))

    def test_missing_data_is_not_an_error(self):
        self.assertEqual(self.age(FakeResponse(404))[0]["status"], "unavailable")
        self.assertEqual(self.age(FakeResponse(200, {"events": []}))[0]["status"], "unavailable")

    def test_failures_become_error_status(self):
        def boom(*a, **k):
            raise requests.ConnectionError("down")
        self.assertEqual(check_domain_age("example.com", 3, get=boom, now=NOW)[0]["status"], "error")
        self.assertEqual(self.age(FakeResponse(500))[0]["status"], "error")
        self.assertEqual(self.age(FakeResponse(200, raises=True))[0]["status"], "error")
        self.assertEqual(self.age(rdap("not-a-date"))[0]["status"], "error")

    def test_rejects_weird_domain_strings(self):
        called = mock.Mock()
        block, _ = check_domain_age("exa mple.com/../x", 3, get=called, now=NOW)
        self.assertEqual(block["status"], "skipped")
        called.assert_not_called()


class SafeBrowsingTests(unittest.TestCase):
    def test_skipped_without_key(self):
        post = mock.Mock()
        block, flags = check_safe_browsing("https://example.com", None, 3, post=post)
        self.assertEqual((block["status"], flags), ("skipped", []))
        post.assert_not_called()

    def test_match_is_high(self):
        post = mock.Mock(return_value=FakeResponse(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}))
        block, flags = check_safe_browsing("https://bad.example", "K", 3, post=post)
        self.assertTrue(block["listed"])
        self.assertEqual(flags[0]["code"], "safe_browsing_match")
        self.assertEqual(flags[0]["severity"], "high")
        _, kwargs = post.call_args
        self.assertEqual(kwargs["params"], {"key": "K"})
        self.assertEqual(kwargs["json"]["threatInfo"]["threatEntries"], [{"url": "https://bad.example"}])

    def test_clean_url(self):
        block, flags = check_safe_browsing("https://ok.example", "K", 3, post=lambda *a, **k: FakeResponse(200, {}))
        self.assertEqual((block["listed"], flags), (False, []))

    def test_api_key_never_leaks_into_results(self):
        def boom(*a, **k):
            raise requests.ConnectionError("GET https://safebrowsing.googleapis.com/?key=SECRET123 failed")
        block, _ = check_safe_browsing("https://x.example", "SECRET123", 3, post=boom)
        self.assertEqual(block["status"], "error")
        self.assertNotIn("SECRET123", str(block))

    def test_http_error_status(self):
        block, _ = check_safe_browsing("https://x.example", "K", 3, post=lambda *a, **k: FakeResponse(403))
        self.assertEqual(block["status"], "error")
        self.assertIn("403", block["error"])


if __name__ == "__main__":
    unittest.main()
