import socket
import ssl
import unittest
from unittest import mock

from src.signals import netguard
from src.signals.netguard import NetworkPolicy, fetch_page
from src.signals.tls import check_certificate
from tests.helpers import LocalServer, make_self_signed_cert, temp_dir

HTML = b"<html><title>tls page</title></html>"


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = temp_dir()
        cls.paths = make_self_signed_cert(cls._tmp.name)
        if cls.paths is None:
            raise unittest.SkipTest("openssl CLI not available")
        cls.server = LocalServer({"/": (200, {"Content-Type": "text/html"}, HTML)}, *cls.paths)
        cls.server.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)
        cls._tmp.cleanup()

    def test_untrusted_certificate_is_reported(self):
        block, flags = check_certificate("localhost", ["127.0.0.1"], self.server.port, 3)
        self.assertEqual(block["status"], "ok")
        self.assertFalse(block["valid"])
        self.assertIn("self", block["error"].lower())
        self.assertEqual([f["code"] for f in flags], ["certificate_invalid"])

    def test_trusted_certificate_details(self):
        ctx = ssl.create_default_context(cafile=self.paths[0])
        block, flags = check_certificate("localhost", ["127.0.0.1"], self.server.port, 3, context=ctx)
        self.assertTrue(block["valid"], block)
        self.assertEqual(block["subject_common_name"], "localhost")
        self.assertEqual(block["alt_names"], ["localhost"])
        self.assertTrue(block["protocol"].startswith("TLS"))
        self.assertIn(block["days_until_expiry"], (1, 2))
        self.assertEqual(block["age_days"], 0)
        self.assertEqual([f["code"] for f in flags], ["certificate_new"])

    def test_hostname_mismatch_is_reported(self):
        ctx = ssl.create_default_context(cafile=self.paths[0])
        block, flags = check_certificate("wrong-name.example", ["127.0.0.1"], self.server.port, 3, context=ctx)
        self.assertFalse(block["valid"])
        self.assertIn("mismatch", block["error"].lower())
        self.assertEqual(flags[0]["code"], "certificate_invalid")

    def test_connection_refused(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]
        block, flags = check_certificate("localhost", ["127.0.0.1"], closed_port, 2)
        self.assertEqual((block["status"], flags), ("error", []))

    def test_non_tls_server_is_a_handshake_error(self):
        with LocalServer({"/": (200, {}, b"plain")}) as plain:
            block, _ = check_certificate("localhost", ["127.0.0.1"], plain.port, 2)
        self.assertEqual(block["status"], "error")

    def test_content_fetch_reads_pages_with_broken_certificates(self):
        # Analysing a suspicious site must still work when its certificate is bad.
        def fake_open(addresses, port, timeout):
            return socket.create_connection(("127.0.0.1", self.server.port), timeout=timeout)

        with mock.patch.object(netguard, "open_pinned_socket", fake_open):
            page = fetch_page("https://good.test/", NetworkPolicy(), resolver=lambda h, p: ["93.184.216.34"])
        self.assertEqual(page.body, HTML)
        self.assertEqual(page.status, 200)


if __name__ == "__main__":
    unittest.main()
