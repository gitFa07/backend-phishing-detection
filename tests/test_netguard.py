import socket
import unittest
from unittest import mock

from src.signals import netguard
from src.signals.netguard import (
    BlockedTargetError, FetchError, NetworkPolicy, assert_public, fetch_page, is_public_address,
)
from tests.helpers import LocalServer

PUBLIC = ["93.184.216.34"]
HTML = b"<html><head><title>hi</title></head><body>ok</body></html>"


class PublicAddressTests(unittest.TestCase):
    def test_non_public_addresses(self):
        for addr in ("127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                     "0.0.0.0", "::1", "fe80::1", "fe80::1%eth0", "fc00::1", "::ffff:127.0.0.1",
                     "::ffff:10.0.0.1", "224.0.0.1", "255.255.255.255", "not-an-ip", ""):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_address(addr))

    def test_public_addresses(self):
        for addr in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"):
            with self.subTest(addr=addr):
                self.assertTrue(is_public_address(addr))

    def test_one_private_answer_blocks_everything(self):
        with self.assertRaises(BlockedTargetError):
            assert_public(["93.184.216.34", "10.0.0.5"], NetworkPolicy())
        with self.assertRaises(BlockedTargetError):
            assert_public([], NetworkPolicy())
        assert_public(["93.184.216.34"], NetworkPolicy())


class FetchTests(unittest.TestCase):
    """The server really runs on 127.0.0.1; ``open_pinned_socket`` is redirected to it
    while the resolver pretends the hostnames live at public / private addresses."""

    def setUp(self):
        self.connected = []
        self.resolver_table = {"good.test": PUBLIC, "internal.test": ["10.0.0.5"], "meta.test": ["169.254.169.254"]}
        self.server = None

    def resolver(self, host, port):
        if host not in self.resolver_table:
            raise socket.gaierror("nope")
        return list(self.resolver_table[host])

    def start(self, routes):
        self.server = LocalServer(routes)
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)

        def fake_open(addresses, port, timeout):
            self.connected.append((list(addresses), port))
            return socket.create_connection(("127.0.0.1", self.server.port), timeout=timeout)

        patcher = mock.patch.object(netguard, "open_pinned_socket", fake_open)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fetch(self, url, **policy):
        return fetch_page(url, NetworkPolicy(**policy), resolver=self.resolver)

    def test_happy_path_pins_the_checked_address(self):
        self.start({"/page": (200, {"Content-Type": "text/html"}, HTML)})
        page = self.fetch("http://good.test/page?x=1")
        self.assertEqual(page.body, HTML)
        self.assertEqual(page.status, 200)
        self.assertEqual(self.connected, [(PUBLIC, 80)])          # connected to the validated IP, not a fresh lookup
        self.assertEqual(self.server.seen[0]["host"], "good.test")  # but still addressed by hostname
        self.assertEqual(self.server.seen[0]["path"], "/page?x=1")
        self.assertIn("PhishingUrlScanner", self.server.seen[0]["ua"])

    def test_redirect_to_private_address_is_blocked_before_connecting(self):
        self.start({"/r": (302, {"Location": "http://internal.test/admin"}, b"")})
        with self.assertRaises(BlockedTargetError):
            self.fetch("http://good.test/r")
        self.assertEqual(len(self.connected), 1)  # only the first hop was ever contacted

    def test_cloud_metadata_address_is_blocked(self):
        self.start({})
        with self.assertRaises(BlockedTargetError):
            self.fetch("http://meta.test/latest/meta-data/")
        self.assertEqual(self.connected, [])

    def test_redirect_to_odd_scheme_or_port_is_blocked(self):
        for target in ("file:///etc/passwd", "gopher://good.test/x", "http://good.test:22/"):
            with self.subTest(target=target):
                self.connected.clear()
                self.start({"/r": (302, {"Location": target}, b"")})
                with self.assertRaises(BlockedTargetError):
                    self.fetch("http://good.test/r")

    def test_relative_redirect_is_followed(self):
        self.start({"/a": (301, {"Location": "/b"}, b""), "/b": (200, {"Content-Type": "text/html"}, HTML)})
        page = self.fetch("http://good.test/a")
        self.assertEqual(page.final_url, "http://good.test/b")
        self.assertEqual(page.redirect_chain, ["http://good.test/a"])

    def test_redirect_loop_is_cut_off(self):
        self.start({"/loop": (302, {"Location": "/loop"}, b"")})
        with self.assertRaisesRegex(FetchError, "Too many redirects"):
            self.fetch("http://good.test/loop", max_redirects=2)
        self.assertEqual(len(self.connected), 3)

    def test_body_is_capped(self):
        self.start({"/big": (200, {"Content-Type": "text/html"}, b"x" * 50_000)})
        page = self.fetch("http://good.test/big", max_bytes=1000)
        self.assertEqual(len(page.body), 1000)
        self.assertTrue(page.truncated)

    def test_small_body_is_not_marked_truncated(self):
        self.start({"/s": (200, {"Content-Type": "text/html"}, HTML)})
        self.assertFalse(self.fetch("http://good.test/s", max_bytes=1000).truncated)

    def test_unresolvable_host(self):
        self.start({})
        with self.assertRaises(FetchError):
            self.fetch("http://nonexistent.test/")

    def test_disallowed_port_and_scheme_on_first_request(self):
        self.start({})
        for url in ("http://good.test:8080/", "ftp://good.test/", "http:///nohost"):
            with self.subTest(url=url):
                with self.assertRaises(BlockedTargetError):
                    self.fetch(url)

    def test_connection_failure_is_a_fetch_error(self):
        self.start({})
        patcher = mock.patch.object(netguard, "open_pinned_socket", side_effect=ConnectionRefusedError())
        patcher.start()
        self.addCleanup(patcher.stop)
        with self.assertRaises(FetchError):
            self.fetch("http://good.test/")


class RealResolverTests(unittest.TestCase):
    def test_loopback_server_is_refused_by_default_policy(self):
        with LocalServer({"/": (200, {}, b"secret")}) as server:
            with self.assertRaises(BlockedTargetError):
                fetch_page(f"http://127.0.0.1:{server.port}/", NetworkPolicy(allowed_ports=(server.port,)))
            self.assertEqual(server.seen, [])  # nothing reached the server

    def test_loopback_works_only_when_explicitly_allowed(self):
        with LocalServer({"/": (200, {"Content-Type": "text/html"}, HTML)}) as server:
            policy = NetworkPolicy(allow_private=True, allowed_ports=(server.port,))
            self.assertEqual(fetch_page(f"http://127.0.0.1:{server.port}/", policy).body, HTML)

    def test_localhost_name_is_refused(self):
        with self.assertRaises(BlockedTargetError):
            fetch_page("http://localhost:80/", NetworkPolicy())


if __name__ == "__main__":
    unittest.main()
