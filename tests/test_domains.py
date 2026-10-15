import unittest

from src.signals.domains import (
    analyze_domain, brands_mentioned, detect_brand_impersonation, edit_distance, registered_domain,
)


def codes(host):
    _, flags = analyze_domain(host, host.encode("idna").decode("ascii"), False)
    return [f["code"] for f in flags]


class DomainTests(unittest.TestCase):
    def test_registered_domain(self):
        cases = {
            "www.example.com": "example.com", "example.com": "example.com",
            "a.b.example.co.in": "example.co.in", "incometax.gov.in": "incometax.gov.in",
            "login.example.co.uk": "example.co.uk", "localhost": "localhost", "example.com.": "example.com",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(registered_domain(host), expected)

    def test_edit_distance(self):
        self.assertEqual(edit_distance("paypal", "paypa1"), 1)
        self.assertEqual(edit_distance("", "abc"), 3)
        self.assertEqual(edit_distance("same", "same"), 0)

    def test_genuine_brand_domains_are_not_flagged(self):
        for host in ("paypal.com", "www.paypal.com", "amazon.in", "accounts.google.com", "login.hdfcbank.com",
                     "onlinesbi.sbi", "github.io", "incometax.gov.in"):
            with self.subTest(host=host):
                self.assertEqual(codes(host), [])

    def test_brand_in_hostname(self):
        for host in ("paypal-secure-login.com", "paypal.com.secure-login.xyz", "sbi-kyc-update.com",
                     "microsoft-support.online"):
            with self.subTest(host=host):
                self.assertIn("brand_impersonation", codes(host))

    def test_lookalike_spellings(self):
        for host in ("paypa1.com", "arnazon.in", "gooogle.com", "micros0ft.com", "amaz0n-deals.net"):
            with self.subTest(host=host):
                self.assertIn("lookalike_domain", codes(host))

    def test_unrelated_words_containing_a_brand_are_not_flagged(self):
        self.assertEqual(codes("applesauce.com"), [])
        self.assertEqual(codes("pineapplefarm.com"), [])

    def test_idn_and_mixed_scripts(self):
        self.assertIn("idn_homograph", codes("xn--pple-43d.com"))
        details, flags = analyze_domain("\u0430pple.com", "xn--pple-43d.com", False)  # Cyrillic 'a' + Latin
        self.assertTrue(details["mixed_scripts"])
        self.assertEqual(flags[0]["severity"], "high")
        self.assertNotIn("idn_homograph", codes("example.com"))

    def test_tld_and_shortener(self):
        self.assertIn("risky_tld", codes("example.top"))
        self.assertNotIn("risky_tld", codes("example.com"))
        self.assertIn("url_shortener", codes("bit.ly"))

    def test_ip_hosts_skip_domain_checks(self):
        details, flags = analyze_domain("192.168.1.1", "192.168.1.1", True)
        self.assertEqual(details["host_type"], "ip_address")
        self.assertEqual(flags, [])

    def test_brands_mentioned_in_text(self):
        self.assertEqual(brands_mentioned("PayPal - Log in to your account", "evil.example"), ["PayPal"])
        self.assertEqual(brands_mentioned("Sign in to Microsoft", "microsoft.com"), [])
        self.assertEqual(brands_mentioned("My apple pie blog", "evil.example"), ["Apple"])  # known false positive
        self.assertEqual(detect_brand_impersonation("example.com"), None)


if __name__ == "__main__":
    unittest.main()
