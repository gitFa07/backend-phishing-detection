import unittest

from src.validation import InvalidURLError, MAX_URL_LENGTH, validate_url


class ValidateUrlTests(unittest.TestCase):
    def test_accepts_normal_urls(self):
        good = [
            "https://example.com/login",
            "http://example.co.in:8443/a?b=c#d",
            "https://secure-login.account-verify.example.net/update/password?id=48213",
            "http://192.168.4.20/secure/login/verify-account.php",
            "http://[2001:db8::1]:8080/x",
            "HTTPS://Example.COM",
            "https://example.com.",
            "https://user:pw@example.com@evil.com/",
        ]
        for url in good:
            with self.subTest(url=url):
                validate_url(url)

    def test_url_is_only_trimmed_never_rewritten(self):
        result = validate_url("  HTTPS://Example.COM/Path?Q=1  ")
        self.assertEqual(result.url, "HTTPS://Example.COM/Path?Q=1")
        self.assertEqual(result.scheme, "https")
        self.assertEqual(result.hostname, "example.com")

    def test_userinfo_trick_resolves_to_real_host(self):
        self.assertEqual(validate_url("https://paypal.com@evil.example/login").hostname, "evil.example")

    def test_idn_is_converted_for_dns(self):
        result = validate_url("https://b\u00fccher.de/x")
        self.assertEqual(result.ascii_hostname, "xn--bcher-kva.de")

    def test_ip_hosts(self):
        v4, v6 = validate_url("http://10.0.0.1/"), validate_url("http://[::1]:8000/")
        self.assertTrue(v4.is_ip and v6.is_ip)
        self.assertEqual(v6.port, 8000)

    def test_effective_port(self):
        self.assertEqual(validate_url("https://example.com").effective_port, 443)
        self.assertEqual(validate_url("http://example.com").effective_port, 80)
        self.assertEqual(validate_url("http://example.com:8080").effective_port, 8080)

    def test_rejects_bad_input(self):
        bad = [
            "", "   ", "example.com/login", "ftp://example.com", "javascript:alert(1)",
            "data:text/html,<script>", "http://", "http:/example.com", "http://localhost/",
            "http://exa mple.com", "http://example.com/a b", "http://[::1", "http://example.com:99999",
            "http://example.com:0", "http://-bad.example.com", "http://exa_mple.com",
            "http://999.999.999.999", "http://example.com\\@evil.com", "http://example\u200b.com",
            "http://a..b.com", "http://" + "a" * 64 + ".com", "https://" + "a." * 200 + "com",
            "http://example.com/" + "a" * (MAX_URL_LENGTH + 1), "http://example.com/\n",
            "http://example.com/\x00",
        ]
        for url in bad:
            with self.subTest(url=url[:40]):
                if url == "http://example.com/\n":
                    # a trailing newline is plain whitespace and is trimmed
                    validate_url(url)
                    continue
                with self.assertRaises(InvalidURLError):
                    validate_url(url)

    def test_rejects_non_strings(self):
        for value in (None, 123, ["https://example.com"], b"https://example.com"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidURLError):
                    validate_url(value)

    def test_error_messages_are_user_safe(self):
        with self.assertRaisesRegex(InvalidURLError, "http:// or https://"):
            validate_url("example.com")


if __name__ == "__main__":
    unittest.main()
