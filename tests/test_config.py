import unittest

from src.config import DEFAULT_CORS_ORIGINS, load_settings


class ConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self):
        s = load_settings({})
        self.assertEqual(s.cors_allow_origins, DEFAULT_CORS_ORIGINS)
        self.assertNotIn("*", s.cors_allow_origins)
        self.assertEqual(s.trusted_proxy_count, 0)
        self.assertIsNone(s.safe_browsing_api_key)

    def test_parses_values(self):
        s = load_settings({
            "CORS_ALLOW_ORIGINS": " https://a.example/ , https://b.example ,, ",
            "RATE_LIMIT_PER_MINUTE": "5",
            "ENABLE_DEEP_SCAN": "false",
            "ENABLE_EXPLANATIONS": "0",
            "TRUSTED_PROXY_COUNT": "1",
            "LOG_level": "ignored",
            "LOG_LEVEL": "debug",
            "SAFE_BROWSING_API_KEY": "  key123 ",
            "DEEP_SCAN_TIMEOUT_SECONDS": "0.5",
        })
        self.assertEqual(s.cors_allow_origins, ("https://a.example", "https://b.example"))
        self.assertEqual(s.rate_limit_per_minute, 5)
        self.assertFalse(s.enable_deep_scan)
        self.assertFalse(s.enable_explanations)
        self.assertEqual(s.trusted_proxy_count, 1)
        self.assertEqual(s.log_level, "DEBUG")
        self.assertEqual(s.safe_browsing_api_key, "key123")
        self.assertEqual(s.deep_scan_timeout_seconds, 2.0)  # clamped to the minimum

    def test_bad_numbers_fail_fast(self):
        with self.assertRaisesRegex(ValueError, "RATE_LIMIT_PER_MINUTE"):
            load_settings({"RATE_LIMIT_PER_MINUTE": "lots"})

    def test_blank_values_fall_back_to_defaults(self):
        s = load_settings({"CORS_ALLOW_ORIGINS": "  ", "RATE_LIMIT_PER_MINUTE": ""})
        self.assertEqual(s.cors_allow_origins, DEFAULT_CORS_ORIGINS)
        self.assertEqual(s.rate_limit_per_minute, 30)


if __name__ == "__main__":
    unittest.main()
