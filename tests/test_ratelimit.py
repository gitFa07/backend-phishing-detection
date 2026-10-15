import unittest

from src.ratelimit import SlidingWindowRateLimiter, resolve_client_ip


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_and_recovers(self):
        clock = FakeClock()
        rl = SlidingWindowRateLimiter(3, window=60, clock=clock)
        self.assertEqual([rl.check("a")[0] for _ in range(3)], [True, True, True])
        allowed, retry = rl.check("a")
        self.assertFalse(allowed)
        self.assertAlmostEqual(retry, 60.0)
        clock.now += 30
        allowed, retry = rl.check("a")
        self.assertFalse(allowed)
        self.assertAlmostEqual(retry, 30.0)
        clock.now += 31
        self.assertTrue(rl.check("a")[0])

    def test_keys_are_independent(self):
        rl = SlidingWindowRateLimiter(1, clock=FakeClock())
        self.assertTrue(rl.check("a")[0])
        self.assertFalse(rl.check("a")[0])
        self.assertTrue(rl.check("b")[0])

    def test_zero_limit_disables(self):
        rl = SlidingWindowRateLimiter(0, clock=FakeClock())
        self.assertTrue(all(rl.check("a")[0] for _ in range(100)))

    def test_memory_is_bounded(self):
        rl = SlidingWindowRateLimiter(5, clock=FakeClock(), max_keys=50)
        for i in range(500):
            rl.check(f"ip-{i}")
        self.assertLessEqual(len(rl._hits), 50)


class ClientIpTests(unittest.TestCase):
    def test_header_ignored_without_trusted_proxy(self):
        self.assertEqual(resolve_client_ip("10.0.0.1", "6.6.6.6", 0), "10.0.0.1")

    def test_spoofed_leading_entries_are_ignored(self):
        self.assertEqual(resolve_client_ip("10.0.0.1", "6.6.6.6, 203.0.113.9", 1), "203.0.113.9")
        self.assertEqual(resolve_client_ip("10.0.0.1", "6.6.6.6, 203.0.113.9, 10.1.1.1", 2), "203.0.113.9")

    def test_falls_back_to_peer(self):
        self.assertEqual(resolve_client_ip("10.0.0.1", None, 1), "10.0.0.1")
        self.assertEqual(resolve_client_ip("10.0.0.1", "203.0.113.9", 2), "10.0.0.1")
        self.assertEqual(resolve_client_ip("10.0.0.1", "not-an-ip", 1), "10.0.0.1")
        self.assertEqual(resolve_client_ip(None, None, 0), "unknown")


if __name__ == "__main__":
    unittest.main()
