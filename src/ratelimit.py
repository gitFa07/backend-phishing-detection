"""In-memory sliding-window rate limiting.

State lives in this process only. That is right for a single instance (the
usual free/cheap hosting tier); if you scale to several instances, move the
counters to Redis or rate-limit at the proxy instead.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from typing import Callable


class SlidingWindowRateLimiter:
    """Allow at most ``limit`` hits per ``window`` seconds for each key."""

    def __init__(
        self,
        limit: int,
        window: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        """Record a hit for ``key``. Returns ``(allowed, retry_after_seconds)``."""
        if self.limit <= 0:
            return True, 0.0
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(cutoff)
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False, max(hits[0] + self.window - now, 0.0)
            hits.append(now)
            return True, 0.0

    def _evict(self, cutoff: float) -> None:
        """Make room: drop idle keys first, then the oldest-created ones."""
        for k in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[k]
        while len(self._hits) >= self._max_keys:
            del self._hits[next(iter(self._hits))]


def resolve_client_ip(peer_host: str | None, forwarded_for: str | None, trusted_proxy_count: int) -> str:
    """Work out the real client address.

    ``X-Forwarded-For`` is a list that each proxy *appends* to, and clients can
    put anything at the start of it. With N trusted proxies in front of the
    app, only the Nth entry from the right was written by infrastructure we
    trust, so that is the one we use. With 0 trusted proxies the header is
    ignored entirely.
    """
    if trusted_proxy_count > 0 and forwarded_for:
        parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
        if len(parts) >= trusted_proxy_count:
            candidate = parts[-trusted_proxy_count]
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass  # garbage in the header: fall back to the socket peer
    return peer_host or "unknown"
