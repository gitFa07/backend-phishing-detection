"""Safe outbound networking for the "deep scan".

The server fetches pages that *strangers* ask it to fetch, which is a classic
SSRF (server-side request forgery) risk. This module is where that risk is
handled, so everything that touches the network goes through it:

* every hostname is resolved first, and **all** resulting addresses must be
  public (no loopback, private, link-local, CGNAT, metadata endpoints...);
* the connection is then made to that already-checked IP address ("pinning"),
  so DNS cannot change its answer between the check and the connection;
* redirects are followed manually and each hop is checked the same way;
* only ports 80/443, a small response size, a short timeout and a redirect cap.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Callable, Sequence
from urllib.parse import urljoin, urlsplit

USER_AGENT = "PhishingUrlScanner/1.0 (security research; no cookies, no JavaScript)"


class BlockedTargetError(Exception):
    """The destination is not allowed (private address, odd port, bad scheme...)."""


class FetchError(Exception):
    """The page could not be fetched (network error, too many redirects...)."""


@dataclass(frozen=True)
class NetworkPolicy:
    allow_private: bool = False  # tests only: lets the code talk to 127.0.0.1
    allowed_ports: tuple[int, ...] = (80, 443)
    timeout: float = 4.0         # seconds, per socket operation
    max_bytes: int = 300_000     # response body cap
    max_redirects: int = 3
    total_deadline: float = 8.0  # seconds for one whole fetch


@dataclass
class FetchResult:
    final_url: str
    status: int
    content_type: str
    body: bytes
    truncated: bool
    redirect_chain: list[str]


def is_public_address(address: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
        ip = mapped
    return ip.is_global and not ip.is_multicast


def resolve_addresses(hostname: str, port: int) -> list[str]:
    """Resolve ``hostname`` to unique IP strings, IPv4 first. Raises socket.gaierror."""
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    seen.sort(key=lambda a: ":" in a)  # stable: IPv4 before IPv6
    return seen


def assert_public(addresses: Sequence[str], policy: NetworkPolicy) -> None:
    if not addresses:
        raise BlockedTargetError("Hostname did not resolve to any address.")
    if policy.allow_private:
        return
    if not all(is_public_address(a) for a in addresses):
        raise BlockedTargetError("Hostname resolves to a non-public address.")


def open_pinned_socket(addresses: Sequence[str], port: int, timeout: float) -> socket.socket:
    """Connect to the first reachable address in ``addresses`` (already validated)."""
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("no addresses to connect to")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, addresses: Sequence[str], timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._addresses = list(addresses)

    def connect(self) -> None:
        self.sock = open_pinned_socket(self._addresses, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, addresses: Sequence[str], timeout: float, ctx: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._addresses = list(addresses)
        self._tls_ctx = ctx

    def connect(self) -> None:
        raw = open_pinned_socket(self._addresses, self.port, self.timeout)
        try:
            # SNI + certificate checks use the hostname, the TCP connection uses the pinned IP.
            self.sock = self._tls_ctx.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _lenient_tls_context() -> ssl.SSLContext:
    # Deliberately does NOT verify certificates: when *analysing* a suspicious
    # site we still want to read its page even if its certificate is broken
    # (a broken certificate is itself a signal, reported by cert_check). No
    # cookies or credentials are ever sent, so nothing sensitive is exposed.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_page(
    url: str,
    policy: NetworkPolicy = NetworkPolicy(),
    resolver: Callable[[str, int], list[str]] = resolve_addresses,
) -> FetchResult:
    """GET ``url`` (following a few redirects) without ever touching a non-public address."""
    deadline = time.monotonic() + policy.total_deadline
    chain: list[str] = []
    current = url

    for _hop in range(policy.max_redirects + 1):
        try:
            parts = urlsplit(current)
            hostname = parts.hostname
            scheme = parts.scheme.lower()
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            raise BlockedTargetError("Redirect target is not a valid URL.") from None
        if scheme not in ("http", "https") or not hostname:
            raise BlockedTargetError("Only http and https URLs can be fetched.")
        if port not in policy.allowed_ports:
            raise BlockedTargetError(f"Port {port} is not allowed.")

        try:
            addresses = resolver(hostname, port)
        except OSError:
            raise FetchError("Hostname could not be resolved.") from None
        assert_public(addresses, policy)

        if scheme == "https":
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                hostname, port, addresses, policy.timeout, _lenient_tls_context()
            )
        else:
            conn = _PinnedHTTPConnection(hostname, port, addresses, policy.timeout)

        try:
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            conn.request("GET", path, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            resp = conn.getresponse()

            location = resp.getheader("Location")
            if resp.status in (301, 302, 303, 307, 308) and location:
                chain.append(current)
                current = urljoin(current, location)
                continue

            body = bytearray()
            limit = policy.max_bytes + 1
            while len(body) < limit and time.monotonic() < deadline:
                chunk = resp.read(min(8192, limit - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            truncated = len(body) > policy.max_bytes
            return FetchResult(
                final_url=current,
                status=resp.status,
                content_type=resp.getheader("Content-Type", "") or "",
                body=bytes(body[: policy.max_bytes]),
                truncated=truncated,
                redirect_chain=chain,
            )
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"Request failed ({type(exc).__name__}).") from None
        finally:
            conn.close()

    raise FetchError("Too many redirects.")
