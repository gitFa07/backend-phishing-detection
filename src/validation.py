"""URL validation.

``validate_url`` decides whether a string is a URL we are willing to score and
to (optionally) probe over the network. It deliberately does **not** rewrite
the URL beyond trimming surrounding whitespace: the model was trained on
features computed from the URL as written, so the scored string must stay
exactly what the caller sent.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# Control characters, format characters (zero-width spaces, bidi overrides...)
# and every kind of separator/space.
_FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Zs", "Zl", "Zp"}


class InvalidURLError(ValueError):
    """The submitted string is not an acceptable URL. ``str(e)`` is user-safe."""


@dataclass(frozen=True)
class ValidatedURL:
    url: str             # trimmed, otherwise exactly as submitted
    scheme: str          # "http" or "https"
    hostname: str        # as parsed (lower-case; may contain non-ASCII)
    ascii_hostname: str  # IDNA/punycode form, safe for DNS and sockets
    port: int | None
    is_ip: bool

    @property
    def effective_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _check_characters(url: str) -> None:
    for ch in url:
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise InvalidURLError("URL must not contain spaces or invisible/control characters.")
    if "\\" in url:
        # Browsers treat "\" as "/", most parsers do not; that mismatch is a
        # classic spoofing trick, so we refuse to guess.
        raise InvalidURLError("URL must not contain backslashes.")


def _check_hostname(hostname: str) -> str:
    """Validate a non-IP hostname and return its ASCII (IDNA) form."""
    host = hostname[:-1] if hostname.endswith(".") else hostname
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidURLError("Hostname is not a valid domain name.") from None

    if not ascii_host or len(ascii_host) > MAX_HOSTNAME_LENGTH:
        raise InvalidURLError("Hostname is empty or too long.")

    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise InvalidURLError(
            "Hostname must be a full domain name such as example.com (single-word hosts are not supported)."
        )
    if not all(_LABEL_RE.match(label) for label in labels):
        raise InvalidURLError("Hostname contains invalid characters or malformed parts.")
    if labels[-1].isdigit():
        raise InvalidURLError("Hostname looks like a malformed IP address.")
    return ascii_host


def validate_url(raw: object) -> ValidatedURL:
    """Validate ``raw`` and return its parsed parts, or raise InvalidURLError."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")

    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    _check_characters(url)

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise InvalidURLError("URL could not be parsed. Check the brackets, port and host.") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or url[len(scheme):len(scheme) + 3] != "://":
        raise InvalidURLError("URL must start with http:// or https://.")
    if not hostname:
        raise InvalidURLError("URL has no hostname.")
    if port == 0:
        raise InvalidURLError("URL has an invalid port.")

    if _is_ip(hostname):
        ascii_hostname, is_ip = hostname, True
    else:
        ascii_hostname, is_ip = _check_hostname(hostname), False

    return ValidatedURL(
        url=url,
        scheme=scheme,
        hostname=hostname,
        ascii_hostname=ascii_hostname,
        port=port,
        is_ip=is_ip,
    )
