"""Certificate inspection (HTTPS only)."""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Sequence

from .domains import flag
from .netguard import open_pinned_socket


def _rdn(parts: Any) -> dict[str, str]:
    """Flatten ssl.getpeercert()'s nested (('commonName', 'x'),) structure."""
    out: dict[str, str] = {}
    for rdn in parts or ():
        for key, value in rdn:
            out.setdefault(key, value)
    return out


def check_certificate(
    hostname: str,
    addresses: Sequence[str],
    port: int,
    timeout: float,
    context: ssl.SSLContext | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Validate the site's TLS certificate against the system trust store."""
    ctx = context or ssl.create_default_context()
    flags: list[dict[str, str]] = []
    try:
        raw = open_pinned_socket(addresses, port, timeout)
    except OSError:
        return {"status": "error", "error": "Could not connect to the HTTPS port."}, flags

    try:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            cert = tls.getpeercert() or {}
            protocol = tls.version()
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or "certificate verification failed"
        flags.append(flag("warning", "certificate_invalid", f"The HTTPS certificate is not trusted: {reason}."))
        return {"status": "ok", "valid": False, "error": reason, "verify_code": exc.verify_code}, flags
    except (ssl.SSLError, OSError, socket.timeout):
        return {"status": "error", "error": "TLS handshake failed."}, flags
    finally:
        raw.close()

    now = time.time()
    subject, issuer = _rdn(cert.get("subject")), _rdn(cert.get("issuer"))
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    not_before = ssl.cert_time_to_seconds(cert["notBefore"]) if cert.get("notBefore") else None
    not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if cert.get("notAfter") else None
    age_days = int((now - not_before) // 86400) if not_before else None
    days_left = int((not_after - now) // 86400) if not_after else None

    if age_days is not None and age_days <= 7:
        flags.append(flag(
            "info", "certificate_new",
            f"The certificate was issued only {max(age_days, 0)} day(s) ago. That is normal for new "
            "sites, and phishing sites are often new too.",
        ))

    return {
        "status": "ok",
        "valid": True,
        "protocol": protocol,
        "subject_common_name": subject.get("commonName"),
        "issuer_organization": issuer.get("organizationName") or issuer.get("commonName"),
        "alt_names": san[:10],
        "age_days": age_days,
        "days_until_expiry": days_left,
    }, flags
