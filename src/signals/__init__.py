"""Extra evidence about a URL, reported alongside (never mixed into) the ML score.

The classifier only sees 14 lexical URL features. This package adds:

* offline domain heuristics (always on) - brand look-alikes, IDN tricks, risky TLDs;
* a "deep scan" (opt-in per request) that does DNS, TLS-certificate, domain-age,
  Safe Browsing and page-content checks over the network.

Signals are explanatory flags. They do **not** change the model's probability.
"""
from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..validation import ValidatedURL
from .content import analyze_page
from .domains import analyze_domain, flag, registered_domain
from .netguard import (
    BlockedTargetError,
    FetchError,
    NetworkPolicy,
    assert_public,
    fetch_page,
    resolve_addresses,
)
from .reputation import check_domain_age, check_safe_browsing
from .tls import check_certificate

_SEVERITY_ORDER = {"high": 0, "warning": 1, "info": 2}
_POOL: ThreadPoolExecutor | None = None


def _pool() -> ThreadPoolExecutor:
    """One small shared pool: bounds how many network probes run at once."""
    global _POOL
    if _POOL is None:
        _POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="deep-scan")
    return _POOL


@dataclass(frozen=True)
class SignalConfig:
    overall_timeout: float = 10.0
    request_timeout: float = 4.0
    policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    safe_browsing_api_key: str | None = None


def _await(future: Future, deadline: float) -> tuple[Any, str | None]:
    """Result of ``future`` or (None, 'timeout'/'error') once ``deadline`` passes."""
    done, _ = wait([future], timeout=max(deadline - time.monotonic(), 0))
    if not done:
        return None, "timeout"
    try:
        return future.result(), None
    except Exception as exc:  # keep one failing probe from sinking the others
        return exc, "error"


def _unavailable(reason: str, status: str = "skipped") -> dict[str, Any]:
    return {"status": status, "reason": reason}


def collect_signals(target: ValidatedURL, config: SignalConfig | None = None, deep_scan: bool = False) -> dict[str, Any]:
    config = config or SignalConfig()
    details, flags = analyze_domain(target.hostname, target.ascii_hostname, target.is_ip)
    out: dict[str, Any] = {
        "deep_scan": deep_scan,
        "domain_reputation": details,
        "dns": None,
        "certificate": None,
        "domain_age": None,
        "safe_browsing": None,
        "content": None,
        "flags": flags,
    }
    if not deep_scan:
        _finish(out)
        return out

    deadline = time.monotonic() + config.overall_timeout
    pool = _pool()
    port = target.effective_port
    reg = registered_domain(target.ascii_hostname)

    dns_f = pool.submit(resolve_addresses, target.ascii_hostname, port)
    age_f = None if target.is_ip else pool.submit(check_domain_age, reg, config.request_timeout)
    sb_f = pool.submit(check_safe_browsing, target.url, config.safe_browsing_api_key, config.request_timeout)

    # --- DNS -------------------------------------------------------------
    addresses, err = _await(dns_f, deadline)
    cert_f = content_f = None
    if err == "timeout":
        out["dns"] = {"status": "timeout"}
        reason = "DNS lookup timed out."
    elif err or not addresses:
        out["dns"] = {"status": "ok", "resolves": False}
        flags.append(flag("info", "dns_unresolved", "The domain does not resolve to an address (it may be offline or taken down)."))
        reason = "Domain does not resolve."
    else:
        try:
            assert_public(addresses, config.policy)
        except BlockedTargetError:
            out["dns"] = {"status": "ok", "resolves": True, "public": False}
            flags.append(flag("warning", "dns_non_public_address", "The domain points to a private or reserved address, so it was not contacted."))
            reason = "Domain points to a non-public address; not contacted."
        else:
            out["dns"] = {"status": "ok", "resolves": True, "public": True, "addresses": addresses[:5]}
            reason = ""
            if target.scheme == "https":
                cert_f = pool.submit(check_certificate, target.ascii_hostname, addresses, port, config.request_timeout)
            content_f = pool.submit(_fetch_and_analyze, target, config)

    # --- Collect everything else -----------------------------------------
    out["certificate"] = _unavailable(reason or "URL does not use HTTPS.") if cert_f is None else _collect(cert_f, deadline, flags)
    out["content"] = _unavailable(reason) if content_f is None else _collect(content_f, deadline, flags)
    out["domain_age"] = _unavailable("Host is an IP address.") if age_f is None else _collect(age_f, deadline, flags)
    out["safe_browsing"] = _collect(sb_f, deadline, flags)

    _finish(out)
    return out


def _collect(future: Future, deadline: float, flags: list[dict[str, str]]) -> dict[str, Any]:
    value, err = _await(future, deadline)
    if err == "timeout":
        return {"status": "timeout"}
    if err:
        return {"status": "error", "error": "Check failed unexpectedly."}
    block, new_flags = value
    flags.extend(new_flags)
    return block


def _fetch_and_analyze(target: ValidatedURL, config: SignalConfig) -> tuple[dict[str, Any], list[dict[str, str]]]:
    try:
        page = fetch_page(target.url, config.policy)
    except BlockedTargetError as exc:
        return {"status": "blocked", "reason": str(exc)}, []
    except FetchError as exc:
        return {"status": "error", "error": str(exc)}, []
    return analyze_page(
        body=page.body,
        content_type=page.content_type,
        final_url=page.final_url,
        original_host=target.ascii_hostname,
        redirect_count=len(page.redirect_chain),
        http_status=page.status,
        truncated=page.truncated,
    )


def _finish(out: dict[str, Any]) -> None:
    seen: set[tuple[str, str]] = set()
    unique = []
    for f in out["flags"]:
        key = (f["code"], f["message"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    out["flags"] = unique
