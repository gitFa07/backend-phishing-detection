"""Online reputation lookups: domain age (RDAP) and Google Safe Browsing.

Both talk to fixed, well-known third-party hosts (never to a host the caller
chose), so they do not need the SSRF guard in ``netguard``.

Privacy note: a deep scan sends the registered domain to rdap.org and, when a
key is configured, the full URL to Google Safe Browsing.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

import requests

from .domains import flag

RDAP_URL = "https://rdap.org/domain/{domain}"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
_MAX_RDAP_BYTES = 2_000_000


def _parse_rdap_date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check_domain_age(
    registered_domain: str,
    timeout: float,
    get: Callable[..., Any] = requests.get,
    now: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Look up when the domain was first registered (RDAP). Young domains are a phishing signal."""
    flags: list[dict[str, str]] = []
    if not _DOMAIN_RE.match(registered_domain):
        return {"status": "skipped", "reason": "Not a registrable domain name."}, flags
    try:
        resp = get(
            RDAP_URL.format(domain=registered_domain),
            timeout=timeout,
            headers={"Accept": "application/rdap+json, application/json"},
        )
    except requests.RequestException:
        return {"status": "error", "error": "RDAP lookup failed."}, flags

    if resp.status_code == 404:
        return {"status": "unavailable", "reason": "No RDAP record found for this domain."}, flags
    if resp.status_code != 200 or len(resp.content) > _MAX_RDAP_BYTES:
        return {"status": "error", "error": f"RDAP lookup returned HTTP {resp.status_code}."}, flags

    try:
        events = resp.json().get("events", [])
        registered = next(
            (e["eventDate"] for e in events if e.get("eventAction") == "registration" and e.get("eventDate")),
            None,
        )
        if registered is None:
            return {"status": "unavailable", "reason": "RDAP record has no registration date."}, flags
        registered_at = _parse_rdap_date(registered)
    except (ValueError, KeyError, TypeError, AttributeError):
        return {"status": "error", "error": "RDAP response could not be read."}, flags

    age_days = max((((now or datetime.now(timezone.utc)) - registered_at).days), 0)
    if age_days < 7:
        flags.append(flag("high", "domain_very_new", f"The domain was registered only {age_days} day(s) ago."))
    elif age_days < 30:
        flags.append(flag("warning", "domain_new", f"The domain was registered {age_days} days ago."))

    return {"status": "ok", "registered": registered_at.date().isoformat(), "age_days": age_days}, flags


def check_safe_browsing(
    url: str,
    api_key: str | None,
    timeout: float,
    post: Callable[..., Any] = requests.post,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Ask Google Safe Browsing (Lookup API v4) whether ``url`` is on a threat list."""
    flags: list[dict[str, str]] = []
    if not api_key:
        return {"status": "skipped", "reason": "No SAFE_BROWSING_API_KEY configured."}, flags

    body = {
        "client": {"clientId": "phishing-url-detection", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = post(SAFE_BROWSING_URL, params={"key": api_key}, json=body, timeout=timeout)
    except requests.RequestException:
        # Never include the exception text: requests puts the full URL, key included, in it.
        return {"status": "error", "error": "Safe Browsing request failed."}, flags
    if resp.status_code != 200:
        return {"status": "error", "error": f"Safe Browsing returned HTTP {resp.status_code}."}, flags

    try:
        matches = resp.json().get("matches", [])
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    except (ValueError, AttributeError):
        return {"status": "error", "error": "Safe Browsing response could not be read."}, flags

    if threats:
        flags.append(flag(
            "high", "safe_browsing_match",
            "Google Safe Browsing lists this URL (" + ", ".join(t.replace("_", " ").lower() for t in threats) + ").",
        ))
    return {"status": "ok", "listed": bool(threats), "threat_types": threats}, flags
