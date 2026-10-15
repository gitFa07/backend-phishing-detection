"""Offline, hostname-only domain heuristics ("reputation" without any lookup).

These checks need no network access, so they run on every request. They are
heuristics: a hit is a reason to look closer, never proof of phishing.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

# Naive public-suffix handling: the last two labels are the registered domain,
# unless the last two form one of these multi-part suffixes. This is not the
# full Public Suffix List; add entries here if you need more countries.
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "nic.in", "res.in", "edu.in", "firm.in", "gen.in", "ind.in",
    "co.jp", "co.nz", "co.za", "co.id",
    "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "com.tr", "com.pk", "com.bd",
})

# TLDs that show up disproportionately in throwaway / abusive domains.
RISKY_TLDS = frozenset({
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "click", "icu", "cyou", "sbs", "buzz", "cam", "monster",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "lnkd.in", "s.id",
})


@dataclass(frozen=True)
class Brand:
    name: str
    tokens: tuple[str, ...]    # words that identify the brand inside a hostname
    domains: tuple[str, ...]   # registered domains that genuinely belong to it


BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal",), ("paypal.com", "paypal.me")),
    Brand("Google", ("google", "gmail"), ("google.com", "google.co.in", "gmail.com", "goo.gl", "youtube.com")),
    Brand("Microsoft", ("microsoft", "outlook", "office365"),
          ("microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com")),
    Brand("Apple", ("apple", "icloud"), ("apple.com", "icloud.com")),
    Brand("Amazon", ("amazon",), ("amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com")),
    Brand("Facebook", ("facebook",), ("facebook.com", "fb.com", "fb.me")),
    Brand("Instagram", ("instagram",), ("instagram.com",)),
    Brand("WhatsApp", ("whatsapp",), ("whatsapp.com", "whatsapp.net")),
    Brand("Netflix", ("netflix",), ("netflix.com",)),
    Brand("LinkedIn", ("linkedin",), ("linkedin.com", "lnkd.in")),
    Brand("GitHub", ("github",), ("github.com", "github.io", "githubusercontent.com")),
    Brand("Dropbox", ("dropbox",), ("dropbox.com",)),
    Brand("Adobe", ("adobe",), ("adobe.com",)),
    Brand("eBay", ("ebay",), ("ebay.com", "ebay.in")),
    Brand("DHL", ("dhl",), ("dhl.com",)),
    Brand("FedEx", ("fedex",), ("fedex.com",)),
    Brand("State Bank of India", ("sbi", "onlinesbi"),
          ("sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in")),
    Brand("HDFC Bank", ("hdfc", "hdfcbank"), ("hdfcbank.com", "hdfc.com")),
    Brand("ICICI Bank", ("icici", "icicibank"), ("icicibank.com",)),
    Brand("Axis Bank", ("axisbank",), ("axisbank.com",)),
    Brand("Paytm", ("paytm",), ("paytm.com", "paytm.in")),
    Brand("PhonePe", ("phonepe",), ("phonepe.com",)),
    Brand("Flipkart", ("flipkart",), ("flipkart.com",)),
    Brand("IRCTC", ("irctc",), ("irctc.co.in",)),
    Brand("Income Tax India", ("incometax", "incometaxindia"), ("incometax.gov.in", "incometaxindia.gov.in")),
)

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def registered_domain(hostname: str) -> str:
    """Return the registered domain of ``hostname`` (naive; see MULTI_PART_SUFFIXES)."""
    labels = hostname.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(text.lower()) if t]


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (small inputs only)."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike_forms(token: str) -> set[str]:
    """Spellings a squatter might use for ``token`` (digits-for-letters, rn->m...)."""
    base = token.translate(_LEET)
    return {base, base.replace("rn", "m"), base.replace("vv", "w")}


def detect_brand_impersonation(hostname: str) -> dict[str, Any] | None:
    """Flag hostnames that use a known brand's name without being that brand's domain."""
    reg = registered_domain(hostname)
    host_tokens = tokenize(hostname)
    sld_tokens = tokenize(reg.split(".")[0])

    for brand in BRANDS:
        if reg in brand.domains:
            continue  # genuine
        for token in brand.tokens:
            if token in host_tokens:
                return {
                    "brand": brand.name,
                    "match_type": "brand_in_hostname",
                    "matched": token,
                    "legitimate_domains": list(brand.domains),
                }
        for token in brand.tokens:
            if len(token) < 5:
                continue
            for cand in sld_tokens:
                if cand == token or len(cand) < 5:
                    continue
                if any(form == token or edit_distance(form, token) == 1 for form in _lookalike_forms(cand)):
                    return {
                        "brand": brand.name,
                        "match_type": "lookalike_spelling",
                        "matched": cand,
                        "legitimate_domains": list(brand.domains),
                    }
    return None


def brands_mentioned(text: str, exclude_registered_domain: str) -> list[str]:
    """Brand names mentioned in free text (e.g. a page title) whose real domain this is not."""
    tokens = set(tokenize(text))
    found = []
    for brand in BRANDS:
        if exclude_registered_domain in brand.domains:
            continue
        if any(t in tokens for t in brand.tokens if len(t) >= 4):
            found.append(brand.name)
    return found


def mixed_scripts(label: str) -> bool:
    """True if one domain label mixes letters from different scripts (e.g. Latin + Cyrillic)."""
    scripts = set()
    for ch in label:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return len(scripts) > 1


def flag(severity: str, code: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message}


def analyze_domain(hostname: str, ascii_hostname: str, is_ip: bool) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Run every offline check. Returns ``(details, flags)``."""
    flags: list[dict[str, str]] = []
    if is_ip:
        return {"host_type": "ip_address"}, flags

    reg = registered_domain(ascii_hostname)
    tld = ascii_hostname.rstrip(".").rsplit(".", 1)[-1]
    punycode = any(label.startswith("xn--") for label in ascii_hostname.split("."))
    mixed = any(mixed_scripts(label) for label in hostname.split("."))
    shortener = reg in URL_SHORTENERS or ascii_hostname in URL_SHORTENERS
    risky_tld = tld in RISKY_TLDS
    brand = detect_brand_impersonation(hostname)

    if brand:
        if brand["match_type"] == "brand_in_hostname":
            flags.append(flag(
                "warning", "brand_impersonation",
                f"The address uses the name '{brand['matched']}' ({brand['brand']}) but the domain "
                f"'{reg}' is not one of that brand's official domains.",
            ))
        else:
            flags.append(flag(
                "high", "lookalike_domain",
                f"'{brand['matched']}' looks like a misspelling of {brand['brand']}, "
                f"but '{reg}' is not one of that brand's official domains.",
            ))
    if punycode or mixed:
        flags.append(flag(
            "high" if mixed else "warning", "idn_homograph",
            "The hostname uses international characters"
            + (" from more than one alphabet" if mixed else "")
            + ", which attackers use to imitate familiar names.",
        ))
    if risky_tld:
        flags.append(flag("info", "risky_tld", f".{tld} domains are often used for throwaway or abusive sites."))
    if shortener:
        flags.append(flag("info", "url_shortener", "This is a link shortener, so the real destination is hidden."))

    details = {
        "host_type": "domain",
        "registered_domain": reg,
        "tld": tld,
        "punycode": punycode,
        "mixed_scripts": mixed,
        "risky_tld": risky_tld,
        "url_shortener": shortener,
        "brand_impersonation": brand,
    }
    return details, flags
