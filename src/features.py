from urllib.parse import urlparse
import re
import ipaddress


def extract_url_features(url):
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    # Basic length features
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)

    # Character counts
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_special_chars"] = len(
        re.findall(r"[^a-zA-Z0-9]", url)
    )

    # Protocol
    features["has_https"] = int(parsed.scheme == "https")

    # Suspicious characters
    features["has_at_symbol"] = int("@" in url)
    features["has_query"] = int(bool(query))

    # IP address instead of domain
    try:
        ipaddress.ip_address(hostname)
        features["has_ip"] = 1
    except ValueError:
        features["has_ip"] = 0

    # Subdomain count
    hostname_parts = hostname.split(".") if hostname else []

    if len(hostname_parts) > 2:
        features["num_subdomains"] = len(hostname_parts) - 2
    else:
        features["num_subdomains"] = 0

    # Suspicious keywords
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "password",
        "bank",
        "confirm",
        "authenticate",
        "wallet",
        "payment"
    ]

    url_lower = url.lower()

    features["has_suspicious_keyword"] = int(
        any(word in url_lower for word in suspicious_words)
    )

    return features