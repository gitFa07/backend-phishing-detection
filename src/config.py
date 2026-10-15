"""Runtime configuration, read from environment variables.

Every setting has a safe default so the project still runs locally with no
configuration. For a hosted deployment, set the variables listed in
``.env.example`` (see DEPLOYMENT.md).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

# Origins the local frontend is served from (README: python -m http.server 5500).
DEFAULT_CORS_ORIGINS: tuple[str, ...] = (
    "http://127.0.0.1:5500",
    "http://localhost:5500",
)


def _get_str(env: Mapping[str, str], name: str) -> str | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def _get_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _get_str(env, name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _get_int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = _get_str(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    return max(value, minimum)


def _get_float(env: Mapping[str, str], name: str, default: float, minimum: float) -> float:
    raw = _get_str(env, name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    return max(value, minimum)


def _get_origins(env: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _get_str(env, name)
    if raw is None:
        return default
    origins = tuple(o.strip().rstrip("/") for o in raw.split(",") if o.strip())
    return origins or default


@dataclass(frozen=True)
class Settings:
    # --- CORS -------------------------------------------------------------
    cors_allow_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS

    # --- Abuse protection -------------------------------------------------
    rate_limit_per_minute: int = 30           # per client, /predict. 0 disables.
    deep_scan_rate_limit_per_minute: int = 6  # per client, deep scans only. 0 disables.
    trusted_proxy_count: int = 0              # reverse proxies in front of the app
    max_request_body_bytes: int = 8192

    # --- Logging ----------------------------------------------------------
    log_level: str = "INFO"

    # --- Features ---------------------------------------------------------
    enable_explanations: bool = True          # load the SHAP explainer at startup
    enable_deep_scan: bool = True             # allow deep_scan=true requests
    deep_scan_timeout_seconds: float = 10.0   # overall budget for all network checks
    safe_browsing_api_key: str | None = None  # optional Google Safe Browsing key


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from environment variables (or a mapping, for tests)."""
    env = os.environ if env is None else env
    defaults = Settings()
    return Settings(
        cors_allow_origins=_get_origins(env, "CORS_ALLOW_ORIGINS", defaults.cors_allow_origins),
        rate_limit_per_minute=_get_int(env, "RATE_LIMIT_PER_MINUTE", defaults.rate_limit_per_minute),
        deep_scan_rate_limit_per_minute=_get_int(
            env, "DEEP_SCAN_RATE_LIMIT_PER_MINUTE", defaults.deep_scan_rate_limit_per_minute
        ),
        trusted_proxy_count=_get_int(env, "TRUSTED_PROXY_COUNT", defaults.trusted_proxy_count),
        max_request_body_bytes=_get_int(
            env, "MAX_REQUEST_BODY_BYTES", defaults.max_request_body_bytes, minimum=1024
        ),
        log_level=(_get_str(env, "LOG_LEVEL") or defaults.log_level).upper(),
        enable_explanations=_get_bool(env, "ENABLE_EXPLANATIONS", defaults.enable_explanations),
        enable_deep_scan=_get_bool(env, "ENABLE_DEEP_SCAN", defaults.enable_deep_scan),
        deep_scan_timeout_seconds=_get_float(
            env, "DEEP_SCAN_TIMEOUT_SECONDS", defaults.deep_scan_timeout_seconds, minimum=2.0
        ),
        safe_browsing_api_key=_get_str(env, "SAFE_BROWSING_API_KEY"),
    )
