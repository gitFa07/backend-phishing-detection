"""One-line-per-event JSON logging (easy to search in any hosting provider's log viewer)."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

LOGGER_NAME = "phishing_api"
_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything passed via logger.info(..., extra={...}) becomes a JSON field.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Attach a JSON stdout handler to the ``phishing_api`` logger (idempotent)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(getattr(h, "_phishing_json", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._phishing_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.propagate = False
    return logger
