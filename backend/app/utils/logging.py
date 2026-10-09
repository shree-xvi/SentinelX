"""Structured JSON logging for the SentinelX backend.

Emits single-line JSON log records that are easy to ship to a log aggregator
(SIEM / observability stack). Falls back gracefully if ``json`` serialization
of a field fails.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from backend.app.config import settings

_RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Format log records as compact JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include structured context passed via ``logger.info(..., extra={...})``.
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        try:
            return json.dumps(payload, default=str)
        except (TypeError, ValueError):
            payload["message"] = str(payload.get("message"))
            return json.dumps(payload, default=str)


def configure_logging() -> logging.Logger:
    """Configure and return the application logger (idempotent)."""
    app_logger = logging.getLogger("sentinelx")

    if not app_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        app_logger.addHandler(handler)
        app_logger.propagate = False

    app_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    return app_logger


def get_logger(name: str = "sentinelx") -> logging.Logger:
    """Return a child logger under the configured application logger."""
    configure_logging()
    return logging.getLogger(f"sentinelx.{name}") if name != "sentinelx" else logging.getLogger("sentinelx")
