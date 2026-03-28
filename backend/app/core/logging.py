from __future__ import annotations

import logging
from typing import Any

from pythonjsonlogger.json import JsonFormatter

SENSITIVE_KEYS = {"api_key", "authorization", "token", "x-api-key"}


class SensitiveDataFilter(logging.Filter):
    """Redacts sensitive keys from structured log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, dict):
            record.msg = redact_payload(record.msg)
        return True


def redact_payload(data: Any) -> Any:
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = redact_payload(value)
        return redacted
    if isinstance(data, list):
        return [redact_payload(item) for item in data]
    return data


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(SensitiveDataFilter())

    root.addHandler(handler)
