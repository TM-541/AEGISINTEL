"""Structured JSON logging with key-based redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

SENSITIVE_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie)", re.I)
REDACTED = "[REDACTED]"
_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively replace values whose key looks sensitive."""
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            k: (REDACTED if SENSITIVE_KEY.search(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v, _depth + 1) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED}
        if extras:
            payload["ctx"] = redact(extras)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        root.setLevel(level)
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    # Keep noisy third-party loggers quiet and never let them log request bodies.
    for name in ("httpx", "httpcore", "chromadb", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
