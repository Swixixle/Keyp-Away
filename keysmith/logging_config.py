"""Logging helpers — never leak secrets to logs."""

from __future__ import annotations

import logging
import re


class SecretRedactionFilter(logging.Filter):
    """Redact common secret-shaped strings from log records."""

    _Bearer = re.compile(r"(?i)bearer\s+[a-z0-9._~+/-]+", re.I)
    _ApiKeyInQuotes = re.compile(r'(["\'])(?:api[_-]?key|token|secret)\1\s*[:=]\s*["\'][^"\']+["\']')
    _LongToken = re.compile(r"\b(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}\b")
    _HexRun = re.compile(r"\b[a-f0-9]{32,}\b", re.I)

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            record.args = tuple(
                self._redact(a) if isinstance(a, str) else a for a in record.args
            )
        return True

    @staticmethod
    def _redact(text: str) -> str:
        s = SecretRedactionFilter._Bearer.sub("Bearer [REDACTED]", text)
        s = SecretRedactionFilter._ApiKeyInQuotes.sub("[REDACTED]", s)
        s = SecretRedactionFilter._LongToken.sub("[REDACTED]", s)
        s = SecretRedactionFilter._HexRun.sub("[REDACTED]", s)
        return s


def configure_safe_logging() -> None:
    """Attach redaction to the root handler if not already present."""
    root = logging.getLogger()
    for f in root.filters:
        if isinstance(f, SecretRedactionFilter):
            return
    root.addFilter(SecretRedactionFilter())
