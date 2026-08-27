"""Output redaction shared by the synthetic target and later evidence pipeline."""

from __future__ import annotations

import re
from typing import Any

SYNTHETIC_CANARY = "SYNTHETIC_CANARY_DO_NOT_EMIT_184"
_SECRET_PATTERN = re.compile(r"(?i)(secret|token|password)[=:][^\s,;]+")


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return _SECRET_PATTERN.sub("[REDACTED]", value.replace(SYNTHETIC_CANARY, "[REDACTED]"))
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
