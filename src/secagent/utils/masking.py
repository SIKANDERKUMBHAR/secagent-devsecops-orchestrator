"""Masking helpers for secrets in command logs/evidence."""

from __future__ import annotations

import re


_TOKEN_PATTERNS = [
    re.compile(r"(?i)(token=)([^\s&]+)"),
    re.compile(r"(?i)(password=)([^\s&]+)"),
    re.compile(r"(?i)(secret=)([^\s&]+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)([^\s]+)"),
]


def mask_secrets(text: str) -> str:
    masked = text
    for pattern in _TOKEN_PATTERNS:
        masked = pattern.sub(r"\1***", masked)
    return masked
