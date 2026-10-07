"""Helpers for masking sensitive data in log messages."""

import re

# Patterns to mask in logs
SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password": "*****"'),
    (re.compile(r'"value"\s*:\s*"[^"]*"'), '"value": "*****"'),
    (re.compile(r"X-API-Key:\s*\S+", re.IGNORECASE), "X-API-Key: *****"),
]


def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data in log messages."""
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
