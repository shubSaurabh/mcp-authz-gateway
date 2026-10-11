"""Masks secrets in tool arguments (before they reach the audit log) and in tool results
(before they reach the agent, so a model that reads a .env file cannot repeat the key)."""
from __future__ import annotations

import re
from typing import Any

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    (
        "assigned-secret",
        re.compile(
            r"(?i)\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
            r"\s*[:=]\s*[\"']?)([^\s\"']{6,})"
        ),
    ),
]
SENSITIVE_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)")


def redact_text(text: str) -> tuple[str, int]:
    count = 0
    for label, pattern in PATTERNS:
        if label == "assigned-secret":
            text, n = pattern.subn(lambda m: f"{m.group(1)}[REDACTED:{label}]", text)
        else:
            text, n = pattern.subn(f"[REDACTED:{label}]", text)
        count += n
    return text, count


def redact(value: Any, mask_keys: bool = True) -> tuple[Any, int]:
    """Return a copy of a JSON value with secrets masked, and how many were masked."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        out, total = [], 0
        for v in value:
            r, n = redact(v, mask_keys)
            out.append(r)
            total += n
        return out, total
    if isinstance(value, dict):
        out, total = {}, 0
        for k, v in value.items():
            if mask_keys and isinstance(k, str) and SENSITIVE_KEYS.search(k) and isinstance(v, str) and v:
                out[k] = "[REDACTED:sensitive-key]"
                total += 1
            else:
                out[k], n = redact(v, mask_keys)
                total += n
        return out, total
    return value, 0
