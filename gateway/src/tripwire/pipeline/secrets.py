"""Secret scanner: credentials and keys in tool results and tool-call arguments.

Provider-specific patterns first (high precision), then a generic
`key = value` assignment check gated on Shannon entropy.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Final

from tripwire.models import DetectorResult


@dataclass(frozen=True, slots=True)
class SecretMatch:
    kind: str
    start: int
    end: int


_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    # Header through END marker, or through the base64 body when output was truncated.
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s]{0,8000})"
        ),
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    ),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("llm_provider_key", re.compile(r"\bsk-(?:ant-(?:api|admin)\d{2}-)?[A-Za-z0-9_-]{32,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("tripwire_api_key", re.compile(r"\btw_[0-9a-f]{8}_[A-Za-z0-9_-]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "connection_string",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+"
        ),
    ),
]

_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
)
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:x+|\*+|<[^>]+>|\$\{?[A-Z_]+\}?|changeme|change-me|password|example|your[_-].*|null|none|true|false|redacted|\[redacted.*)$"
)
_MIN_ENTROPY = 3.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def find_secrets(text: str) -> list[SecretMatch]:
    found: list[SecretMatch] = []
    taken: list[tuple[int, int]] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            s, e = m.span()
            if any(s < te and ts < e for ts, te in taken):
                continue
            found.append(SecretMatch(kind, s, e))
            taken.append((s, e))
    for m in _ASSIGNMENT.finditer(text):
        s, e = m.span(1)
        value = m.group(1)
        if any(s < te and ts < e for ts, te in taken):
            continue
        if _PLACEHOLDER_VALUE.match(value) or shannon_entropy(value) < _MIN_ENTROPY:
            continue
        found.append(SecretMatch("generic_secret", s, e))
        taken.append((s, e))
    return sorted(found, key=lambda f: f.start)


def scan(text: str) -> DetectorResult:
    found = find_secrets(text)
    kinds = sorted({f.kind for f in found})
    return DetectorResult(
        detector="secrets",
        score=1.0 if found else 0.0,
        spans=[(f.start, f.end) for f in found],
        reason=", ".join(kinds) if kinds else "no secrets",
    )


def redact(text: str, matches: list[SecretMatch] | None = None) -> str:
    matches = find_secrets(text) if matches is None else matches
    out, pos = [], 0
    for m in sorted(matches, key=lambda x: x.start):
        if m.start < pos:
            continue
        out.append(text[pos : m.start])
        out.append(f"[REDACTED:{m.kind}]")
        pos = m.end
    out.append(text[pos:])
    return "".join(out)
