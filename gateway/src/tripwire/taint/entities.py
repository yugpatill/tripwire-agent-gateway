"""Entity extraction for value matching: emails, URLs, file paths, long numbers.

Entities are returned as typed keys, e.g. ``email:a@b.io``, ``url:evil.io/x``,
``path:/etc/passwd``, ``num:4111111111111111``. Keys are normalized so the same
entity written differently (case, trailing slash, separators) compares equal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from tripwire.pipeline.normalize import strip_invisible

# Domain labels accept any Unicode letter or digit so internationalized and homoglyph
# domains (e.g. "evil.io" spelled with Cyrillic U+0456 for "i") are extracted as entities.
_LABEL = r"(?:[^\W_]|-)+"
_TLD = r"[^\W\d_]{2,}"
_EMAIL = re.compile(rf"(?<![\w.+-])[\w.+-]+@{_LABEL}(?:\.{_LABEL})*\.{_TLD}")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]}]+", re.IGNORECASE)
_PATH = re.compile(r"(?<![\w/.:])(?:~|\.{1,2})?(?:/[\w.@+-]+){2,}/?")
# Digit runs with optional single separators (space, dash, dot): card, account, phone numbers.
_NUMBER = re.compile(r"(?<![\w.])\d(?:[ .-]?\d){3,}(?![\w])")
_MIN_NUMBER_DIGITS = 4


@dataclass(frozen=True, slots=True)
class Entity:
    kind: str  # email | url | path | num
    key: str  # normalized key, "<kind>:<value>"
    text: str  # original text
    start: int
    end: int
    domain: str | None = None  # email domain or URL host


def _url_key(raw: str) -> tuple[str, str | None]:
    raw = raw.rstrip(".,;:!?")
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    key = host + path
    if parts.query:
        key += "?" + parts.query
    return key, host or None


def extract(text: str) -> list[Entity]:
    text = strip_invisible(text)
    found: list[Entity] = []
    taken: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < te and ts < e for ts, te in taken)

    for m in _URL.finditer(text):
        key, host = _url_key(m.group(0))
        if host:
            found.append(Entity("url", f"url:{key}", m.group(0), m.start(), m.end(), host))
            taken.append(m.span())
    for m in _EMAIL.finditer(text):
        if overlaps(*m.span()):
            continue
        addr = m.group(0).lower().rstrip(".")
        domain = addr.rsplit("@", 1)[1]
        found.append(Entity("email", f"email:{addr}", m.group(0), m.start(), m.end(), domain))
        taken.append(m.span())
    for m in _PATH.finditer(text):
        if overlaps(*m.span()):
            continue
        p = m.group(0).rstrip("/") or "/"
        found.append(Entity("path", f"path:{p}", m.group(0), m.start(), m.end()))
        taken.append(m.span())
    for m in _NUMBER.finditer(text):
        if overlaps(*m.span()):
            continue
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) >= _MIN_NUMBER_DIGITS:
            found.append(Entity("num", f"num:{digits}", m.group(0), m.start(), m.end()))
            taken.append(m.span())
    found.sort(key=lambda e: e.start)
    return found


def entity_keys(text: str) -> list[str]:
    return sorted({e.key for e in extract(text)})


def domains(text: str) -> list[tuple[str, str]]:
    """(kind, domain) for every email/URL entity, kind in {"email","url"}."""
    return [(e.kind, e.domain) for e in extract(text) if e.domain]
