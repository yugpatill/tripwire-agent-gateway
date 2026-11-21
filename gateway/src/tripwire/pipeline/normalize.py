"""Text normalization shared by taint matching and (Phase 3) detectors."""

from __future__ import annotations

import base64 as _b64
import binascii as _binascii
import html as _html
import re
import unicodedata
from dataclasses import dataclass as _dataclass
from typing import Any
from urllib.parse import unquote as _unquote

# Zero-width and bidi control characters commonly used to hide or split payloads.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_WS = re.compile(r"\s+")


def strip_invisible(text: str) -> str:
    return _INVISIBLE.sub("", text)


def normalize(text: str) -> str:
    """NFKC, drop invisible characters, casefold, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    return _WS.sub(" ", text.casefold()).strip()


def flatten_strings(value: Any) -> list[str]:
    """All scalar leaves of a JSON-like value as strings (bools/None skipped)."""
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, bool) or v is None:
            return
        elif isinstance(v, int | float):
            out.append(str(v))
        elif isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, list | tuple):
            for item in v:
                walk(item)
        else:
            out.append(str(v))

    walk(value)
    return out


# ---------------------------------------------------------------------------
# Detection views: text forms that detectors scan, each mapped back to the
# original string so reported spans point at what the user actually sees.
# ---------------------------------------------------------------------------

# Unicode "tag" characters (U+E0000..U+E007F) mirror ASCII and are invisible:
# used for ASCII smuggling of hidden instructions.
_TAG_START, _TAG_END = 0xE0000, 0xE007F
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_JSON_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_PCT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}[^\s%]*){3,}")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_MAX_DECODED = 20_000


@_dataclass(frozen=True, slots=True)
class View:
    """A scannable form of the input. `offsets[i]` is the original index of
    character i; for decoded segments every character maps to the source span."""

    kind: str  # "normalized" | "base64" | "url" | "html_entities" | "tags" | "html_comment"
    text: str
    offsets: list[int] | None = None  # per-character map (normalized view)
    source_span: tuple[int, int] | None = None  # whole-view map (decoded views)

    def span(self, start: int, end: int) -> tuple[int, int]:
        if self.offsets is not None and self.offsets:
            s = self.offsets[min(start, len(self.offsets) - 1)]
            e = self.offsets[min(max(end - 1, 0), len(self.offsets) - 1)] + 1
            return s, e
        if self.source_span is not None:
            return self.source_span
        return start, end


# Common Cyrillic/Greek lookalikes of Latin letters, folded only in the detection
# view so "Ign\u043ere" (Cyrillic o) still matches "ignore". 1:1 so offsets hold.
_CONFUSABLES = str.maketrans(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u04cf\u0501"
    "\u03bf\u03b1\u03b5\u03b9\u03ba\u03bd\u03c4\u03c1\u0391\u0392\u0395\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a7",
    "aeopcyxijsldoaeikvtpabehikmnoptx",
)


def _normalized_view(text: str) -> View:
    out: list[str] = []
    offsets: list[int] = []
    prev_space = False
    for i, ch in enumerate(text):
        if _INVISIBLE.match(ch) or _TAG_START <= ord(ch) <= _TAG_END:
            continue
        for c in unicodedata.normalize("NFKC", ch).casefold().translate(_CONFUSABLES):
            if c == "\n":
                # Keep line breaks: role-marker rules anchor on line starts.
                while out and out[-1] == " ":
                    out.pop()
                    offsets.pop()
                prev_space = True
            elif c.isspace():
                if prev_space:
                    continue
                c, prev_space = " ", True
            else:
                prev_space = False
            out.append(c)
            offsets.append(i)
    return View("normalized", "".join(out), offsets=offsets)


_SPACES = re.compile(r"[^\S\n]+")


def normalize_lines(text: str) -> str:
    """Like `normalize` but keeps line breaks (for detection views)."""
    text = strip_invisible(unicodedata.normalize("NFKC", text)).casefold()
    return "\n".join(_SPACES.sub(" ", line).strip() for line in text.splitlines()).strip()


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\r\t" for ch in s) / len(s)


def _decode_base64(run: str) -> str | None:
    padded = run + "=" * (-len(run) % 4)
    for decoder in (_b64.b64decode, _b64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (ValueError, _binascii.Error):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Real text has spaces or punctuation; random IDs/hashes decode to junk.
        if _printable_ratio(s) > 0.95 and re.search(r"[A-Za-z]{3,}", s):
            return s
    return None


def detection_views(text: str) -> list[View]:
    """The normalized view plus every decodable hidden payload, normalized too."""
    views = [_normalized_view(text)]

    tags = "".join(
        chr(ord(ch) - _TAG_START)
        for ch in text
        if _TAG_START + 0x20 <= ord(ch) <= _TAG_START + 0x7E
    )
    if tags.strip():
        first = next(i for i, ch in enumerate(text) if _TAG_START <= ord(ch) <= _TAG_END)
        views.append(View("tags", normalize_lines(tags), source_span=(first, len(text))))

    for m in _BASE64_RUN.finditer(text):
        decoded = _decode_base64(m.group(0))
        if decoded:
            views.append(
                View("base64", normalize_lines(decoded[:_MAX_DECODED]), source_span=m.span())
            )

    for m in _JSON_ESCAPES.finditer(text):
        try:
            decoded = m.group(0).encode("ascii").decode("unicode_escape")
            decoded = decoded.encode("utf-16", "surrogatepass").decode("utf-16")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        hidden = "".join(
            chr(ord(ch) - _TAG_START) if _TAG_START + 0x20 <= ord(ch) <= _TAG_START + 0x7E else ch
            for ch in decoded
        )
        views.append(
            View("json_escapes", normalize_lines(hidden[:_MAX_DECODED]), source_span=m.span())
        )

    for m in _PCT_RUN.finditer(text):
        decoded = _unquote(m.group(0))
        if decoded != m.group(0):
            views.append(View("url", normalize_lines(decoded[:_MAX_DECODED]), source_span=m.span()))

    if "&" in text and ";" in text:
        unescaped = _html.unescape(text)
        if unescaped != text:
            views.append(
                View(
                    "html_entities",
                    normalize_lines(unescaped[:_MAX_DECODED]),
                    source_span=(0, len(text)),
                )
            )

    for m in _HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if body:
            views.append(
                View("html_comment", normalize_lines(body[:_MAX_DECODED]), source_span=m.span())
            )
    return views


def count_hidden_chars(text: str) -> tuple[int, int]:
    """(invisible/bidi control characters, Unicode tag characters)."""
    tags = sum(1 for ch in text if _TAG_START <= ord(ch) <= _TAG_END)
    return len(_INVISIBLE.findall(text)), tags
