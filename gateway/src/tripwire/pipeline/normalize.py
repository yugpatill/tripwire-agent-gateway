"""Text normalization shared by taint matching and (Phase 3) detectors."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

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
