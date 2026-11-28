"""JSONL round trip with characters str.splitlines() treats as line breaks.

The Phase 9 Colab run failed in train.py: a record held U+2028 inside a JSON
string written with ensure_ascii=False, and load_jsonl split it with splitlines().
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from common import dump_jsonl_line, jsonl_lines, load_jsonl  # noqa: E402

TRICKY = "a b c\x85d\x1ce\x1df\x1eg\x0bh\x0ci\rj"


def test_load_jsonl_keeps_records_with_unicode_line_separators(tmp_path: Path) -> None:
    rows = [{"text": TRICKY, "label": 1}, {"text": "plain", "label": 0}]
    p = tmp_path / "raw.jsonl"
    # Written the way the failing file was: non-ASCII left unescaped.
    p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    assert len(p.read_text(encoding="utf-8").splitlines()) > 2  # the old reader's bug
    assert load_jsonl(p) == rows


def test_writer_escapes_so_any_splitter_works(tmp_path: Path) -> None:
    rows = [{"text": TRICKY}, {"text": "héllo  "}]
    p = tmp_path / "out.jsonl"
    p.write_text("".join(dump_jsonl_line(r) for r in rows), encoding="utf-8")
    raw = p.read_text(encoding="utf-8")
    assert raw.isascii()
    assert len(raw.splitlines()) == 2
    assert load_jsonl(p) == rows


def test_blank_lines_are_skipped() -> None:
    assert jsonl_lines('{"a": 1}\n\n  \n{"b": 2}\n') == ['{"a": 1}', '{"b": 2}']
