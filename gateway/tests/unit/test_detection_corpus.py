"""Regression gates on the detection corpora (tests/fixtures, built by
scripts/build_corpus.py). Numbers and the method behind them: docs/detection.md."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from tripwire.pipeline import heuristics
from tripwire.pipeline.detect import content_text

FIX = Path(__file__).resolve().parents[1] / "fixtures"
THRESHOLD = 0.5


def rows(path: Path) -> list[dict[str, Any]]:
    out = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    for r in out:
        r["_text"] = r["text"] if "text" in r else content_text(r["content"])
    return out


def flagged(r: dict[str, Any]) -> bool:
    return heuristics.score_text(r["_text"]).score >= THRESHOLD


def test_benign_corpus_size_and_categories() -> None:
    files = sorted((FIX / "benign").glob("*.jsonl"))
    assert {f.stem for f in files} >= {
        "web_pages",
        "emails",
        "api_json",
        "docs",
        "support_tickets",
        "hard_negatives",
    }
    assert sum(len(rows(f)) for f in files) >= 200


def test_heuristic_false_positive_rate_under_2_percent() -> None:
    benign = [r for f in sorted((FIX / "benign").glob("*.jsonl")) for r in rows(f)]
    fps = [r["id"] for r in benign if flagged(r)]
    assert len(fps) / len(benign) < 0.02, fps


def test_heldout_false_positive_rate_under_2_5_percent() -> None:
    benign = rows(FIX / "heldout" / "benign.jsonl")
    fps = [r["id"] for r in benign if flagged(r)]
    assert len(fps) / len(benign) <= 0.025, fps


def test_attack_corpus_size() -> None:
    files = sorted((FIX / "attacks").glob("*.jsonl"))
    assert len(files) == 6 and sum(len(rows(f)) for f in files) >= 100


@pytest.mark.parametrize(
    ("family", "floor"),
    [
        ("direct_override", 0.9),
        ("role_markers", 0.9),
        ("hidden_unicode", 0.95),
        ("base64", 0.95),
        ("html_comments", 0.95),
        ("markdown_exfil", 0.95),
    ],
)
def test_heuristic_recall_per_family(family: str, floor: float) -> None:
    attacks = rows(FIX / "attacks" / f"{family}.jsonl")
    hits = sum(flagged(r) for r in attacks)
    assert hits / len(attacks) >= floor, f"{family}: {hits}/{len(attacks)}"


def test_heldout_recall_floor() -> None:
    by_family: dict[str, list[bool]] = defaultdict(list)
    for r in rows(FIX / "heldout" / "attacks.jsonl"):
        by_family[r["family"]].append(flagged(r))
    total = [x for v in by_family.values() for x in v]
    assert sum(total) / len(total) >= 0.85
