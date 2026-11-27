"""How a trained classifier combines with the heuristics on the Phase 3 corpus.

    uv run python scripts/analyze_classifier.py ARTIFACT_DIR [--strict T ...] [--json out.json]

Scores every benign and attack fixture with the gateway's own heuristics and
classifier code (same window selection), then reports, for several decision
rules, the false-positive rate on benign fixtures and the recall on attacks.
Thresholds come from the artifact (1% FPR on ml val) or from --strict values,
which must also be chosen on ml val data. Nothing here is tuned on this corpus.

The tuned set (benign/ + attacks/) is the corpus the heuristics were written
against, so heuristic recall there is optimistic; held-out rows are reported
separately.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tripwire.pipeline import heuristics
from tripwire.pipeline.classifier import InjectionClassifier
from tripwire.pipeline.detect import content_text

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
SUSPICIOUS = 0.5


def load(path: Path, label: int, split: str, category: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        r = json.loads(line)
        text = r["text"] if "text" in r else content_text(r["content"])
        cat = category or r.get("family") or path.stem
        rows.append({"id": r["id"], "text": text, "label": label, "split": split, "cat": cat})
    return rows


def corpus() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in sorted((FIX / "benign").glob("*.jsonl")):
        rows += load(f, 0, "tuned")
    for f in sorted((FIX / "attacks").glob("*.jsonl")):
        rows += load(f, 1, "tuned")
    rows += load(FIX / "heldout" / "benign.jsonl", 0, "heldout", "heldout_benign")
    rows += load(FIX / "heldout" / "attacks.jsonl", 1, "heldout")
    return rows


Rule = Callable[[float, float], bool]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--strict", type=float, nargs="*", default=[], help="val-chosen thresholds")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--examples", type=int, default=5)
    a = ap.parse_args()

    clf = InjectionClassifier(a.artifact, intra_op_threads=4)
    if not clf.available or clf.config is None:
        raise SystemExit(f"classifier unavailable: {clf.reason}")
    t = clf.config.threshold
    rows = corpus()
    for r in rows:
        h = heuristics.score_text(r["text"])
        r["h"] = h.score
        cal = clf.score(r["text"], h.spans if h.score > 0 else []).score
        # The gateway reports a calibrated score (threshold -> 0.5); recover the raw
        # probability so rules can be written in the artifact's own terms.
        r["c"] = cal * 2 * t if cal < 0.5 else t + (cal - 0.5) * 2 * (1 - t)

    rules: dict[str, Rule] = {
        "heuristics only (h >= 0.5)": lambda h, c: h >= SUSPICIOUS,
        f"classifier only (c >= {t})": lambda h, c: c >= t,
        "Phase 3 wiring: max(h, raw p) >= 0.5": lambda h, c: max(h, c) >= SUSPICIOUS,
        f"h >= 0.5 OR c >= {t}": lambda h, c: h >= SUSPICIOUS or c >= t,
        f"h >= 0.5 OR (c >= {t} AND h > 0)": lambda h, c: h >= SUSPICIOUS or (c >= t and h > 0),
        f"c >= {t} AND h > 0": lambda h, c: c >= t and h > 0,
    }
    for s in a.strict:
        rules[f"h >= 0.5 OR c >= {s}"] = lambda h, c, s=s: h >= SUSPICIOUS or c >= s
        rules[f"h >= 0.5 OR (c >= {s} AND h > 0)"] = lambda h, c, s=s: (
            h >= SUSPICIOUS or (c >= s and h > 0)
        )

    def rate(sel: list[dict[str, Any]], rule: Rule) -> tuple[int, int]:
        return sum(rule(r["h"], r["c"]) for r in sel), len(sel)

    table = []
    print(f"## {a.artifact.name}: decision rules on the Phase 3 corpus\n")
    print("| rule | FPR all | recall all | FPR held-out | recall held-out |")
    print("|---|---|---|---|---|")
    for name, rule in rules.items():
        cells = {}
        for key, split in (("all", None), ("heldout", "heldout")):
            sel = [r for r in rows if split is None or r["split"] == split]
            fp, nb = rate([r for r in sel if r["label"] == 0], rule)
            tp, na = rate([r for r in sel if r["label"] == 1], rule)
            cells[key] = {"fp": fp, "n_benign": nb, "tp": tp, "n_attack": na}
        al, ho = cells["all"], cells["heldout"]
        print(
            f"| {name} | {al['fp']}/{al['n_benign']} = {al['fp'] / al['n_benign']:.1%} "
            f"| {al['tp']}/{al['n_attack']} = {al['tp'] / al['n_attack']:.1%} "
            f"| {ho['fp']}/{ho['n_benign']} = {ho['fp'] / ho['n_benign']:.1%} "
            f"| {ho['tp']}/{ho['n_attack']} = {ho['tp'] / ho['n_attack']:.1%} |"
        )
        table.append({"rule": name, **cells})

    fps = [r for r in rows if r["label"] == 0 and r["c"] >= t]
    n_by_cat = Counter(r["cat"] for r in rows if r["label"] == 0)
    fp_by_cat = Counter(r["cat"] for r in fps)
    print(f"\n### Classifier false positives at c >= {t} by benign category\n")
    print("| category | n | FP | FP with h > 0 |\n|---|---|---|---|")
    for cat, n in sorted(n_by_cat.items()):
        with_h = sum(1 for r in fps if r["cat"] == cat and r["h"] > 0)
        print(f"| {cat} | {n} | {fp_by_cat.get(cat, 0)} | {with_h} |")
    print(f"| **Total** | {sum(n_by_cat.values())} | {len(fps)} | {sum(r['h'] > 0 for r in fps)} |")

    print("\n### All classifier false positives\n")
    for r in sorted(fps, key=lambda r: -r["c"]):
        snippet = " ".join(r["text"].split())[:160]
        print(f"- {r['id']} (c={r['c']:.5f}, h={r['h']:.2f}): {snippet}")

    misses = [r for r in rows if r["label"] == 1 and r["c"] < t]
    print(f"\n### Classifier misses ({len(misses)}), by family\n")
    for fam, n in Counter(r["cat"] for r in misses).most_common():
        print(f"- {fam}: {n}")

    if a.json:
        a.json.write_text(
            json.dumps(
                {
                    "artifact": a.artifact.name,
                    "threshold": t,
                    "rules": table,
                    "fp_by_category": dict(fp_by_cat),
                    "scores": [{k: r[k] for k in ("id", "cat", "label", "h", "c")} for r in rows],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
