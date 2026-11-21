"""Evaluate detectors on the fixture corpora.

    uv run python scripts/eval_detectors.py [--json out.json] [--show-misses]

Flag definitions: heuristic/classifier score >= suspicious_threshold (0.5);
secrets/pii: any match. Classifier rows appear only when TRIPWIRE_CLASSIFIER_DIR
points at an artifact.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from tripwire.pipeline import heuristics, secrets
from tripwire.pipeline.classifier import InjectionClassifier
from tripwire.pipeline.detect import content_text
from tripwire.pipeline.pii import PiiDetector

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
THRESHOLD = 0.5


def load(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    for r in rows:
        r["_text"] = r["text"] if "text" in r else content_text(r["content"])
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    ap.add_argument("--show-misses", action="store_true")
    a = ap.parse_args()

    pii = PiiDetector("patterns")
    clf = InjectionClassifier(os.environ.get("TRIPWIRE_CLASSIFIER_DIR") or None)

    def run(text: str) -> dict[str, bool]:
        out = {
            "heuristic": heuristics.score_text(text).score >= THRESHOLD,
            "secrets": bool(secrets.find_secrets(text)),
            "pii": bool(pii.find(text)),
        }
        if clf.available:
            out["classifier"] = clf.score(text).score >= THRESHOLD
        return out

    report: dict[str, Any] = {"benign": {}, "attacks": {}, "quoted_payloads": {}}
    fp_rows: list[str] = []
    totals: dict[str, int] = defaultdict(int)
    n_benign = 0
    for f in sorted((FIX / "benign").glob("*.jsonl")):
        rows = load(f)
        counts: dict[str, int] = defaultdict(int)
        for r in rows:
            for det, flagged in run(r["_text"]).items():
                counts[det] += flagged
                totals[det] += flagged
                if flagged and det == "heuristic":
                    fp_rows.append(f"{r['id']}: {heuristics.score_text(r['_text']).reason}")
        n_benign += len(rows)
        report["benign"][f.stem] = {"n": len(rows), **counts}
    report["benign"]["_total"] = {"n": n_benign, **totals}

    misses: list[str] = []
    n_att, hit_att = 0, 0
    for f in sorted((FIX / "attacks").glob("*.jsonl")):
        rows = load(f)
        hits = 0
        for r in rows:
            res = heuristics.score_text(r["_text"])
            if res.score >= THRESHOLD:
                hits += 1
            else:
                misses.append(f"{r['id']} ({res.score:.2f}): {r['_text'][:90]!r}")
        n_att += len(rows)
        hit_att += hits
        report["attacks"][f.stem] = {
            "n": len(rows),
            "detected": hits,
            "recall": round(hits / len(rows), 3),
        }
    report["attacks"]["_total"] = {
        "n": n_att,
        "detected": hit_att,
        "recall": round(hit_att / n_att, 3),
    }

    hb = load(FIX / "heldout" / "benign.jsonl")
    ha = load(FIX / "heldout" / "attacks.jsonl")
    hb_fp = [r for r in hb if heuristics.score_text(r["_text"]).score >= THRESHOLD]
    ha_hit: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    ha_miss: list[str] = []
    for r in ha:
        ok = heuristics.score_text(r["_text"]).score >= THRESHOLD
        ha_hit[r["family"]][0] += ok
        ha_hit[r["family"]][1] += 1
        if not ok:
            ha_miss.append(f"{r['id']}: {r['_text'][:90]!r}")
    report["heldout"] = {
        "benign": {"n": len(hb), "heuristic_fp": len(hb_fp)},
        "attacks": {f: {"n": n, "detected": d} for f, (d, n) in ha_hit.items()},
    }

    q = load(FIX / "quoted_payloads.jsonl")
    qf = sum(heuristics.score_text(r["_text"]).score >= THRESHOLD for r in q)
    report["quoted_payloads"] = {"n": len(q), "heuristic_flagged": qf}

    dets = ["heuristic", "secrets", "pii"] + (["classifier"] if clf.available else [])
    print(f"## Benign corpus ({n_benign} samples): samples flagged per detector\n")
    print("| Category | n | " + " | ".join(dets) + " |")
    print("|---|---|" + "---|" * len(dets))
    for cat, c in report["benign"].items():
        name = "**Total**" if cat == "_total" else cat
        print(f"| {name} | {c['n']} | " + " | ".join(str(c.get(d, 0)) for d in dets) + " |")
    h = report["benign"]["_total"]["heuristic"]
    print(f"\nHeuristic false-positive rate: {h}/{n_benign} = {h / n_benign:.1%}\n")
    print(f"## Attack corpus ({n_att} samples): heuristic recall per family\n")
    print("| Family | n | detected | recall |\n|---|---|---|---|")
    for fam, c in report["attacks"].items():
        name = "**Total**" if fam == "_total" else fam
        print(f"| {name} | {c['n']} | {c['detected']} | {c['recall']:.0%} |")
    print(f"\nQuoted-payload articles flagged by heuristics: {qf}/{len(q)}")
    print("\n## Held-out set (written after tuning, scored once)\n")
    print(f"Benign false positives: {len(hb_fp)}/{len(hb)} = {len(hb_fp) / len(hb):.1%}\n")
    print("| Family | n | detected | recall |\n|---|---|---|---|")
    td = tn = 0
    for fam, (d, n) in sorted(ha_hit.items()):
        print(f"| {fam} | {n} | {d} | {d / n:.0%} |")
        td, tn = td + d, tn + n
    print(f"| **Total** | {tn} | {td} | {td / tn:.0%} |")
    for r in hb_fp:
        print(f"- held-out FP {r['id']}: {heuristics.score_text(r['_text']).reason}")
    for m in ha_miss:
        print(f"- held-out miss {m}")
    if not clf.available:
        print(f"\nClassifier not evaluated: {clf.reason}")
    if fp_rows:
        print("\n### Heuristic false positives\n")
        print("\n".join(f"- {x}" for x in fp_rows))
    if a.show_misses and misses:
        print("\n### Heuristic misses\n")
        print("\n".join(f"- {x}" for x in misses))
    if a.json:
        a.json.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
