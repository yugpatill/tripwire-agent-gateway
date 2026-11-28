"""Phase 9 acceptance gate for a retrained classifier.

    uv run python scripts/gate.py --model minilm-l6 [--model deberta-v3-small] [--out artifacts/gate.json]

A model may be published only if, on its int8 artifact (metrics.json from evaluate.py):

* classifier-only false-positive rate on the gateway's Phase 3 corpus <= 2%
  (gateway/tests/fixtures; never used for training or threshold selection), and
* recall on test_ood (the held-out role_markers family) >= 98%, and
* the int8 file stays within 0.05 of PyTorch (config.json int8_ok).

Also prints the numbers the README quotes from the first model (test F1 "98%",
Phase 3 corpus recall "74%" and false-positive rate "7%"), so a change is visible.
Exit code 1 if any model fails; the notebook only reports it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import ARTIFACTS, artifact_dir

MAX_GW_FPR = 0.02
MIN_OOD_RECALL = 0.98


def gate(key: str) -> dict[str, Any]:
    d = artifact_dir(key)
    met = json.loads((d / "metrics.json").read_text())
    cfg = json.loads((d / "config.json").read_text())
    gw, ood, test = met["gateway_phase3_corpus"], met["test_ood"], met["test"]
    checks = {
        "gw_fpr<=2%": gw["fpr"] <= MAX_GW_FPR,
        "test_ood_recall>=98%": ood["recall"] >= MIN_OOD_RECALL,
        "int8_ok": bool(cfg.get("int8_ok", cfg.get("verification", {}).get("max_abs_diff_int8_vs_torch", 1.0) < 0.05)),
    }
    return {
        "model": key,
        "pass": all(checks.values()),
        "checks": checks,
        "gw_fpr": gw["fpr"],
        "gw_recall": gw["recall"],
        "test_ood_recall": ood["recall"],
        "test_f1": test["f1"],
        "test_fpr": test["fpr"],
        "deepset_recall": test["recall_by_family"].get("deepset"),
        "threshold": met["threshold"],
        "int8_strategy": cfg.get("verification", {}).get("int8_strategy", "default"),
        "int8_diff": cfg.get("verification", {}).get("max_abs_diff_int8_vs_torch"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="append", required=True)
    ap.add_argument("--out", type=Path, default=ARTIFACTS / "gate.json")
    a = ap.parse_args()
    results = [gate(k) for k in a.model]
    for r in results:
        verdict = "PASS" if r["pass"] else "FAIL"
        print(f"{r['model']}: {verdict}  {r['checks']}")
        print(
            f"  Phase 3 corpus FPR {r['gw_fpr']:.1%} (README: 7%), recall {r['gw_recall']:.1%} (README: 74%); "
            f"test F1 {r['test_f1']:.3f} (README: 98%); test_ood recall {r['test_ood_recall']:.1%}; "
            f"deepset {r['deepset_recall']}; int8 {r['int8_strategy']} ({r['int8_diff']})"
        )
    a.out.write_text(json.dumps(results, indent=2))
    if not all(r["pass"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
