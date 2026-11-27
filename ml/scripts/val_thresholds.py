"""Stricter operating points for an artifact, chosen on val benign tool outputs only.

    uv run python scripts/val_thresholds.py --model minilm-l6 [--fpr 0.01 0.005 0.002 0.001]

Prints JSON {target_fpr: threshold}. Thresholds are never chosen on the gateway
Phase 3 corpus, which stays an evaluation set.
"""

from __future__ import annotations

import argparse
import json

import numpy as np
from common import DATA, MODELS, artifact_dir, load_jsonl
from evaluate import OnnxScorer, threshold_for_fpr


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=list(MODELS))
    ap.add_argument("--fpr", type=float, nargs="+", default=[0.01, 0.005, 0.002, 0.001])
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    benign = [r["text"] for r in load_jsonl(DATA / "val.jsonl") if r["label"] == 0]
    scores = OnnxScorer(artifact_dir(a.model), a.threads).score_many(benign, 1)
    out = {str(f): round(threshold_for_fpr(np.asarray(scores), f), 6) for f in a.fpr}
    print(json.dumps({"model": a.model, "n_val_benign": len(benign), "thresholds": out}))


if __name__ == "__main__":
    main()
