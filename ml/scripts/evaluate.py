"""Evaluate an exported int8 ONNX artifact exactly as the gateway runs it.

    uv run python scripts/evaluate.py --model minilm-l6 [--threads 8]

* Windows of max_length tokens with a 64-token overlap, [CLS] ... [SEP], max
  p(injection) over windows (same as gateway/src/tripwire/pipeline/classifier.py).
* Threshold: lowest score with FPR <= 1% on the validation benign set (benign tool
  outputs + hard negatives), then applied unchanged to test and test_ood.
* Reports precision, recall, F1, ROC AUC, PR AUC, FPR, FPR on hard negatives and
  per-family recall on test and test_ood, plus the gateway's Phase 3 fixture corpus
  (written independently of this dataset) as an extra out-of-distribution check.

Writes artifacts/injection-<key>/metrics.json and pr_curve.png, and the threshold
into config.json.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import onnxruntime as ort
from common import DATA, MODELS, OVERLAP_TOKENS, ROOT, artifact_dir, load_jsonl
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from tokenizers import Tokenizer

TARGET_FPR = 0.01
GATEWAY_FIXTURES = ROOT.parent / "gateway" / "tests" / "fixtures"


class OnnxScorer:
    def __init__(self, d: Path, threads: int) -> None:
        cfg = json.loads((d / "config.json").read_text())
        self.max_length = int(cfg["max_length"])
        self.pos = cfg["labels"].index("injection")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        self.sess = ort.InferenceSession(str(d / "model.int8.onnx"), opts, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.sess.get_inputs()}
        self.tok = Tokenizer.from_file(str(d / "tokenizer.json"))
        self.tok.no_truncation()
        self.tok.no_padding()
        self.cls = self.tok.token_to_id("[CLS]")
        self.sep = self.tok.token_to_id("[SEP]")
        self.body = self.max_length - (2 if self.cls is not None and self.sep is not None else 0)
        pad = self.tok.token_to_id("[PAD]")
        self.pad = 0 if pad is None else pad

    def windows(self, ids: list[int]) -> list[list[int]]:
        if len(ids) <= self.body:
            return [ids]
        stride = self.body - OVERLAP_TOKENS
        return [ids[s : s + self.body] for s in range(0, max(len(ids) - OVERLAP_TOKENS, 1), stride)]

    def score(self, text: str) -> float:
        ids = self.tok.encode(text, add_special_tokens=False).ids
        if not ids:
            return 0.0
        best = 0.0
        for w in self.windows(ids):
            x = [self.cls, *w, self.sep] if self.cls is not None and self.sep is not None else w
            feed = {"input_ids": np.asarray([x], np.int64), "attention_mask": np.ones((1, len(x)), np.int64)}
            if "token_type_ids" in self.inputs:
                feed["token_type_ids"] = np.zeros((1, len(x)), np.int64)
            logits = self.sess.run(None, feed)[0][0]
            z = np.exp(logits - logits.max())
            best = max(best, float(z[self.pos] / z.sum()))
        return best


    def score_many(self, texts: list[str], batch: int = 1) -> np.ndarray:
        """Max p(injection) per text. batch=1 reproduces the gateway exactly; larger
        batches are faster but dynamic int8 quantization then computes activation
        scales across the batch, shifting scores by ~1e-3."""
        items: list[tuple[int, list[int]]] = []
        for ti, text in enumerate(texts):
            ids = self.tok.encode(text, add_special_tokens=False).ids
            for w in self.windows(ids) if ids else []:
                x = [self.cls, *w, self.sep] if self.cls is not None and self.sep is not None else w
                items.append((ti, x))
        items.sort(key=lambda it: len(it[1]))
        best = np.zeros(len(texts))
        for i in range(0, len(items), batch):
            chunk = items[i : i + batch]
            width = max(len(x) for _, x in chunk)
            ids = np.full((len(chunk), width), self.pad, np.int64)
            mask = np.zeros((len(chunk), width), np.int64)
            for j, (_, x) in enumerate(chunk):
                ids[j, : len(x)] = x
                mask[j, : len(x)] = 1
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            logits = self.sess.run(None, feed)[0]
            z = np.exp(logits - logits.max(axis=1, keepdims=True))
            p = z[:, self.pos] / z.sum(axis=1)
            for (ti, _), pj in zip(chunk, p, strict=True):
                best[ti] = max(best[ti], float(pj))
        return best


def threshold_for_fpr(benign_scores: np.ndarray, target: float) -> float:
    """Smallest threshold t such that mean(benign >= t) <= target."""
    s = np.sort(benign_scores)
    k = int(np.floor(target * len(s)))  # number of benign allowed at/above t
    if k == 0:
        return float(np.nextafter(s[-1], 1.0))
    return float(np.nextafter(s[-k - 1], 1.0)) if s[-k] > s[-k - 1] else float(np.nextafter(s[-k], 1.0))


def block(rows: list[dict[str, Any]], scores: np.ndarray, thr: float) -> dict[str, Any]:
    y = np.array([r["label"] for r in rows])
    pred = scores >= thr
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    hard = np.array([r["family"] == "hard_negative" for r in rows])
    fam: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r, p in zip(rows, pred, strict=True):
        if r["label"] == 1:
            fam[r["family"]][0] += int(p)
            fam[r["family"]][1] += 1
    out: dict[str, Any] = {
        "n": len(rows),
        "n_injection": int(y.sum()),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "fpr_hard_negatives": round(float(pred[hard].mean()), 4) if hard.any() else None,
        "recall_by_family": {f: round(h / n, 4) for f, (h, n) in sorted(fam.items())},
    }
    if 0 < y.sum() < len(y):
        out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
    return out


BATCH = 1


def score_rows(scorer: OnnxScorer, rows: list[dict[str, Any]], label: str) -> np.ndarray:
    t0 = time.time()
    out = scorer.score_many([r["text"] for r in rows], BATCH)
    print(f"  scored {label}: {len(rows)} rows in {time.time() - t0:.0f}s", flush=True)
    return out


def gateway_fixtures() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in sorted((GATEWAY_FIXTURES / "benign").glob("*.jsonl")):
        for r in load_jsonl(f):
            text = r.get("text") or "\n".join(_strings(r.get("content")))
            rows.append({"text": text, "label": 0, "family": "hard_negative" if f.stem == "hard_negatives" else "benign"})
    for f in sorted((GATEWAY_FIXTURES / "attacks").glob("*.jsonl")):
        rows += [{"text": r["text"], "label": 1, "family": f.stem} for r in load_jsonl(f)]
    for r in load_jsonl(GATEWAY_FIXTURES / "heldout" / "benign.jsonl"):
        rows.append({"text": r["text"], "label": 0, "family": "benign"})
    for r in load_jsonl(GATEWAY_FIXTURES / "heldout" / "attacks.jsonl"):
        rows.append({"text": r["text"], "label": 1, "family": r["family"]})
    return rows


def _strings(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        return [s for x in v.values() for s in _strings(x)]
    if isinstance(v, list):
        return [s for x in v for s in _strings(x)]
    return [] if v is None or isinstance(v, bool) else [str(v)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=list(MODELS))
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--batch", type=int, default=1, help=">1 is faster but not bit-exact with the gateway")
    a = ap.parse_args()
    global BATCH
    BATCH = a.batch
    d = artifact_dir(a.model)
    scorer = OnnxScorer(d, a.threads)
    print(f"evaluating {d}")

    val = load_jsonl(DATA / "val.jsonl")
    v_scores = score_rows(scorer, val, "val")
    v_y = np.array([r["label"] for r in val])
    thr = threshold_for_fpr(v_scores[v_y == 0], TARGET_FPR)

    results: dict[str, Any] = {
        "model": a.model,
        "base_model": json.loads((d / "config.json").read_text()).get("base_model", MODELS[a.model].hf_id),
        "zero_shot": MODELS[a.model].zero_shot,
        "evaluated_artifact": "model.int8.onnx",
        "batch": BATCH,
        "threshold": round(thr, 6),
        "threshold_rule": f"lowest score with FPR <= {TARGET_FPR:.0%} on val benign tool outputs (n={int((v_y == 0).sum())})",
        "val": block(val, v_scores, thr),
    }
    curves = {}
    for split in ("test", "test_ood"):
        rows = load_jsonl(DATA / f"{split}.jsonl")
        s = score_rows(scorer, rows, split)
        results[split] = block(rows, s, thr)
        results[split]["at_threshold_0.5"] = {k: v for k, v in block(rows, s, 0.5).items() if k in ("precision", "recall", "f1", "fpr")}
        curves[split] = (np.array([r["label"] for r in rows]), s)
    fx = gateway_fixtures()
    results["gateway_phase3_corpus"] = block(fx, score_rows(scorer, fx, "gateway fixtures"), thr)

    (d / "metrics.json").write_text(json.dumps(results, indent=2))
    cfg = json.loads((d / "config.json").read_text())
    cfg["threshold"] = round(thr, 6)
    (d / "config.json").write_text(json.dumps(cfg, indent=2))

    plt.figure(figsize=(5, 4))
    for split, (y, s) in curves.items():
        p, r, _ = precision_recall_curve(y, s)
        plt.plot(r, p, label=f"{split} (AP {average_precision_score(y, s):.3f})")
    plt.xlabel("recall")
    plt.ylabel("precision")
    plt.title(a.model)
    plt.legend()
    plt.tight_layout()
    plt.savefig(d / "pr_curve.png", dpi=120)
    print(json.dumps({k: results[k] for k in ("threshold", "test", "test_ood")}, indent=2))


if __name__ == "__main__":
    main()
