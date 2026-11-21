"""Export a fine-tuned (or zero-shot) model to the gateway's artifact contract.

    uv run python scripts/export_onnx.py --model minilm-l6

Writes artifacts/injection-<key>/: model.int8.onnx, tokenizer.json, config.json
(threshold filled in later by evaluate.py). Exports with Optimum, applies dynamic
int8 quantization (QInt8 weights), and verifies fp32 ONNX vs PyTorch probabilities
agree within 1e-2; the int8 deviation is recorded too.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from common import CHECKPOINTS, DATA, MODELS, artifact_dir, load_jsonl
from onnxruntime.quantization import QuantType, quantize_dynamic
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoModelForSequenceClassification, AutoTokenizer

POSITIVE = ("injection", "malicious", "label_1", "jailbreak")


def positive_index(id2label: dict[int, str]) -> int:
    for i, lab in sorted(id2label.items()):
        if str(lab).lower() in POSITIVE:
            return int(i)
    return max(int(i) for i in id2label)


def softmax(x: np.ndarray) -> np.ndarray:
    z = np.exp(x - x.max(axis=-1, keepdims=True))
    return z / z.sum(axis=-1, keepdims=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=list(MODELS))
    a = ap.parse_args()
    spec = MODELS[a.model]
    src = spec.hf_id if spec.zero_shot else str(CHECKPOINTS / spec.key / "best")
    base_model = spec.hf_id
    info_path = Path(src) / "train_info.json"
    if info_path.exists():
        base_model = json.loads(info_path.read_text())["base"]
    out = artifact_dir(spec.key)
    out.mkdir(parents=True, exist_ok=True)

    tok = AutoTokenizer.from_pretrained(src, use_fast=True)
    with tempfile.TemporaryDirectory() as tmp:
        ort_model = ORTModelForSequenceClassification.from_pretrained(src, export=True)
        ort_model.save_pretrained(tmp)
        fp32 = Path(tmp) / "model.onnx"
        quantize_dynamic(str(fp32), str(out / "model.int8.onnx"), weight_type=QuantType.QInt8)

        # Verification on real validation texts.
        texts = [r["text"] for r in load_jsonl(DATA / "val.jsonl")[:64]]
        enc = tok(texts, truncation=True, max_length=spec.max_length, padding=True, return_tensors="np")
        torch_model = AutoModelForSequenceClassification.from_pretrained(src).eval()
        with torch.inference_mode():
            pt = softmax(torch_model(**{k: torch.tensor(v) for k, v in enc.items()}).logits.numpy())
        def run(path: Path) -> np.ndarray:
            sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            names = {i.name for i in sess.get_inputs()}
            feed = {k: v.astype(np.int64) for k, v in enc.items() if k in names}
            return softmax(sess.run(None, feed)[0])
        d32 = float(np.abs(run(fp32) - pt).max())
        d8 = float(np.abs(run(out / "model.int8.onnx") - pt).max())
        id2label = {int(k): v for k, v in torch_model.config.id2label.items()}

    if d32 > 1e-2:
        raise SystemExit(f"fp32 ONNX deviates from PyTorch by {d32:.4f} (> 1e-2)")
    tok.backend_tokenizer.save(str(out / "tokenizer.json"))
    pos = positive_index(id2label)
    labels = ["benign", "injection"] if len(id2label) == 2 else [id2label[i] for i in sorted(id2label)]
    if len(id2label) == 2 and pos == 0:
        labels = ["injection", "benign"]
    cfg_path = out / "config.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    cfg.update(
        {
            "max_length": spec.max_length,
            "threshold": cfg.get("threshold", 0.5),
            "labels": labels,
            "base_model": base_model,
            "model_key": spec.key,
            "source_labels": {str(k): v for k, v in id2label.items()},
            "verification": {"max_abs_diff_fp32_vs_torch": round(d32, 6), "max_abs_diff_int8_vs_torch": round(d8, 6)},
        }
    )
    cfg_path.write_text(json.dumps(cfg, indent=2))
    size = (out / "model.int8.onnx").stat().st_size / 1e6
    print(f"wrote {out} | int8 {size:.0f} MB | fp32 vs torch {d32:.2e} | int8 vs torch {d8:.2e} | labels {labels}")
    shutil.rmtree(Path(tempfile.gettempdir()) / "onnx", ignore_errors=True)


if __name__ == "__main__":
    main()
