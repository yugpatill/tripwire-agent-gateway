"""Export an UNTRAINED DeBERTa-v3 classifier to int8 ONNX for latency measurement.

Random weights, real architecture: CPU latency depends on the architecture and
sequence length, not on the weights, so this lets the gateway measure its
classifier stage before the Phase 4 model exists. The output must never be used
for detection: config.json marks it with "untrained_latency_probe": true.

    uv run python scripts/latency_probe.py [--base microsoft/deberta-v3-small]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from onnxruntime.quantization import QuantType, quantize_dynamic
from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="microsoft/deberta-v3-small")
    ap.add_argument("--max-length", type=int, default=512)
    ap.add_argument("--keep-fp32", action="store_true", help="also keep model.fp32.onnx")
    a = ap.parse_args()

    out = ROOT / "artifacts" / f"latency-probe-{a.base.split('/')[-1]}"
    out.mkdir(parents=True, exist_ok=True)

    config = AutoConfig.from_pretrained(a.base, num_labels=2)
    tokenizer = AutoTokenizer.from_pretrained(a.base, use_fast=True)
    torch.manual_seed(42)
    model = AutoModelForSequenceClassification.from_config(config).eval()

    dummy = tokenizer("latency probe " * 20, return_tensors="pt")
    fp32 = out / "model.fp32.onnx"
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(fp32),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"}},
        opset_version=17,
        dynamo=False,
    )
    quantize_dynamic(str(fp32), str(out / "model.int8.onnx"), weight_type=QuantType.QInt8)
    if not a.keep_fp32:
        fp32.unlink()
        for extra in out.glob("*.data"):
            extra.unlink()
    tokenizer.backend_tokenizer.save(str(out / "tokenizer.json"))
    (out / "config.json").write_text(
        json.dumps(
            {
                "max_length": a.max_length,
                "threshold": 0.85,
                "labels": ["benign", "injection"],
                "untrained_latency_probe": True,
                "base_model": a.base,
            },
            indent=2,
        )
    )
    size = (out / "model.int8.onnx").stat().st_size / 1e6
    print(f"wrote {out} (model.int8.onnx {size:.0f} MB)")


if __name__ == "__main__":
    main()
