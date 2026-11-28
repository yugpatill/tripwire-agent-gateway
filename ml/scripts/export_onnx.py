"""Export a fine-tuned (or zero-shot) model to the gateway's artifact contract.

    uv run python scripts/export_onnx.py --model minilm-l6

Writes artifacts/injection-<key>/: model.int8.onnx, tokenizer.json, config.json
(threshold filled in later by evaluate.py). Exports with Optimum, verifies fp32 ONNX
vs PyTorch probabilities agree within 1e-2, then applies dynamic int8 quantization.

Quantization (Phase 9): DeBERTa-v3-small lost accuracy under default dynamic int8
(max probability difference 0.98 vs PyTorch; MiniLM 0.006). The settings below are
tried in order on 256 validation texts and the first whose int8 probabilities stay
within INT8_MAX_DIFF of PyTorch is kept:

1. default: every supported op (the Phase 4 setting);
2. per-channel: every supported op, per-channel weight scales;
3. no-attention: per-channel, attention MatMuls left in fp32;
4. matmul: MatMul only, per-channel (embedding lookups stay fp32, so a larger file);
5. matmul-ffn: MatMul only, per-channel, attention MatMuls left in fp32.

If none passes, the closest one is kept and config.json records int8_ok: false;
check_artifacts.py and the release gate refuse such an artifact for publishing.
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
INT8_MAX_DIFF = 0.05
VERIFY_TEXTS = 256


def quantize_variants(fp32: Path) -> list[tuple[str, dict[str, object]]]:
    import onnx

    attention = [n.name for n in onnx.load(str(fp32), load_external_data=False).graph.node if n.op_type == "MatMul" and "attention" in n.name.lower()]
    return [
        ("default", {}),
        ("per-channel", {"per_channel": True}),
        ("no-attention", {"per_channel": True, "nodes_to_exclude": attention}),
        # Embedding lookups stay fp32 from here on: DeBERTa-v3's 128k-token table makes the file ~470 MB.
        ("matmul", {"op_types_to_quantize": ["MatMul"], "per_channel": True}),
        ("matmul-ffn", {"op_types_to_quantize": ["MatMul"], "per_channel": True, "nodes_to_exclude": attention}),
    ]


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
        # Verification on real validation texts.
        texts = [r["text"] for r in load_jsonl(DATA / "val.jsonl")[:VERIFY_TEXTS]]
        # One text at a time, like the gateway (no padding; dynamic int8 scales per input).
        encs = [tok(t, truncation=True, max_length=spec.max_length, return_tensors="np") for t in texts]
        torch_model = AutoModelForSequenceClassification.from_pretrained(src).eval()
        with torch.inference_mode():
            pt = np.concatenate([softmax(torch_model(**{k: torch.tensor(v) for k, v in e.items()}).logits.numpy()) for e in encs])
        def run(path: Path) -> np.ndarray:
            sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            names = {i.name for i in sess.get_inputs()}
            return np.concatenate([softmax(sess.run(None, {k: v.astype(np.int64) for k, v in e.items() if k in names})[0]) for e in encs])
        d32 = float(np.abs(run(fp32) - pt).max())
        tried: dict[str, float] = {}
        best: tuple[float, str] | None = None
        for name, kw in quantize_variants(fp32):
            cand = Path(tmp) / f"model.{name}.int8.onnx"
            quantize_dynamic(str(fp32), str(cand), weight_type=QuantType.QInt8, **kw)  # type: ignore[arg-type]
            tried[name] = round(float(np.abs(run(cand) - pt).max()), 6)
            print(f"  int8 {name}: max |p_int8 - p_torch| = {tried[name]:.4f}", flush=True)
            if best is None or tried[name] < best[0]:
                best = (tried[name], name)
                shutil.copyfile(cand, out / "model.int8.onnx")
            if tried[name] < INT8_MAX_DIFF:
                break
        assert best is not None
        d8, strategy = best
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
            "verification": {
                "texts": len(texts),
                "max_abs_diff_fp32_vs_torch": round(d32, 6),
                "max_abs_diff_int8_vs_torch": round(d8, 6),
                "int8_strategy": strategy,
                "int8_tried": tried,
                "int8_max_allowed": INT8_MAX_DIFF,
            },
            "int8_ok": d8 < INT8_MAX_DIFF,
        }
    )
    cfg_path.write_text(json.dumps(cfg, indent=2))
    size = (out / "model.int8.onnx").stat().st_size / 1e6
    print(f"wrote {out} | int8 {size:.0f} MB ({strategy}) | fp32 vs torch {d32:.2e} | int8 vs torch {d8:.2e} | labels {labels}")
    if d8 >= INT8_MAX_DIFF:
        print(f"WARNING: no int8 setting kept {spec.key} within {INT8_MAX_DIFF} of PyTorch; config.json has int8_ok: false")
    shutil.rmtree(Path(tempfile.gettempdir()) / "onnx", ignore_errors=True)


if __name__ == "__main__":
    main()
