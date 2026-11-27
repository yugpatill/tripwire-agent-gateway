"""Fail fast before training: environment, pins, imports, and a tiny ONNX export.

    python scripts/preflight.py

Runs in seconds. Exits non-zero with a clear message on any problem, so the
notebook stops before spending an hour on training that cannot be exported.
"""

from __future__ import annotations

import importlib.metadata as md
import importlib.util
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFLICTING = ("diffusers", "gradio", "gradio_client")
KEY_PACKAGES = (
    "transformers", "tokenizers", "huggingface-hub", "optimum", "onnxruntime", "onnx",
    "datasets", "accelerate", "scikit-learn", "numpy",
)


def fail(msg: str) -> None:
    print(f"\nPREFLIGHT FAILED: {msg}", flush=True)
    raise SystemExit(1)


def ok(msg: str) -> None:
    print(f"  ok  {msg}", flush=True)


def main() -> None:
    print("Preflight", flush=True)
    if sys.version_info < (3, 12):
        fail(f"Python {sys.version.split()[0]} found; the pinned numpy needs Python 3.12+")
    ok(f"Python {sys.version.split()[0]}")

    import torch

    v = tuple(int(x) for x in re.findall(r"\d+", torch.__version__)[:2])
    if not ((2, 5) <= v < (3, 0)):
        fail(f"torch {torch.__version__} is outside the ml/ pin >=2.5,<3")
    ok(f"torch {torch.__version__}, CUDA available: {torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        print("  warn  no GPU: training will be very slow (Runtime > Change runtime type > T4 GPU)", flush=True)

    pins = {}
    for line in (ROOT / "requirements-colab.txt").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==([^\s;]+)", line)
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    for name in KEY_PACKAGES:
        try:
            installed = md.version(name)
        except md.PackageNotFoundError:
            fail(f"{name} is not installed; run the install cell")
        if pins.get(name) and installed != pins[name]:
            fail(f"{name}=={installed} installed but requirements-colab.txt pins {pins[name]}")
    ok("pinned versions installed: " + ", ".join(f"{n}=={md.version(n)}" for n in KEY_PACKAGES))

    present = [p for p in CONFLICTING if importlib.util.find_spec(p) is not None]
    if present:
        fail(f"{', '.join(present)} installed: they need huggingface_hub>=1 and break optimum's exporter; uninstall them")
    ok("no conflicting packages (diffusers, gradio)")

    try:
        import optimum.exporters.onnx.model_patcher  # noqa: F401  (imports diffusers if present)
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import (
            AutoModelForSequenceClassification,
            BertConfig,
            BertForSequenceClassification,
            DebertaV2Config,
            DebertaV2ForSequenceClassification,
            Trainer,  # noqa: F401
        )
        import datasets  # noqa: F401
        import onnxruntime as ort
        from onnxruntime.quantization import QuantType, quantize_dynamic
        import sklearn  # noqa: F401
        import tokenizers  # noqa: F401
    except Exception as exc:  # report the real import error
        fail(f"import failed: {exc!r}")
    ok("imports: optimum exporter + onnxruntime, transformers Trainer, datasets, sklearn, tokenizers")

    import numpy as np

    tiny = {
        "bert": (BertConfig, BertForSequenceClassification, {}),
        "deberta-v2": (DebertaV2Config, DebertaV2ForSequenceClassification, {"relative_attention": True, "position_buckets": 32, "pos_att_type": ["p2c", "c2p"]}),
    }
    for name, (cfg_cls, model_cls, extra) in tiny.items():
        with tempfile.TemporaryDirectory() as tmp:
            cfg = cfg_cls(vocab_size=128, hidden_size=32, num_hidden_layers=2, num_attention_heads=2, intermediate_size=64, max_position_embeddings=128, num_labels=2, **extra)
            src = Path(tmp) / "src"
            model_cls(cfg).save_pretrained(src)
            try:
                m = ORTModelForSequenceClassification.from_pretrained(str(src), export=True)
                m.save_pretrained(Path(tmp) / "onnx")
                q = Path(tmp) / "model.int8.onnx"
                quantize_dynamic(str(Path(tmp) / "onnx" / "model.onnx"), str(q), weight_type=QuantType.QInt8)
                sess = ort.InferenceSession(str(q), providers=["CPUExecutionProvider"])
                feed = {"input_ids": np.array([[1, 5, 7, 2]], np.int64), "attention_mask": np.ones((1, 4), np.int64)}
                if "token_type_ids" in {i.name for i in sess.get_inputs()}:
                    feed["token_type_ids"] = np.zeros((1, 4), np.int64)
                out = sess.run(None, feed)[0]
            except Exception as exc:
                fail(f"tiny {name} ONNX export/quantize/run failed: {exc!r}")
            if out.shape != (1, 2):
                fail(f"tiny {name} export produced logits of shape {out.shape}, expected (1, 2)")
        ok(f"tiny {name} model: Optimum ONNX export, int8 quantization and onnxruntime run")
    del AutoModelForSequenceClassification
    print("\nPreflight passed.", flush=True)


if __name__ == "__main__":
    main()
