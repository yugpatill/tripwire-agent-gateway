# Tripwire ml/

Training for the gateway's prompt-injection classifier. A separate uv project: it never imports the gateway; the only interface is the artifact folder (see `docs/design.md`, section 4.3).

## Pipeline

| Script | What it does |
|---|---|
| `scripts/build_dataset.py` | Builds `data/{train,val,test,test_ood}.jsonl` from deepset/prompt-injections, Dolly-15k, SQuAD v2 and generated attacks/hard negatives. Split by group; `role_markers` held out as `test_ood`. |
| `scripts/preflight.py` | Fails fast: Python ≥ 3.12, torch in `>=2.5,<3`, exact pins, no diffusers/gradio, imports, tiny BERT and DeBERTa ONNX export, int8 quantization and run. |
| `scripts/train.py` | Fine-tunes (seed 42, early stopping on val PR-AUC). |
| `scripts/export_onnx.py` | Optimum ONNX export and dynamic int8 quantization into `artifacts/injection-<model>/`, with a check that fp32 ONNX matches PyTorch within 1e-2. |
| `scripts/evaluate.py` | Scores the int8 artifact exactly as the gateway does; threshold for 1% FPR on val benign; writes `metrics.json`. |
| `scripts/check_artifacts.py` | Checks every artifact folder against the contract, prints a summary, and builds `tripwire-artifacts.zip`. |
| `scripts/latency_probe.py` | Untrained int8 probes for latency benchmarks only. |

Training runs on a free Colab/Kaggle T4 with `notebooks/train_colab.ipynb`, not on a laptop.

## Colab requirements

`requirements-colab.txt` pins the same versions as `uv.lock`, with every transitive dependency, for Linux on Python 3.12+. torch and its CUDA/Triton wheels are left out so the runtime's GPU build of torch is kept. To regenerate it after changing `pyproject.toml`, put the top-level pins from `uv.lock` (plus `optimum[onnxruntime]` and `torch>=2.5,<3`) in a `.in` file, then:

```bash
uv pip compile colab.in --universal --python-version 3.12 --no-header --no-annotate --no-emit-package torch --no-emit-package triton -o requirements-colab.txt
```

Then delete any `nvidia-*` and `cuda-*` lines.

Colab and Kaggle preinstall diffusers and gradio, which need `huggingface_hub>=1`. Our transformers pin needs `<1.0`, and optimum's exporter imports diffusers when it is present, so the notebook uninstalls them first.

## Results

Comparison of MiniLM-L6, DeBERTa-v3-small and Prompt Guard 2 22M (zero-shot) and the default-model decision: pending the Phase 4 training run.
