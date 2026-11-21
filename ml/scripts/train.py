"""Fine-tune a sequence classifier on data/{train,val}.jsonl.

    uv run python scripts/train.py --model minilm-l6 [--epochs 3] [--limit N]

Seed 42, early stopping on validation PR-AUC (patience 1), best checkpoint kept.
Runs on CUDA (Colab/Kaggle T4, fp16), Apple MPS, or CPU.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import replace

import numpy as np
import torch
from common import CHECKPOINTS, DATA, MODELS, SEED, load_jsonl
from datasets import Dataset
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
    set_seed,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=[k for k, m in MODELS.items() if not m.zero_shot])
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--limit", type=int, default=0, help="subsample train (quick experiments)")
    ap.add_argument("--batch-size", type=int, default=0)
    ap.add_argument("--hf-id", default="", help="override the base checkpoint (e.g. after selection)")
    ap.add_argument("--output-key", default="", help="checkpoint folder name (default: --model)")
    a = ap.parse_args()
    spec = MODELS[a.model]
    if a.hf_id:
        spec = replace(spec, hf_id=a.hf_id)
    out_key = a.output_key or spec.key
    set_seed(SEED)

    tok = AutoTokenizer.from_pretrained(spec.hf_id, use_fast=True)
    train_rows = load_jsonl(DATA / "train.jsonl")
    if a.limit:
        rng = np.random.default_rng(SEED)
        train_rows = [train_rows[i] for i in rng.choice(len(train_rows), a.limit, replace=False)]
    val_rows = load_jsonl(DATA / "val.jsonl")

    def to_ds(rows: list[dict]) -> Dataset:
        ds = Dataset.from_dict({"text": [r["text"] for r in rows], "label": [r["label"] for r in rows]})
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=spec.max_length), batched=True, remove_columns=["text"])

    train_ds, val_ds = to_ds(train_rows), to_ds(val_rows)
    model = AutoModelForSequenceClassification.from_pretrained(
        spec.hf_id, num_labels=2, id2label={0: "benign", 1: "injection"}, label2id={"benign": 0, "injection": 1}
    )

    def metrics(p: tuple[np.ndarray, np.ndarray]) -> dict[str, float]:
        logits, labels = p
        z = logits - logits.max(axis=1, keepdims=True)
        prob = np.exp(z)[:, 1] / np.exp(z).sum(axis=1)
        return {
            "pr_auc": float(average_precision_score(labels, prob)),
            "roc_auc": float(roc_auc_score(labels, prob)),
            "f1_at_0.5": float(f1_score(labels, prob >= 0.5)),
        }

    out = CHECKPOINTS / out_key
    cuda = torch.cuda.is_available()
    args = TrainingArguments(
        output_dir=str(out),
        num_train_epochs=a.epochs,
        learning_rate=spec.lr,
        per_device_train_batch_size=a.batch_size or spec.batch_size,
        per_device_eval_batch_size=64,
        warmup_ratio=0.06,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        load_best_model_at_end=True,
        metric_for_best_model="pr_auc",
        greater_is_better=True,
        fp16=cuda,
        group_by_length=True,
        logging_steps=50,
        report_to=[],
        seed=SEED,
        data_seed=SEED,
    )
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=DataCollatorWithPadding(tok),
        compute_metrics=metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=1)],
    )
    t0 = time.time()
    trainer.train()
    best = trainer.evaluate()
    final = out / "best"
    trainer.save_model(str(final))
    tok.save_pretrained(str(final))
    info = {
        "model": spec.key,
        "base": spec.hf_id,
        "epochs_run": trainer.state.epoch,
        "train_examples": len(train_rows),
        "device": "cuda" if cuda else "mps" if torch.backends.mps.is_available() else "cpu",
        "train_seconds": round(time.time() - t0),
        "val": {k: round(v, 4) for k, v in best.items() if isinstance(v, float)},
        "seed": SEED,
    }
    (final / "train_info.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
