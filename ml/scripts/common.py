"""Shared settings for the ml/ scripts (never imported by the gateway)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CHECKPOINTS = ROOT / "checkpoints"
ARTIFACTS = ROOT / "artifacts"
OVERLAP_TOKENS = 64  # must match gateway/src/tripwire/pipeline/classifier.py
SEED = 42


@dataclass(frozen=True)
class ModelSpec:
    key: str
    hf_id: str
    max_length: int
    lr: float
    batch_size: int
    zero_shot: bool = False
    license: str = ""


MODELS: dict[str, ModelSpec] = {
    "minilm-l6": ModelSpec("minilm-l6", "nreimers/MiniLM-L6-H384-uncased", 512, 5e-5, 32, license="MIT"),
    "minilm-l6-st": ModelSpec("minilm-l6-st", "sentence-transformers/all-MiniLM-L6-v2", 512, 5e-5, 32, license="Apache-2.0"),
    "deberta-v3-small": ModelSpec("deberta-v3-small", "microsoft/deberta-v3-small", 512, 3e-5, 16, license="MIT"),
    "prompt-guard-2-22m": ModelSpec(
        "prompt-guard-2-22m", "meta-llama/Llama-Prompt-Guard-2-22M", 512, 0, 0, zero_shot=True, license="Llama 4 Community License"
    ),
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def artifact_dir(key: str) -> Path:
    return ARTIFACTS / f"injection-{key}"
