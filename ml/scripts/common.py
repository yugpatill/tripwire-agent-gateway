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


def jsonl_lines(text: str) -> list[str]:
    """JSONL records: split on "\n" only. str.splitlines() also breaks on U+2028,
    U+2029, \x85 and \x1c-\x1e, which can sit unescaped inside a JSON string."""
    return [line for line in text.split("\n") if line.strip()]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in jsonl_lines(path.read_text(encoding="utf-8"))]


def dump_jsonl_line(record: dict[str, Any]) -> str:
    """One JSONL line. ensure_ascii escapes every non-ASCII character (U+2028 and
    friends included), so any line splitter reads the file back correctly."""
    return json.dumps(record, ensure_ascii=True) + "\n"


def artifact_dir(key: str) -> Path:
    return ARTIFACTS / f"injection-{key}"
