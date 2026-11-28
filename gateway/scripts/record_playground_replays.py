"""Record one replay per preset into src/tripwire/playground/replays/<id>.json.

    uv run python scripts/record_playground_replays.py                      # scripted model
    ANTHROPIC_API_KEY=... uv run python scripts/record_playground_replays.py \
        --provider anthropic [--model claude-haiku-5-5]                      # real model

Runs in memory (no Postgres/Redis) under the demo policy, with the classifier
from TRIPWIRE_CLASSIFIER_DIR when it is available, like the live playground.
Each fixture records its source ("scripted" or "live") and the model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from tripwire.main import load_active_policy
from tripwire.pipeline.classifier import InjectionClassifier
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.recorder import MemoryRecorder
from tripwire.playground.runner import PlaygroundConfig, PlaygroundRunner
from tripwire.playground.scenarios import presets
from tripwire.playground.store import (
    REPLAY_DIR,
    MemoryLimits,
    MemoryRunEvents,
    MemoryRunStore,
    replay_id,
    replay_path,
)
from tripwire.taint.store import InMemoryTaintStore

POLICY = Path(__file__).resolve().parents[1] / "policies" / "demo.yaml"


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["scripted", "anthropic", "openai"], default="scripted")
    ap.add_argument("--model", default="")
    ap.add_argument("--only", nargs="*", help="scenario ids (default: all presets)")
    a = ap.parse_args()

    clf_dir = os.environ.get("TRIPWIRE_CLASSIFIER_DIR", "")
    classifier = InjectionClassifier(clf_dir) if clf_dir else None
    detection = DetectionPipeline(classifier=classifier)
    engine = Engine(
        InMemoryTaintStore(), MemoryRecorder(), load_active_policy(str(POLICY)), detection=detection
    )
    live = a.provider != "scripted"
    key = os.environ.get("ANTHROPIC_API_KEY" if a.provider == "anthropic" else "OPENAI_API_KEY", "")
    if live and not key:
        sys.exit(f"set the API key for {a.provider}")
    config = PlaygroundConfig(
        provider="openai" if a.provider == "openai" else "anthropic",
        model=a.model,
        api_key=key,
    )
    runner = PlaygroundRunner(
        engine, detection, MemoryRunStore(), MemoryRunEvents(), MemoryLimits(), config
    )
    REPLAY_DIR.mkdir(parents=True, exist_ok=True)
    failures = 0
    for sc in presets().values():
        if a.only and sc.id not in a.only:
            continue
        variant = "live" if live else "scripted"
        rid = replay_id(sc.id, variant)
        record = await runner.execute(rid, sc, variant)
        record["recorded_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        record["replay"] = True
        record["classifier"] = bool(classifier and classifier.available)
        path = replay_path(sc.id, variant)
        path.write_text(json.dumps(record, indent=1, ensure_ascii=False, default=str) + "\n")
        v = record["verdict"]
        ok = v["attack_succeeded_unprotected"] and not v["attack_succeeded_protected"]
        failures += not ok
        u = record["usage"]
        sides = record["sides"]
        print(
            f"{sc.id:20} {record['model']['source']:24} "
            f"unprotected_attack={v['attack_succeeded_unprotected']!s:5} "
            f"protected_attack={v['attack_succeeded_protected']!s:5} "
            f"stops={sides['unprotected']['stop']}/{sides['protected']['stop']} "
            f"tokens={u['input_tokens']}in/{u['output_tokens']}out cost=${u['cost_usd']} "
            f"rules={v['rules_fired_protected']} -> {path.name}"
        )
    return 1 if failures and not live else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
