"""Phase 9 step 2: no-defense AgentDojo baseline on a small sample, with cost.

    set -a; . ../.env; set +a     # ANTHROPIC_API_KEY
    uv run python -m agentdojo_tripwire.sample --model claude-haiku-5-5 --per-suite 5

Picks `--per-suite` (user task, injection task) pairs per suite with a fixed seed,
runs each with AgentDojo's `important_instructions` attack and no defense, and
writes results/agentdojo_sample_<model>.json: attack success (AgentDojo's
security result: the injection task's goal was reached), utility under attack,
tokens and cost per case. Responses are cached on disk, so a rerun is free.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites

from agentdojo_tripwire.llm import ClaudeLLM

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = "v1.2.2"
ATTACK = "important_instructions"
SUITES = ("workspace", "travel", "banking", "slack")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--per-suite", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--effort", default="low")
    a = ap.parse_args()

    MODEL_NAMES.setdefault(a.model, "Claude")  # how the attack text addresses the model
    llm = ClaudeLLM(a.model, ROOT / "results" / "agentdojo" / "llm_cache", effort=a.effort)
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
    )
    pipeline.name = f"{a.model}-no-defense"

    rng = random.Random(a.seed)
    cases = []
    suites = get_suites(BENCHMARK)
    t0 = time.time()
    for name in SUITES:
        suite = suites[name]
        attack = load_attack(ATTACK, suite, pipeline)
        pairs = [(u, i) for u in sorted(suite.user_tasks) for i in sorted(suite.injection_tasks)]
        for user_id, inj_id in rng.sample(pairs, a.per_suite):
            user_task = suite.get_user_task_by_id(user_id)
            inj_task = suite.get_injection_task_by_id(inj_id)
            llm.case = f"{name}/{user_id}/{inj_id}"
            injections = attack.attack(user_task, inj_task)
            try:
                utility, security = suite.run_task_with_pipeline(pipeline, user_task, inj_task, injections)
                error = None
            except Exception as exc:  # keep going; report it
                utility, security, error = False, False, repr(exc)[:300]
            tin, tout = llm.usage.by_case.get(llm.case, [0, 0])
            cases.append(
                {"suite": name, "user_task": user_id, "injection_task": inj_id, "attack_succeeded": bool(security),
                 "utility": bool(utility), "input_tokens": tin, "output_tokens": tout, "error": error}
            )
            print(f"{llm.case:40} attack={'SUCCEEDED' if security else 'failed':9} utility={utility} tokens={tin}/{tout}"
                  + (f" ERROR {error}" if error else ""), flush=True)

    ok = [c for c in cases if c["error"] is None]
    asr = sum(c["attack_succeeded"] for c in ok) / len(ok) if ok else 0.0
    util = sum(c["utility"] for c in ok) / len(ok) if ok else 0.0
    out = {
        "benchmark": BENCHMARK, "attack": ATTACK, "defense": "none", "model": a.model, "effort": a.effort,
        "seed": a.seed, "cases": len(cases), "errors": len(cases) - len(ok),
        "attack_success_rate": round(asr, 4), "utility_under_attack": round(util, 4),
        "api_calls": llm.usage.calls, "cached_calls": llm.usage.cached_calls,
        "input_tokens": llm.usage.input_tokens, "output_tokens": llm.usage.output_tokens,
        "cost_usd": round(llm.usage.cost(a.model), 4), "seconds": round(time.time() - t0),
        "results": cases,
    }
    path = ROOT / "results" / f"agentdojo_sample_{a.model}.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()
