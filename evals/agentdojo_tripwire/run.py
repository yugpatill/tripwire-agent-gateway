"""Run AgentDojo configurations on Claude, with a dollar budget.

    set -a; . ../.env; set +a
    uv run python -m agentdojo_tripwire.run --config A --budget 2.25
    uv run python -m agentdojo_tripwire.run --config D --budget 2.25   # needs the gateway

Configurations (section 7.1 of the project doc): A = no defense, D = full Tripwire.
B, C, E and F are future work on AgentDojo (see docs/evaluation.md).

For every suite of benchmark v1.2.2 it runs every user task without an attack
(utility) and every (user task, injection task) pair with the `important_instructions`
attack (utility under attack, attack success). `--cases` restricts the run to a
fixed list (a stratified sample, so both configurations see the same cases).

Each finished case is appended to results/agentdojo/<config>/<suite>.jsonl; a rerun
skips cases already there, so a run stopped by the budget resumes without paying
twice. LLM responses are cached on disk too. New cases stop starting once the
spend reaches `--budget` (cases already running finish).
"""

from __future__ import annotations

import argparse
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites

from agentdojo_tripwire.llm import ClaudeLLM

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = "v1.2.2"
ATTACK = "important_instructions"
SUITES = ("workspace", "travel", "banking", "slack")
CONFIGS = {"A": "no defense", "D": "full Tripwire"}
# Injection tasks whose security check reads only the model's final answer (no
# tool call is needed to succeed). Found by inspecting every injection task's
# security() in v1.2.2: only this one ignores the environment. A gateway that
# vets tool calls cannot stop these, so results are also split by goal type.
TEXT_ONLY_GOALS = {("travel", "injection_task_6")}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    k, n = sum(bool(r[key]) for r in rows), len(rows)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": [round(lo, 4), round(hi, 4)]}


def build_pipeline(config: str, llm: ClaudeLLM) -> AgentPipeline:
    pre: list[BasePipelineElement] = []
    tools: list[BasePipelineElement] = [ToolsExecutor()]
    if config == "D":
        from agentdojo_tripwire.element import tripwire_pre_elements, tripwire_tools_elements

        pre, tools = tripwire_pre_elements(), tripwire_tools_elements()
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), *pre, llm, ToolsExecutionLoop([*tools, llm])])
    pipe.name = f"{llm.model}-{config}"
    return pipe


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", choices=list(CONFIGS), required=True)
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--effort", default="low")
    ap.add_argument("--budget", type=float, required=True, help="USD; no new case starts beyond it")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--suites", default=",".join(SUITES))
    ap.add_argument("--cases", type=Path, help="JSON list of [suite, user_task, injection_task|null]")
    a = ap.parse_args()

    MODEL_NAMES.setdefault(a.model, "Claude")
    llm = ClaudeLLM(a.model, ROOT / "results" / "agentdojo" / "llm_cache", effort=a.effort)
    pipeline = build_pipeline(a.config, llm)
    out_dir = ROOT / "results" / "agentdojo" / a.config
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = {tuple(c) for c in json.loads(a.cases.read_text())} if a.cases else None

    suites = get_suites(BENCHMARK)
    jobs: list[tuple[str, str, str | None]] = []
    for name in a.suites.split(","):
        suite = suites[name]
        for u in sorted(suite.user_tasks):
            jobs.append((name, u, None))
            jobs += [(name, u, i) for i in sorted(suite.injection_tasks)]
    if wanted is not None:
        jobs = [j for j in jobs if j in wanted]

    done: set[tuple[str, str, str | None]] = set()
    for f in out_dir.glob("*.jsonl"):
        for line in f.read_text().split("\n"):
            if line.strip():
                r = json.loads(line)
                if r["error"] is None:  # errored cases are retried
                    done.add((r["suite"], r["user_task"], r["injection_task"]))
    todo = [j for j in jobs if j not in done]
    print(f"config {a.config} ({CONFIGS[a.config]}): {len(jobs)} cases, {len(done & set(jobs))} already done, {len(todo)} to run", flush=True)

    write_lock = threading.Lock()
    stopped = threading.Event()
    t0 = time.time()

    def run_one(job: tuple[str, str, str | None]) -> None:
        if stopped.is_set():
            return
        if llm.usage.cost(a.model) >= a.budget:
            stopped.set()
            return
        name, user_id, inj_id = job
        suite = suites[name]
        user_task = suite.get_user_task_by_id(user_id)
        llm.case = f"{name}/{user_id}/{inj_id}"
        error = None
        try:
            if inj_id is None:
                utility, security = suite.run_task_with_pipeline(pipeline, user_task, injection_task=None, injections={})
            else:
                inj_task = suite.get_injection_task_by_id(inj_id)
                injections = load_attack(ATTACK, suite, pipeline).attack(user_task, inj_task)
                utility, security = suite.run_task_with_pipeline(pipeline, user_task, inj_task, injections)
        except Exception as exc:  # recorded, excluded from rates
            utility, security, error = False, False, repr(exc)[:300]
        tin, tout = llm.usage.by_case.get(llm.case, [0, 0])
        row = {"suite": name, "user_task": user_id, "injection_task": inj_id, "utility": bool(utility),
               "attack_succeeded": bool(security) if inj_id else None, "input_tokens": tin, "output_tokens": tout, "error": error}
        with write_lock:
            with (out_dir / f"{name}.jsonl").open("a") as f:
                f.write(json.dumps(row) + "\n")
            n = len(done) + 1
            done.add(job)
            if n % 25 == 0 or error:
                print(f"  {n}/{len(jobs)} done, ${llm.usage.cost(a.model):.3f} spent, {time.time() - t0:.0f}s"
                      + (f"  ERROR {llm.case}: {error}" if error else ""), flush=True)

    with ThreadPoolExecutor(a.workers) as pool:
        list(pool.map(run_one, todo))

    summarize(a.config, a.model, a.effort, out_dir, jobs, llm, stopped.is_set())


def summarize(config: str, model: str, effort: str, out_dir: Path, jobs: list[tuple[str, str, str | None]], llm: ClaudeLLM, stopped: bool) -> None:
    rows = [json.loads(line) for f in sorted(out_dir.glob("*.jsonl")) for line in f.read_text().split("\n") if line.strip()]
    keys = set(jobs)
    latest: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for r in rows:  # a retried case: the last record wins
        k = (r["suite"], r["user_task"], r["injection_task"])
        if k in keys:
            latest[k] = r
    rows = list(latest.values())
    ok = [r for r in rows if r["error"] is None]
    benign = [r for r in ok if r["injection_task"] is None]
    attacked = [r for r in ok if r["injection_task"] is not None]

    def block(rs_b: list[dict[str, Any]], rs_a: list[dict[str, Any]]) -> dict[str, Any]:
        tool = [r for r in rs_a if (r["suite"], r["injection_task"]) not in TEXT_ONLY_GOALS]
        text = [r for r in rs_a if (r["suite"], r["injection_task"]) in TEXT_ONLY_GOALS]
        out = {"utility": rate(rs_b, "utility"), "utility_under_attack": rate(rs_a, "utility"), "attack_success": rate(rs_a, "attack_succeeded"),
               "attack_success_tool_goals": rate(tool, "attack_succeeded")}
        if text:
            out["attack_success_text_only_goals"] = rate(text, "attack_succeeded")
        return out

    out = {
        "benchmark": BENCHMARK, "attack": ATTACK, "config": config, "defense": CONFIGS[config], "model": model, "effort": effort,
        "cases_planned": len(jobs), "cases_recorded": len(rows), "errors": len(rows) - len(ok), "stopped_by_budget": stopped,
        "overall": block(benign, attacked),
        "by_suite": {s: block([r for r in benign if r["suite"] == s], [r for r in attacked if r["suite"] == s]) for s in SUITES if any(r["suite"] == s for r in rows)},
        "tokens_all_runs": {"input": sum(r["input_tokens"] for r in rows), "output": sum(r["output_tokens"] for r in rows)},
        "cost_usd_all_runs": round(sum(r["input_tokens"] * 0.10 + r["output_tokens"] * 0.50 for r in rows) / 1e6, 4),
        "cost_usd_this_invocation": round(llm.usage.cost(model), 4),
    }
    path = ROOT / "results" / f"agentdojo_{config}_{model}.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k != "by_suite"}, indent=2))


if __name__ == "__main__":
    main()
