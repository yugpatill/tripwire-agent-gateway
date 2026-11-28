"""Import evaluation results (evals/results/*.json) into the `eval_runs` table.

    tripwire evals import evals/results/agentdojo_A_claude-haiku-5-5.json \
        evals/results/mcp_suite.json ...

The gateway never imports the evals project; it only reads its JSON files. Each
file becomes one or more rows (suite, config, model, metrics). AgentDojo results
give one row per suite with `benchmark: agentdojo`; the MCP suite and the adaptive
attacker give one row each, against configuration D (the full Tripwire policy).
Importing a file again adds newer rows; the console shows the newest per suite and
configuration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _r(block: dict[str, Any]) -> float | None:
    v = block.get("rate")
    return float(v) if v is not None else None


def rows_from_result(data: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """Rows for one results file; raises ValueError for an unknown format."""
    if data.get("benchmark", "").startswith("v1.") and "by_suite" in data:
        rows = []
        for suite, b in data["by_suite"].items():
            rows.append(
                {
                    "suite": suite,
                    "config": data["config"],
                    "model": data["model"],
                    "metrics": {
                        "benchmark": "agentdojo",
                        "benchmark_version": data["benchmark"],
                        "attack": data["attack"],
                        "asr": _r(b["attack_success"]),
                        "asr_ci95": b["attack_success"]["ci95"],
                        "utility": _r(b["utility"]),
                        "utility_ci95": b["utility"]["ci95"],
                        "utility_under_attack": _r(b["utility_under_attack"]),
                        "utility_under_attack_ci95": b["utility_under_attack"]["ci95"],
                        "tasks": b["utility"]["n"],
                        "attacked_cases": b["attack_success"]["n"],
                        "sample": bool(data.get("sample", False)),
                    },
                    "source_file": source,
                }
            )
        return rows
    if "summary" in data and "attacks_stopped" in data.get("summary", {}):
        s = data["summary"]
        stopped, benign = s["attacks_stopped"], s["benign_passed"]
        return [
            {
                "suite": "mcp_suite",
                "config": "D",
                "model": "scripted agent",
                "metrics": {
                    "benchmark": "mcp_suite",
                    "asr": round(1 - stopped["rate"], 4) if stopped["rate"] is not None else None,
                    "attacks_stopped": stopped,
                    "attacks_stopped_excluding_known_gaps": s[
                        "attacks_stopped_excluding_known_gaps"
                    ],
                    "utility": benign["rate"],
                    "benign_passed": benign,
                    "benign_held": s["benign_held"],
                    "tasks": stopped["n"] + benign["n"],
                },
                "source_file": source,
            }
        ]
    if "by_guard" in data and "attacker" in data:
        goals = data["goals"]
        won = sum(g["succeeded"] for g in data["by_guard"].values())
        return [
            {
                "suite": "adaptive",
                "config": "D",
                "model": "scripted agent and attacker",
                "metrics": {
                    "benchmark": "adaptive",
                    "asr": round(won / goals, 4) if goals else None,
                    "by_guard": data["by_guard"],
                    "max_tries": data["max_tries"],
                    "tasks": goals,
                },
                "source_file": source,
            }
        ]
    raise ValueError(f"{source}: not an AgentDojo, MCP suite or adaptive attacker result")


def load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in paths:
        rows += rows_from_result(json.loads(p.read_text(encoding="utf-8")), p.name)
    return rows
