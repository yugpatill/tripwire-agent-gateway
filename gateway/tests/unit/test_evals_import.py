"""evals/results JSON -> eval_runs rows."""

from __future__ import annotations

import pytest

from tripwire.evals_import import rows_from_result


def _block(k: int, n: int) -> dict[str, object]:
    return {"k": k, "n": n, "rate": round(k / n, 4), "ci95": [0.0, 1.0]}


def test_agentdojo_one_row_per_suite() -> None:
    data = {
        "benchmark": "v1.2.2",
        "attack": "important_instructions",
        "config": "A",
        "model": "claude-haiku-5-5",
        "by_suite": {
            "banking": {
                "utility": _block(10, 16),
                "utility_under_attack": _block(100, 144),
                "attack_success": _block(7, 144),
            },
            "slack": {
                "utility": _block(18, 21),
                "utility_under_attack": _block(80, 105),
                "attack_success": _block(3, 105),
            },
        },
    }
    rows = rows_from_result(data, "agentdojo_A.json")
    assert [(r["suite"], r["config"]) for r in rows] == [("banking", "A"), ("slack", "A")]
    m = rows[0]["metrics"]
    assert m["benchmark"] == "agentdojo" and m["asr"] == round(7 / 144, 4) and m["utility"] == 0.625
    assert m["tasks"] == 16 and m["attacked_cases"] == 144 and m["sample"] is False


def test_mcp_suite_and_adaptive_rows() -> None:
    mcp = {
        "summary": {
            "attacks_stopped": _block(28, 30),
            "attacks_stopped_excluding_known_gaps": _block(27, 27),
            "benign_passed": _block(15, 16),
            "benign_held": _block(1, 16),
        }
    }
    (row,) = rows_from_result(mcp, "mcp_suite.json")
    assert (
        row["suite"] == "mcp_suite"
        and row["config"] == "D"
        and row["metrics"]["asr"] == round(2 / 30, 4)
    )
    adaptive = {
        "attacker": "scripted",
        "max_tries": 10,
        "goals": 6,
        "by_guard": {
            "taint": {"succeeded": 0, "goals": 3},
            "detection": {"succeeded": 2, "goals": 2},
        },
    }
    (row,) = rows_from_result(adaptive, "adaptive_attacker.json")
    assert row["suite"] == "adaptive" and row["metrics"]["asr"] == round(2 / 6, 4)


def test_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError):
        rows_from_result({"hello": 1}, "x.json")
