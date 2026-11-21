"""Keep docs/policy-test-coverage.md honest."""

from __future__ import annotations

import re
from pathlib import Path

from tripwire.policy.schema import RuleWhen

ROOT = Path(__file__).resolve().parents[3]
DOC = ROOT / "docs" / "policy-test-coverage.md"
TESTS = ROOT / "gateway" / "tests"


def _rows() -> dict[str, set[str]]:
    rows: dict[str, set[str]] = {}
    for line in DOC.read_text().splitlines():
        m = re.match(r"\|\s*(.+?)\s*\|\s*(.+?)\s*\|$", line)
        if m and "test_" in m.group(2):
            rows[m.group(1).strip("`")] = set(re.findall(r"`(test_\w+)`", m.group(2)))
    return rows


def test_every_schema_condition_has_a_row() -> None:
    rows = _rows()
    required = set(RuleWhen.model_fields) | {"unless.arg_domain_in", "limit", "shadow mode"}
    missing = required - set(rows)
    assert not missing, f"no coverage row for {sorted(missing)}"
    assert all(rows[k] for k in required)


def test_every_listed_test_exists() -> None:
    defined = {
        m
        for f in TESTS.rglob("test_*.py")
        for m in re.findall(r"^(?:async )?def (test_\w+)", f.read_text(), re.M)
    }
    listed = set().union(*_rows().values())
    assert listed - defined == set()
