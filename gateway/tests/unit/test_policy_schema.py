from __future__ import annotations

import pytest

from tripwire.policy.loader import PolicyError, parse_policy

from .helpers import POLICIES


@pytest.mark.parametrize("name", ["default.yaml", "demo.yaml"])
def test_shipped_policies_validate(name: str) -> None:
    parse_policy((POLICIES / name).read_text())


def test_minimal_policy_gets_defaults() -> None:
    doc = parse_policy("version: 1\n")
    assert doc.defaults.unknown_tool == "require_approval"
    assert doc.defaults.on_engine_error == "block"


def test_engine_error_cannot_be_allow() -> None:
    with pytest.raises(PolicyError) as ei:
        parse_policy("version: 1\ndefaults:\n  on_engine_error: allow\n")
    err = ei.value.errors[0]
    assert err.loc == "defaults.on_engine_error"
    assert (err.line, err.column) == (3, 20)


def test_error_points_at_bad_rule_line() -> None:
    text = "version: 1\nrules:\n  - id: ok\n    action: allow\n  - id: bad\n    action: explode\n"
    with pytest.raises(PolicyError) as ei:
        parse_policy(text)
    err = ei.value.errors[0]
    assert err.loc == "rules.1.action"
    assert err.line == 6


def test_unknown_keys_rejected() -> None:
    with pytest.raises(PolicyError) as ei:
        parse_policy("version: 1\nrules:\n  - id: r\n    action: block\n    when: {tol: x}\n")
    assert "rules.0.when.tol" in ei.value.errors[0].loc


def test_duplicate_rule_ids_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy("version: 1\nrules:\n  - {id: a, action: block}\n  - {id: a, action: allow}\n")


def test_yaml_syntax_error_has_position() -> None:
    with pytest.raises(PolicyError) as ei:
        parse_policy("version: 1\nrules: [\n")
    assert ei.value.errors[0].line is not None


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(PolicyError):
        parse_policy(
            "version: 1\ndefaults: {classifier_threshold: 0.4, suspicious_threshold: 0.6}\n"
        )
