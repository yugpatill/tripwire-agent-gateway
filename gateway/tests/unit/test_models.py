from __future__ import annotations

import pytest

from tripwire.models import (
    ACTION_PRECEDENCE,
    CONFIDENTIALITY_ORDER,
    TRUST_ORDER,
    max_confidentiality,
)


def test_trust_ordering() -> None:
    ordered = sorted(TRUST_ORDER, key=TRUST_ORDER.__getitem__)
    assert ordered == ["trusted", "untrusted", "untrusted_origin", "suspicious"]


def test_confidentiality_ordering() -> None:
    ordered = sorted(CONFIDENTIALITY_ORDER, key=CONFIDENTIALITY_ORDER.__getitem__)
    assert ordered == ["public", "internal", "confidential", "secret"]


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("public", "secret", "secret"),
        ("confidential", "internal", "confidential"),
        ("internal", "internal", "internal"),
    ],
)
def test_max_confidentiality(a: str, b: str, expected: str) -> None:
    assert max_confidentiality(a, b) == expected  # type: ignore[arg-type]


def test_action_precedence_block_highest() -> None:
    assert max(ACTION_PRECEDENCE, key=ACTION_PRECEDENCE.__getitem__) == "block"
    assert (
        ACTION_PRECEDENCE["require_approval"]
        > ACTION_PRECEDENCE["redact"]
        > ACTION_PRECEDENCE["allow"]
    )
