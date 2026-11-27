from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from tests import scenario
from tripwire_guard import Guard

LIVE = bool(os.environ.get("TRIPWIRE_URL") and os.environ.get("TRIPWIRE_API_KEY"))


@pytest.fixture(autouse=True)
def _reset_sent() -> Iterator[None]:
    scenario.SENT.clear()
    yield
    scenario.SENT.clear()


@pytest.fixture
def live_guard() -> Iterator[Guard]:
    """A guard on a running gateway (one fresh session per test)."""
    if not LIVE:
        pytest.skip("set TRIPWIRE_URL and TRIPWIRE_API_KEY to run against a gateway")
    g = Guard(agent_name="sdk-test", user_prompt=scenario.USER_PROMPT)
    yield g
    g.close()
