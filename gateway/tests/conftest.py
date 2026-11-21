from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from tripwire.config import Settings
from tripwire.main import create_app


@pytest.fixture
def settings() -> Settings:
    # Unreachable backends: health must still work, readiness must report degraded.
    return Settings(
        database_url="postgresql+asyncpg://x:x@127.0.0.1:1/x",
        redis_url="redis://127.0.0.1:1/0",
        log_json=False,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c
