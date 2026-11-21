from __future__ import annotations

from fastapi.testclient import TestClient

from tripwire.config import Settings
from tripwire.db.models import Base


def test_healthz_ok(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_degraded_without_backends(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"] == {"database": False, "redis": False}


def test_openapi_exposes_health(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/healthz" in paths and "/readyz" in paths


def test_cors_origins_parse_comma_list() -> None:
    s = Settings(cors_origins="http://a.test, http://b.test")  # type: ignore[arg-type]
    assert s.cors_origins == ["http://a.test", "http://b.test"]


def test_schema_has_all_phase1_tables() -> None:
    expected = {
        "sessions",
        "events",
        "approvals",
        "tool_pins",
        "policies",
        "eval_runs",
        "api_keys",
        "users",
    }
    assert expected <= set(Base.metadata.tables)
