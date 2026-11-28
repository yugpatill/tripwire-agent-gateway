"""Policy APIs end to end: deploy with versions, test against recorded calls,
shadow mode, and the read-only demo account (live Postgres + Redis)."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, update

from tripwire.config import Settings
from tripwire.db import models as db
from tripwire.main import create_app
from tripwire.policy.service import MODE_KEY

DB_URL = os.environ.get("TRIPWIRE_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("TRIPWIRE_TEST_REDIS_URL")
POLICY = Path(__file__).parents[2] / "policies" / "demo.yaml"
ADMIN = f"admin-{uuid.uuid4().hex[:8]}@example.com"
PASSWORD = "correct horse battery staple"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (DB_URL and REDIS_URL), reason="live Postgres/Redis not configured"),
]


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(
        database_url=DB_URL or "",
        redis_url=REDIS_URL or "",
        tripwire_policy_path=str(POLICY),
        tripwire_classifier_dir="",
        jwt_secret=f"test-{uuid.uuid4()}",  # type: ignore[arg-type]
        admin_email=ADMIN,
        admin_password=PASSWORD,  # type: ignore[arg-type]
        log_json=False,
    )
    with TestClient(create_app(settings)) as c:
        factory = c.app.state.sessionmaker  # type: ignore[attr-defined]

        async def max_version() -> int:
            async with factory() as s:
                return int(await s.scalar(select(func.max(db.Policy.version))) or 0)

        start = c.portal.call(max_version)  # type: ignore[union-attr]
        try:
            yield c
        finally:
            # Leave the database as other tests expect: the file policy active.
            async def restore() -> None:
                async with factory() as s, s.begin():
                    await s.execute(delete(db.Policy).where(db.Policy.version > start))
                    await s.execute(
                        update(db.Policy).where(db.Policy.version == start).values(is_active=True)
                    )
                await c.app.state.redis.delete(MODE_KEY)  # type: ignore[attr-defined]

            c.portal.call(restore)  # type: ignore[union-attr]


def login(c: TestClient, demo: bool = False) -> None:
    if demo:
        creds = c.get("/v1/auth/demo").json()
        body = {"username": creds["username"], "password": creds["password"]}
    else:
        body = {"username": ADMIN, "password": PASSWORD}
    assert c.post("/v1/auth/login", json=body).status_code == 200


def test_demo_reads_but_cannot_change(client: TestClient) -> None:
    login(client, demo=True)
    active = client.get("/v1/policies/active").json()
    assert active["version"] >= 1 and "tools:" in active["yaml"]
    assert "properties" in client.get("/v1/policies/schema").json()
    assert client.get("/v1/policies/mode").json() == {"mode": "enforce"}
    assert client.put("/v1/policies/active", json={"yaml": active["yaml"]}).status_code == 403
    assert client.put("/v1/policies/mode", json={"mode": "shadow"}).status_code == 403


def test_invalid_policy_reports_line_and_column(client: TestClient) -> None:
    login(client)
    r = client.put(
        "/v1/policies/active", json={"yaml": "version: 1\ndefaults:\n  unknown_tool: maybe\n"}
    )
    assert r.status_code == 422
    (err,) = [e for e in r.json()["detail"]["errors"] if "unknown_tool" in e["loc"]]
    assert err["line"] == 3


def test_test_deploy_and_shadow_mode(client: TestClient) -> None:
    from tripwire.auth.api_keys import SqlKeyRepository

    repo = SqlKeyRepository(client.app.state.sessionmaker)  # type: ignore[attr-defined]
    key = client.portal.call(repo.create, "policy-it")  # type: ignore[union-attr]
    agent = {"Authorization": f"Bearer {key.token}"}
    sid = client.post(
        "/v1/sessions", json={"agent_name": "policy-it", "user_prompt": "hi"}, headers=agent
    ).json()["session_id"]
    tool = f"unlisted__tool_{uuid.uuid4().hex[:6]}"
    call = {"session_id": sid, "tool": tool, "args": {"x": "1"}}
    assert client.post("/v1/check/call", json=call, headers=agent).json()["action"] == (
        "require_approval"
    )

    login(client)
    current = client.get("/v1/policies/active").json()
    candidate = current["yaml"].replace("unknown_tool: require_approval", "unknown_tool: block")
    assert candidate != current["yaml"]

    result = client.post("/v1/policies/test", json={"yaml": candidate}).json()
    assert result["replayed"] >= 1 and result["since_hours"] == 168 and result["skipped"] >= 0
    (change,) = [c for c in result["changes"] if c["tool"] == tool]
    assert (change["old_action"], change["new_action"]) == ("require_approval", "block")

    deployed = client.put("/v1/policies/active", json={"yaml": candidate}).json()
    assert deployed["version"] == current["version"] + 1
    after = client.get("/v1/policies/active").json()
    assert after["version"] == deployed["version"] and after["created_by"] == ADMIN
    assert client.post("/v1/check/call", json=call, headers=agent).json()["action"] == "block"

    assert client.put("/v1/policies/mode", json={"mode": "shadow"}).json() == {"mode": "shadow"}
    r = client.post("/v1/check/call", json=call, headers=agent).json()
    assert r["action"] == "log_only"
    client.put("/v1/policies/mode", json={"mode": "enforce"})
    client.portal.call(repo.revoke, key.id)  # type: ignore[union-attr]


def test_evals_placeholder_until_imported(client: TestClient) -> None:
    assert client.get("/v1/evals").status_code == 401
    login(client, demo=True)
    body = client.get("/v1/evals").json()
    if body["placeholder"]:  # nothing imported into eval_runs yet (Phase 9)
        assert body["note"] and len(body["runs"]) == 24
        assert {r["model"] for r in body["runs"]} == {"placeholder"}
