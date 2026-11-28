"""Console sign-in end to end (live Postgres + Redis)."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tripwire.config import Settings
from tripwire.main import create_app

DB_URL = os.environ.get("TRIPWIRE_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("TRIPWIRE_TEST_REDIS_URL")
POLICY = Path(__file__).parents[2] / "policies" / "demo.yaml"
ADMIN = f"admin-{uuid.uuid4().hex[:8]}@example.com"

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
        admin_password="correct horse battery staple",  # type: ignore[arg-type]
        log_json=False,
    )
    with TestClient(create_app(settings)) as c:
        yield c


def _login(c: TestClient, user: str, pw: str) -> int:
    return c.post("/v1/auth/login", json={"username": user, "password": pw}).status_code


def test_login_me_logout(client: TestClient) -> None:
    assert client.get("/v1/auth/me").status_code == 401
    assert _login(client, ADMIN, "wrong") == 401
    assert _login(client, ADMIN, "correct horse battery staple") == 200
    me = client.get("/v1/auth/me").json()
    assert me == {"username": ADMIN, "role": "admin", "can_write": True}
    assert client.get("/v1/approvals").status_code == 200
    client.post("/v1/auth/logout")
    assert client.get("/v1/auth/me").status_code == 401


def test_demo_account_is_public_and_read_only(client: TestClient) -> None:
    demo = client.get("/v1/auth/demo").json()
    assert demo["username"] == "demo"
    assert _login(client, demo["username"], demo["password"]) == 200
    assert client.get("/v1/auth/me").json()["can_write"] is False
    assert client.get("/v1/approvals").status_code == 200
    assert client.get("/v1/tools").status_code == 200
    r = client.post(f"/v1/approvals/{uuid.uuid4()}", json={"decision": "approve"})
    assert r.status_code == 403
    assert client.post("/v1/tools/x__y/approve").status_code == 403
    with client.websocket_connect("/v1/stream") as ws:
        assert ws.receive_json()["role"] == "readonly"


def test_console_read_api_redacts_secrets(client: TestClient) -> None:
    from tripwire.auth.api_keys import SqlKeyRepository

    repo = SqlKeyRepository(client.app.state.sessionmaker)  # type: ignore[attr-defined]
    key = client.portal.call(repo.create, "console-it")  # type: ignore[union-attr]
    agent = {"Authorization": f"Bearer {key.token}"}
    secret = "AKIA" + "ABCDEFGHIJKLMNOP"
    sid = client.post(
        "/v1/sessions",
        json={"agent_name": "console-it", "user_prompt": "save a note"},
        headers=agent,
    ).json()["session_id"]
    r = client.post(
        "/v1/check/call",
        json={
            "session_id": sid,
            "tool": "files__write_file",
            "args": {"path": "/tmp/n.txt", "content": f"key={secret}"},
        },
        headers=agent,
    )
    assert r.status_code == 200
    demo = client.get("/v1/auth/demo").json()
    assert _login(client, demo["username"], demo["password"]) == 200
    page = client.get("/v1/events", params={"session_id": sid}).json()
    (event,) = page["items"]
    assert secret not in str(event) and "[REDACTED" in event["payload"]["args"]["content"]
    trace = client.get(f"/v1/sessions/{sid}/trace").json()
    assert trace["session"]["agent_name"] == "console-it" and len(trace["events"]) == 1
    summary = client.get("/v1/metrics/summary", params={"hours": 1}).json()
    assert summary["totals"] and summary["sessions"] >= 1
    sessions = client.get("/v1/sessions", params={"limit": 5}).json()
    assert any(s["id"] == sid for s in sessions)
    client.post("/v1/auth/logout")
    assert client.get("/v1/events").status_code == 401
    client.portal.call(repo.revoke, key.id)  # type: ignore[union-attr]
