from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from tripwire.auth.api_keys import (
    ApiKeyAuthenticator,
    KeyRecord,
    generate_token,
    hash_token,
    parse_prefix,
    verify_hash,
)
from tripwire.config import Settings
from tripwire.main import create_app
from tripwire.models import SessionCreate

from .helpers import call, make_engine, session


class FakeRepo:
    def __init__(self) -> None:
        self.records: list[KeyRecord] = []
        self.lookups = 0
        self.touched: list[uuid.UUID] = []

    def add(self, name: str, revoked: bool = False) -> tuple[str, KeyRecord]:
        token, prefix = generate_token()
        rec = KeyRecord(uuid.uuid4(), name, prefix, hash_token(token), revoked)
        self.records.append(rec)
        return token, rec

    async def by_prefix(self, prefix: str) -> list[KeyRecord]:
        self.lookups += 1
        return [r for r in self.records if r.prefix == prefix]

    async def touch(self, key_id: uuid.UUID) -> None:
        self.touched.append(key_id)


def test_token_format_and_prefix() -> None:
    token, prefix = generate_token()
    assert token.startswith(f"tw_{prefix}_") and len(prefix) == 8
    assert parse_prefix(token) == prefix
    for bad in ["", "tw_", "sk_abc", "tw_short_x", f"tw_{prefix}", f"tw_{prefix}_tooShort"]:
        assert parse_prefix(bad) is None


def test_hash_is_argon2_and_verifies() -> None:
    token, _ = generate_token()
    h = hash_token(token)
    assert h.startswith("$argon2id$") and token not in h
    assert verify_hash(h, token)
    assert not verify_hash(h, token + "x")
    assert not verify_hash("not-a-hash", token)


async def test_authenticate_valid_then_cached() -> None:
    repo = FakeRepo()
    token, rec = repo.add("agent")
    auth = ApiKeyAuthenticator(repo)
    p1 = await auth.authenticate(token)
    p2 = await auth.authenticate(token)
    assert p1 is not None and p1.key_id == rec.id and p1 == p2
    assert repo.lookups == 1  # second call served from cache, no argon2 verify
    assert repo.touched == [rec.id]


async def test_authenticate_rejects_wrong_secret_revoked_and_malformed() -> None:
    repo = FakeRepo()
    token, _ = repo.add("agent")
    revoked_token, _ = repo.add("old", revoked=True)
    auth = ApiKeyAuthenticator(repo)
    prefix = parse_prefix(token)
    assert await auth.authenticate(f"tw_{prefix}_{'x' * 43}") is None
    assert await auth.authenticate(revoked_token) is None
    assert await auth.authenticate("Bearer nonsense") is None


async def test_cache_expires() -> None:
    repo = FakeRepo()
    token, _ = repo.add("agent")
    auth = ApiKeyAuthenticator(repo, cache_ttl=0.0)
    await auth.authenticate(token)
    await auth.authenticate(token)
    assert repo.lookups == 2


async def test_session_of_another_key_is_unknown() -> None:
    engine = make_engine()
    owner, intruder = uuid.uuid4(), uuid.uuid4()
    sid = await engine.create_session(SessionCreate(agent_name="a", user_prompt="hi"), owner=owner)
    own = await engine.check_call(call(sid, "calculator__add", a=1, b=2), owner=owner)
    other = await engine.check_call(call(sid, "calculator__add", a=1, b=2), owner=intruder)
    assert own.action == "allow"
    assert (other.action, other.rule_id) == ("block", "unknown-session")
    anon_sid = await session(engine, "hi")  # no owner (direct engine use)
    assert (
        await engine.check_call(call(anon_sid, "calculator__add", a=1), owner=intruder)
    ).action == "allow"


@pytest.fixture
def api() -> Iterator[tuple[TestClient, str]]:
    settings = Settings(
        database_url="postgresql+asyncpg://x:x@127.0.0.1:1/x",
        redis_url="redis://127.0.0.1:1/0",
        log_json=False,
    )
    repo = FakeRepo()
    token, _ = repo.add("agent")
    with TestClient(create_app(settings)) as c:
        c.app.state.authenticator = ApiKeyAuthenticator(repo)  # type: ignore[attr-defined]
        c.app.state.engine = make_engine()  # type: ignore[attr-defined]
        yield c, token


SESSION = {"agent_name": "a", "user_prompt": "hi"}


@pytest.mark.parametrize(
    ("method", "path"),
    [("post", "/v1/sessions"), ("post", "/v1/check/call"), ("post", "/v1/check/result")],
)
def test_v1_endpoints_require_key(api: tuple[TestClient, str], method: str, path: str) -> None:
    client, _ = api
    r = client.request(method, path, json={})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    bad = client.request(method, path, json={}, headers={"Authorization": "Bearer tw_nope"})
    assert bad.status_code == 401


def test_health_needs_no_key(api: tuple[TestClient, str]) -> None:
    client, _ = api
    assert client.get("/healthz").status_code == 200


def test_valid_key_creates_owned_session(api: tuple[TestClient, str]) -> None:
    client, token = api
    h = {"Authorization": f"Bearer {token}"}
    sid = client.post("/v1/sessions", json=SESSION, headers=h).json()["session_id"]
    d = client.post(
        "/v1/check/call",
        json={"session_id": sid, "tool": "calculator__add", "args": {"a": 1}},
        headers=h,
    ).json()
    assert d["action"] == "allow"


def test_auth_backend_error_is_503_not_allow(api: tuple[TestClient, str]) -> None:
    client, token = api

    class Boom:
        async def authenticate(self, token: str) -> None:
            raise RuntimeError("db down")

    client.app.state.authenticator = Boom()  # type: ignore[attr-defined]
    r = client.post("/v1/sessions", json=SESSION, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 503


def test_openapi_declares_bearer_security(api: tuple[TestClient, str]) -> None:
    client, _ = api
    spec = client.get("/openapi.json").json()
    assert "HTTPBearer" in spec["components"]["securitySchemes"]
    assert spec["paths"]["/v1/check/call"]["post"]["security"] == [{"HTTPBearer": []}]
    assert "security" not in spec["paths"]["/healthz"]["get"]
