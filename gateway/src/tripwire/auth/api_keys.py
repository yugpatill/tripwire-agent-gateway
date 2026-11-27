"""Agent API keys: `Authorization: Bearer tw_<prefix>_<secret>`.

Keys are stored as argon2id hashes (api_keys table) with an indexed, non-secret
prefix for lookup. argon2 verification costs ~40 ms by design, far over the
decision latency budget, so successful verifications are cached in-process for
`cache_ttl` seconds, keyed by SHA-256 of the presented token (never the token
itself). Revocation therefore takes effect within `cache_ttl` seconds.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Literal, Protocol

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.db import models as db

KEY_PREFIX = "tw_"
Role = Literal["agent", "operator"]
ROLES: tuple[Role, ...] = ("agent", "operator")
_PREFIX_LEN = 8
_hasher = PasswordHasher()


@dataclass(frozen=True, slots=True)
class NewKey:
    id: uuid.UUID
    name: str
    token: str  # shown once, never stored
    role: Role = "agent"


@dataclass(frozen=True, slots=True)
class KeyRecord:
    id: uuid.UUID
    name: str
    prefix: str
    key_hash: str
    revoked: bool
    role: Role = "agent"


def _role(value: str) -> Role:
    """Unknown role strings degrade to the least privileged role."""
    return "operator" if value == "operator" else "agent"


def generate_token() -> tuple[str, str]:
    """Return (token, lookup_prefix). Token: tw_<8 hex>_<43 urlsafe chars>."""
    prefix = secrets.token_hex(_PREFIX_LEN // 2)
    return f"{KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}", prefix


def parse_prefix(token: str) -> str | None:
    if not token.startswith(KEY_PREFIX):
        return None
    body = token[len(KEY_PREFIX) :]
    prefix, sep, secret = body.partition("_")
    if not sep or len(prefix) != _PREFIX_LEN or len(secret) < 16:
        return None
    return prefix


def hash_token(token: str) -> str:
    return _hasher.hash(token)


def verify_hash(key_hash: str, token: str) -> bool:
    try:
        return _hasher.verify(key_hash, token)
    except (VerificationError, InvalidHashError):
        return False


class KeyRepository(Protocol):
    async def by_prefix(self, prefix: str) -> list[KeyRecord]: ...
    async def touch(self, key_id: uuid.UUID) -> None: ...


class SqlKeyRepository:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory

    async def by_prefix(self, prefix: str) -> list[KeyRecord]:
        async with self._factory() as s:
            rows = (await s.scalars(select(db.ApiKey).where(db.ApiKey.prefix == prefix))).all()
        return [
            KeyRecord(r.id, r.name, r.prefix, r.key_hash, r.revoked, _role(r.role)) for r in rows
        ]

    async def touch(self, key_id: uuid.UUID) -> None:
        async with self._factory() as s, s.begin():
            await s.execute(
                update(db.ApiKey).where(db.ApiKey.id == key_id).values(last_used_at=func.now())
            )

    async def create(self, name: str, role: Role = "agent") -> NewKey:
        token, prefix = generate_token()
        key_hash = await asyncio.to_thread(hash_token, token)
        row = db.ApiKey(name=name, prefix=prefix, key_hash=key_hash, role=role)
        async with self._factory() as s, s.begin():
            s.add(row)
        return NewKey(row.id, name, token, role)

    async def list(self) -> list[KeyRecord]:
        async with self._factory() as s:
            rows = (await s.scalars(select(db.ApiKey).order_by(db.ApiKey.created_at))).all()
        return [KeyRecord(r.id, r.name, r.prefix, "", r.revoked, _role(r.role)) for r in rows]

    async def revoke(self, key_id: uuid.UUID) -> bool:
        async with self._factory() as s, s.begin():
            res = await s.execute(
                update(db.ApiKey).where(db.ApiKey.id == key_id).values(revoked=True)
            )
        return bool(getattr(res, "rowcount", 0))


@dataclass(frozen=True, slots=True)
class Principal:
    key_id: uuid.UUID
    name: str
    role: Role = "agent"

    @property
    def is_operator(self) -> bool:
        return self.role == "operator"


class ApiKeyAuthenticator:
    def __init__(
        self, repo: KeyRepository, cache_ttl: float = 60.0, cache_size: int = 10_000
    ) -> None:
        self._repo = repo
        self._ttl = cache_ttl
        self._size = cache_size
        self._cache: dict[str, tuple[float, Principal]] = {}

    async def authenticate(self, token: str) -> Principal | None:
        prefix = parse_prefix(token)
        if prefix is None:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        hit = self._cache.get(digest)
        if hit is not None and hit[0] > now:
            return hit[1]
        for rec in await self._repo.by_prefix(prefix):
            if rec.revoked:
                continue
            if await asyncio.to_thread(verify_hash, rec.key_hash, token):
                principal = Principal(rec.id, rec.name, rec.role)
                if len(self._cache) >= self._size:
                    self._cache.clear()
                self._cache[digest] = (now + self._ttl, principal)
                await self._repo.touch(rec.id)
                return principal
        return None
