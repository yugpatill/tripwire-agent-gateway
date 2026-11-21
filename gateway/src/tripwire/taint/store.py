"""Per-session taint state. Redis in production, in-memory for tests."""

from __future__ import annotations

import json
from typing import Any, Protocol
from uuid import UUID

import redis.asyncio as aioredis
from pydantic import BaseModel

from tripwire.models import CONFIDENTIALITY_ORDER, Confidentiality, Mode
from tripwire.taint.labels import TaggedValue

SESSION_TTL_SECONDS = 24 * 3600


class SessionState(BaseModel):
    session_id: UUID
    mode: Mode
    has_untrusted: bool = False
    suspicious: bool = False
    max_confidentiality: Confidentiality = "public"


class CallRecord(BaseModel):
    event_id: UUID
    tool: str
    args: dict[str, Any]


class TaintStore(Protocol):
    async def create_session(self, state: SessionState) -> None: ...
    async def get_session(self, session_id: UUID) -> SessionState | None: ...
    async def mark_context(
        self,
        session_id: UUID,
        *,
        confidentiality: Confidentiality,
        untrusted: bool,
        suspicious: bool,
    ) -> None: ...
    async def add_values(self, session_id: UUID, values: list[TaggedValue]) -> None: ...
    async def get_values(self, session_id: UUID) -> list[TaggedValue]: ...
    async def record_call(self, session_id: UUID, call: CallRecord) -> None: ...
    async def get_call(self, session_id: UUID, event_id: UUID) -> CallRecord | None: ...
    async def incr_counter(self, session_id: UUID, name: str) -> int: ...


class InMemoryTaintStore:
    def __init__(self) -> None:
        self._sessions: dict[UUID, SessionState] = {}
        self._values: dict[UUID, list[TaggedValue]] = {}
        self._calls: dict[tuple[UUID, UUID], CallRecord] = {}
        self._counters: dict[tuple[UUID, str], int] = {}

    async def create_session(self, state: SessionState) -> None:
        self._sessions[state.session_id] = state.model_copy()
        self._values.setdefault(state.session_id, [])

    async def get_session(self, session_id: UUID) -> SessionState | None:
        s = self._sessions.get(session_id)
        return s.model_copy() if s else None

    async def mark_context(
        self,
        session_id: UUID,
        *,
        confidentiality: Confidentiality,
        untrusted: bool,
        suspicious: bool,
    ) -> None:
        s = self._sessions[session_id]
        if CONFIDENTIALITY_ORDER[confidentiality] > CONFIDENTIALITY_ORDER[s.max_confidentiality]:
            s.max_confidentiality = confidentiality
        s.has_untrusted = s.has_untrusted or untrusted
        s.suspicious = s.suspicious or suspicious

    async def add_values(self, session_id: UUID, values: list[TaggedValue]) -> None:
        self._values.setdefault(session_id, []).extend(values)

    async def get_values(self, session_id: UUID) -> list[TaggedValue]:
        return list(self._values.get(session_id, []))

    async def record_call(self, session_id: UUID, call: CallRecord) -> None:
        self._calls[(session_id, call.event_id)] = call

    async def get_call(self, session_id: UUID, event_id: UUID) -> CallRecord | None:
        return self._calls.get((session_id, event_id))

    async def incr_counter(self, session_id: UUID, name: str) -> int:
        key = (session_id, name)
        self._counters[key] = self._counters.get(key, 0) + 1
        return self._counters[key]


class RedisTaintStore:
    """Keys: tw:s:<sid>:meta (hash), :values (list), :calls (hash), :count (hash)."""

    def __init__(self, client: aioredis.Redis, ttl: int = SESSION_TTL_SECONDS) -> None:
        self._r = client
        self._ttl = ttl

    @staticmethod
    def _k(session_id: UUID, part: str) -> str:
        return f"tw:s:{session_id}:{part}"

    async def _touch(self, session_id: UUID) -> None:
        pipe = self._r.pipeline()
        for part in ("meta", "values", "calls", "count"):
            pipe.expire(self._k(session_id, part), self._ttl)
        await pipe.execute()

    async def create_session(self, state: SessionState) -> None:
        mapping = {
            "mode": state.mode,
            "untrusted": int(state.has_untrusted),
            "suspicious": int(state.suspicious),
            f"conf:{state.max_confidentiality}": 1,
        }
        await self._r.hset(self._k(state.session_id, "meta"), mapping=mapping)  # type: ignore[misc]
        await self._touch(state.session_id)

    async def get_session(self, session_id: UUID) -> SessionState | None:
        raw: dict[str, str] = await self._r.hgetall(self._k(session_id, "meta"))  # type: ignore[misc]
        if not raw:
            return None
        levels = [k.split(":", 1)[1] for k in raw if k.startswith("conf:")]
        best: Confidentiality = "public"
        for lvl in levels:
            if (
                lvl in CONFIDENTIALITY_ORDER
                and CONFIDENTIALITY_ORDER[lvl] > CONFIDENTIALITY_ORDER[best]
            ):
                best = lvl  # type: ignore[assignment]
        return SessionState(
            session_id=session_id,
            mode=raw.get("mode", "enforce"),
            has_untrusted=raw.get("untrusted") == "1",
            suspicious=raw.get("suspicious") == "1",
            max_confidentiality=best,
        )

    async def mark_context(
        self,
        session_id: UUID,
        *,
        confidentiality: Confidentiality,
        untrusted: bool,
        suspicious: bool,
    ) -> None:
        # Monotonic flags: each field only ever goes 0 -> 1, so concurrent writers are safe.
        mapping: dict[str, int] = {f"conf:{confidentiality}": 1}
        if untrusted:
            mapping["untrusted"] = 1
        if suspicious:
            mapping["suspicious"] = 1
        await self._r.hset(self._k(session_id, "meta"), mapping=mapping)  # type: ignore[misc]

    async def add_values(self, session_id: UUID, values: list[TaggedValue]) -> None:
        if not values:
            return
        key = self._k(session_id, "values")
        await self._r.rpush(key, *[v.model_dump_json() for v in values])  # type: ignore[misc]
        await self._r.expire(key, self._ttl)

    async def get_values(self, session_id: UUID) -> list[TaggedValue]:
        raw: list[str] = await self._r.lrange(self._k(session_id, "values"), 0, -1)  # type: ignore[misc]
        return [TaggedValue.model_validate_json(r) for r in raw]

    async def record_call(self, session_id: UUID, call: CallRecord) -> None:
        key = self._k(session_id, "calls")
        await self._r.hset(key, str(call.event_id), call.model_dump_json())  # type: ignore[misc]
        await self._r.expire(key, self._ttl)

    async def get_call(self, session_id: UUID, event_id: UUID) -> CallRecord | None:
        raw: str | None = await self._r.hget(self._k(session_id, "calls"), str(event_id))  # type: ignore[misc]
        return CallRecord.model_validate(json.loads(raw)) if raw else None

    async def incr_counter(self, session_id: UUID, name: str) -> int:
        key = self._k(session_id, "count")
        value: int = await self._r.hincrby(key, name, 1)  # type: ignore[misc]
        await self._r.expire(key, self._ttl)
        return value
