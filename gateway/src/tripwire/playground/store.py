"""Playground persistence: finished runs, live event streams, rate limits, replays."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.db import models as db

REPLAY_DIR = Path(__file__).parent / "replays"
REPLAY_PREFIX = "replay-"
EVENT_TTL_S = 3600


def replay_id(scenario_id: str) -> str:
    return f"{REPLAY_PREFIX}{scenario_id}"


def load_replay(run_id: str) -> dict[str, Any] | None:
    """A committed replay fixture (`replays/<scenario>.json`), or None."""
    if not run_id.startswith(REPLAY_PREFIX):
        return None
    name = run_id[len(REPLAY_PREFIX) :]
    if not name.replace("_", "").isalnum():
        return None
    path = REPLAY_DIR / f"{name}.json"
    if not path.is_file():
        return None
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


# ---------------------------------------------------------------- finished runs


class RunStore(Protocol):
    async def save(self, run: dict[str, Any], ip_hash: str | None) -> None: ...
    async def get(self, run_id: str) -> dict[str, Any] | None: ...


class MemoryRunStore:
    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}

    async def save(self, run: dict[str, Any], ip_hash: str | None) -> None:
        self.runs[run["run_id"]] = run

    async def get(self, run_id: str) -> dict[str, Any] | None:
        return self.runs.get(run_id) or load_replay(run_id)


class SqlRunStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory

    async def save(self, run: dict[str, Any], ip_hash: str | None) -> None:
        async with self._factory() as s, s.begin():
            s.add(
                db.PlaygroundRun(
                    id=uuid.UUID(run["run_id"]),
                    scenario_id=run["scenario"]["id"],
                    source=run["source"],
                    model=run["model"]["name"],
                    ip_hash=ip_hash,
                    payload=run,
                )
            )

    async def get(self, run_id: str) -> dict[str, Any] | None:
        replay = load_replay(run_id)
        if replay is not None:
            return replay
        try:
            rid = uuid.UUID(run_id)
        except ValueError:
            return None
        async with self._factory() as s:
            row = await s.get(db.PlaygroundRun, rid)
            return dict(row.payload) if row is not None else None


# ---------------------------------------------------------------- live events


class RunEvents(Protocol):
    async def publish(self, run_id: str, event: dict[str, Any]) -> None: ...
    def follow(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        """History so far, then live events, until `run.completed`."""
        ...


class MemoryRunEvents:
    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._cond = asyncio.Condition()

    async def publish(self, run_id: str, event: dict[str, Any]) -> None:
        async with self._cond:
            self._events.setdefault(run_id, []).append(event)
            self._cond.notify_all()

    async def follow(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        i = 0

        def more(seen: int) -> bool:
            return len(self._events.get(run_id, [])) > seen

        while True:
            async with self._cond:
                await self._cond.wait_for(functools.partial(more, i))
                batch = self._events[run_id][i:]
            for ev in batch:
                i += 1
                yield ev
                if ev.get("type") == "run.completed":
                    return

    def history(self, run_id: str) -> list[dict[str, Any]]:
        return list(self._events.get(run_id, []))


class RedisRunEvents:
    """Events in a Redis list (for late joiners and other workers) plus pub/sub."""

    def __init__(self, redis: Any) -> None:
        self._r = redis

    @staticmethod
    def _keys(run_id: str) -> tuple[str, str]:
        return f"tripwire:pg:events:{run_id}", f"tripwire:pg:live:{run_id}"

    async def publish(self, run_id: str, event: dict[str, Any]) -> None:
        lst, chan = self._keys(run_id)
        data = json.dumps(event, default=str)
        pipe = self._r.pipeline()
        pipe.rpush(lst, data)
        pipe.expire(lst, EVENT_TTL_S)
        pipe.publish(chan, data)
        await pipe.execute()

    async def follow(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        lst, chan = self._keys(run_id)
        pubsub = self._r.pubsub()
        await pubsub.subscribe(chan)  # subscribe first, then read history: no gap
        try:
            seen = -1
            for raw in await self._r.lrange(lst, 0, -1):
                ev = json.loads(raw)
                seen = max(seen, int(ev.get("seq", -1)))
                yield ev
                if ev.get("type") == "run.completed":
                    return
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                ev = json.loads(msg["data"])
                if int(ev.get("seq", -1)) <= seen:
                    continue
                yield ev
                if ev.get("type") == "run.completed":
                    return
        finally:
            await pubsub.unsubscribe(chan)
            await pubsub.aclose()


# ---------------------------------------------------------------- limits


def hash_ip(ip: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:32]


class Limits(Protocol):
    async def ip_allowed(self, ip_hash: str, per_hour: int) -> bool:
        """Count one run for this IP in the current hour; False when over the limit."""
        ...

    async def daily_allowed(self, cap: int) -> bool:
        """Count one live (real-model) run today; False when over the global cap."""
        ...


def _hour() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H")


def _day() -> str:
    return datetime.now(UTC).strftime("%Y%m%d")


class MemoryLimits:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def _incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def ip_allowed(self, ip_hash: str, per_hour: int) -> bool:
        return self._incr(f"ip:{ip_hash}:{_hour()}") <= per_hour

    async def daily_allowed(self, cap: int) -> bool:
        return self._incr(f"day:{_day()}") <= cap


class RedisLimits:
    def __init__(self, redis: Any) -> None:
        self._r = redis

    async def _incr(self, key: str, ttl: int) -> int:
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl)
        n, _ = await pipe.execute()
        return int(n)

    async def ip_allowed(self, ip_hash: str, per_hour: int) -> bool:
        return await self._incr(f"tripwire:pg:ip:{ip_hash}:{_hour()}", 3600) <= per_hour

    async def daily_allowed(self, cap: int) -> bool:
        return await self._incr(f"tripwire:pg:day:{_day()}", 2 * 86400) <= cap
