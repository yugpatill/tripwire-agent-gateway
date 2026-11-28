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


def replay_id(scenario_id: str, variant: str = "") -> str:
    """`replay-<id>` (the default demo) or `replay-<id>-scripted` / `replay-<id>-live`."""
    return f"{REPLAY_PREFIX}{scenario_id}" + (f"-{variant}" if variant else "")


def replay_path(scenario_id: str, variant: str) -> Path:
    """`<id>.json` holds the scripted replay, `<id>.live.json` the real-model one."""
    return REPLAY_DIR / (f"{scenario_id}.live.json" if variant == "live" else f"{scenario_id}.json")


def _read(scenario_id: str, variant: str) -> dict[str, Any] | None:
    path = replay_path(scenario_id, variant)
    if not path.is_file():
        return None
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def demonstrates(record: dict[str, Any]) -> bool:
    v = record.get("verdict", {})
    return bool(v.get("attack_succeeded_unprotected")) and not v.get("attack_succeeded_protected")


def replay_variants(scenario_id: str) -> dict[str, Any]:
    """Which replays exist for a preset and which one is the default demo.

    The real-model replay is the default when it shows the attack working
    unprotected and stopped protected; otherwise (the model refused, or there is
    none) the scripted replay is, and the real-model one stays available.
    """
    live = _read(scenario_id, "live")
    scripted = _read(scenario_id, "scripted")
    default = "live" if live is not None and demonstrates(live) else "scripted"
    if scripted is None and live is not None:
        default = "live"
    available = [v for v, r in (("scripted", scripted), ("live", live)) if r is not None]
    return {"default": default if available else None, "available": available}


def load_replay(run_id: str) -> dict[str, Any] | None:
    """A committed replay fixture, by `replay-<id>[-scripted|-live]`, or None."""
    if not run_id.startswith(REPLAY_PREFIX):
        return None
    name = run_id[len(REPLAY_PREFIX) :]
    variant = ""
    for v in ("scripted", "live"):
        if name.endswith(f"-{v}"):
            name, variant = name[: -len(v) - 1], v
    if not name.replace("_", "").isalnum():
        return None
    if not variant:
        variant = replay_variants(name)["default"] or "scripted"
    data = _read(name, variant)
    if data is None:
        return None
    data["run_id"] = run_id
    data["replay_variant"] = variant
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
