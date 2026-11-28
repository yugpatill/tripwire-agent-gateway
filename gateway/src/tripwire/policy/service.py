"""The active policy: versioned in Postgres, hot-swapped in every worker.

- On start, the newest active row in `policies` wins; when there is none, the
  file policy (TRIPWIRE_POLICY_PATH) becomes version 1.
- `deploy` validates (line/column errors), stores a new version, swaps it into
  the engine and announces `policy.updated` on the event bus, so other workers
  reload it.
- `test` replays recorded call decisions against a candidate policy and lists
  the calls whose action would change. Rate-limit counters are not replayed.
- Shadow mode (decisions logged, `log_only` enforced) is a runtime switch in
  Redis, announced the same way.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.approvals.service import EventBus
from tripwire.db import models as db
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.normalize import flatten_strings
from tripwire.playground.runner import PLAYGROUND_OWNER
from tripwire.policy.compiler import UNKNOWN_TOOL_SPEC, CallFacts, CompiledPolicy, compile_policy
from tripwire.policy.evaluate import evaluate
from tripwire.policy.loader import parse_policy
from tripwire.taint.labels import Provenance

log = structlog.get_logger(__name__)

Mode = Literal["enforce", "shadow"]
MODE_KEY = "tripwire:runtime:mode"
MAX_REPLAY_EVENTS = 5000


class PolicyService:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        engines: list[Engine],
        bus: EventBus,
        redis: Any,
        default_mode: Mode,
    ) -> None:
        self._factory = factory
        self.engines = engines  # the policy applies to the agent engine(s), not the playground
        self._bus = bus
        self._redis = redis
        self._default_mode: Mode = default_mode
        self.version: int | None = None
        self._listener: asyncio.Task[None] | None = None

    # ---------- startup and sync

    async def start(self, file_policy: CompiledPolicy | None) -> None:
        try:
            await self._load(file_policy)
            await self._apply_mode(await self.mode())
        except Exception as exc:  # DB or Redis down: keep the file policy, retry on events
            log.warning("policy.db_unavailable", error=repr(exc))
        self._listener = asyncio.create_task(self._listen())

    async def _load(self, file_policy: CompiledPolicy | None) -> None:
        async with self._factory() as s, s.begin():
            row = await s.scalar(
                select(db.Policy).where(db.Policy.is_active).order_by(db.Policy.version.desc())
            )
            # The file seeds the first version, and keeps updating it while nobody
            # has deployed from the console (so editing the file still works in dev).
            if file_policy is not None and (
                row is None or (row.created_by == "file" and row.yaml != file_policy.source)
            ):
                latest = await s.scalar(select(func.max(db.Policy.version))) or 0
                await s.execute(update(db.Policy).values(is_active=False))
                row = db.Policy(
                    version=latest + 1, yaml=file_policy.source, is_active=True, created_by="file"
                )
                s.add(row)
        if row is None:
            return
        self._set(compile_policy(parse_policy(row.yaml), row.yaml), row.version)

    def _set(self, policy: CompiledPolicy, version: int) -> None:
        for engine in self.engines:
            engine.policy = policy
        self.version = version
        log.info("policy.active", version=version, rules=len(policy.rules))

    async def _listen(self) -> None:
        while True:
            try:
                async for event in self._bus.subscribe():
                    kind = event.get("type")
                    if kind == "policy.updated" and event.get("version") != self.version:
                        await self._load(None)
                    elif kind == "mode.updated":
                        await self._apply_mode(event.get("mode", "enforce"))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("policy.listener_failed", error=repr(exc))
                await asyncio.sleep(2)

    async def stop(self) -> None:
        if self._listener:
            self._listener.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._listener

    # ---------- reads

    async def active(self) -> dict[str, Any]:
        async with self._factory() as s:
            row = await s.scalar(
                select(db.Policy).where(db.Policy.is_active).order_by(db.Policy.version.desc())
            )
        if row is None:
            policy = self.engines[0].policy
            return {
                "version": 0,
                "yaml": policy.source if policy else "",
                "created_by": "file",
                "created_at": None,
            }
        return {
            "version": row.version,
            "yaml": row.yaml,
            "created_by": row.created_by,
            "created_at": row.created_at,
        }

    # ---------- deploy

    async def deploy(self, text: str, user: str) -> int:
        """Validate (raises PolicyError with line/column) and activate a new version."""
        compiled = compile_policy(parse_policy(text), text)
        async with self._factory() as s, s.begin():
            latest = await s.scalar(select(func.max(db.Policy.version))) or 0
            await s.execute(update(db.Policy).values(is_active=False))
            s.add(db.Policy(version=latest + 1, yaml=text, is_active=True, created_by=user))
        self._set(compiled, latest + 1)
        await self._bus.publish({"type": "policy.updated", "version": latest + 1, "by": user})
        return latest + 1

    # ---------- test against recorded traffic

    async def test(self, text: str, since_hours: int) -> dict[str, Any]:
        candidate = compile_policy(parse_policy(text), text)
        since = datetime.now(UTC) - timedelta(hours=since_hours)
        async with self._factory() as s:
            rows = list(
                (
                    await s.scalars(
                        select(db.Event)
                        .join(db.Session, db.Session.id == db.Event.session_id)
                        .where(
                            db.Event.kind == "call",
                            db.Event.created_at >= since,
                            # playground runs follow the demo policy, not this one
                            db.Session.api_key_id.is_distinct_from(PLAYGROUND_OWNER),
                        )
                        .order_by(db.Event.created_at.desc())
                        .limit(MAX_REPLAY_EVENTS)
                    )
                ).all()
            )

        async def no_limits(_: str) -> int:
            return 1  # counters are not replayed

        changes = []
        skipped = 0
        for e in rows:
            args = (e.payload or {}).get("args", {})
            facts = (e.payload or {}).get("facts")
            if not isinstance(facts, dict):
                # Recorded before session facts were stored: guessing them would
                # report changes that never happened, so leave these out.
                skipped += 1
                continue
            labels = {
                arg: [Provenance.model_validate(p) for p in ls]
                for arg, ls in (e.labels or {}).items()
                if isinstance(ls, list)
            }
            spec = candidate.tool_spec(e.tool)
            ev = await evaluate(
                candidate,
                CallFacts(
                    tool=e.tool,
                    tool_spec=spec or UNKNOWN_TOOL_SPEC,
                    tool_known=spec is not None,
                    arg_labels=labels,
                    arg_text={k: flatten_strings(v) for k, v in args.items()},
                    context_confidentiality=facts.get("context_confidentiality", "public"),
                    session_suspicious=bool(facts.get("session_suspicious", False)),
                ),
                no_limits,
            )
            if ev.action != e.action:
                changes.append(
                    {
                        "event_id": str(e.id),
                        "session_id": str(e.session_id),
                        "created_at": e.created_at.isoformat(),
                        "tool": e.tool,
                        "old_action": e.action,
                        "old_rule_id": e.rule_id,
                        "new_action": ev.action,
                        "rule_id": ev.rule_id,
                    }
                )
        return {
            "replayed": len(rows) - skipped,
            "skipped": skipped,
            "since_hours": since_hours,
            "changes": changes,
        }

    # ---------- shadow mode

    async def mode(self) -> Mode:
        try:
            value = await self._redis.get(MODE_KEY)
        except Exception:
            value = None
        return "shadow" if value == "shadow" else ("enforce" if value else self._default_mode)

    async def set_mode(self, mode: Mode, user: str) -> None:
        await self._redis.set(MODE_KEY, mode)
        await self._apply_mode(mode)
        await self._bus.publish({"type": "mode.updated", "mode": mode, "by": user})
        log.warning("policy.mode", mode=mode, by=user)

    async def _apply_mode(self, mode: str) -> None:
        for engine in self.engines:
            engine.default_mode = "shadow" if mode == "shadow" else "enforce"
