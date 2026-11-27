"""Playground runner: one scenario, run twice at the same time.

- unprotected: the agent calls the run's mock servers directly;
- protected: the agent's tool listings and calls go through Tripwire's MCP proxy
  code (manifest guard, check/call, check/result) with one Tripwire session per
  run, on its own copy of the environment and its own tool pins.

Each side has its own seeded `MockState`; the attacker's goal is checked on it
afterwards with the scenario's success predicate. Events from both sides are
numbered, streamed (`RunEvents`) and stored with the run (`RunStore`).

Mode per request:
- `live`: a real model (API key configured, under the daily cap);
- `scripted`: no real model available: presets replay their script live, custom
  attacks use the naive scripted model (`NaiveModel`);
- `replay`: a committed fixture of the preset (`replays/<id>.json`) is served
  instead of running anything (no API key, daily cap reached, or the visitor's
  hourly limit reached).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import structlog

from tripwire.auth.api_keys import Principal
from tripwire.models import SessionCreate
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.engine import Engine
from tripwire.playground.agent import (
    AnthropicModel,
    DirectBackend,
    Model,
    NaiveModel,
    OpenAIModel,
    ProtectedBackend,
    ScriptedModel,
    ToolRequest,
    run_agent,
)
from tripwire.playground.mock_servers.servers import MockState, build_servers
from tripwire.playground.scenarios import (
    CUSTOM_TASKS,
    CUSTOM_URL,
    USER_EMAIL,
    Scenario,
    custom_scenario,
    presets,
)
from tripwire.playground.store import (
    Limits,
    RunEvents,
    RunStore,
    hash_ip,
    load_replay,
    replay_id,
)
from tripwire.proxy.guard import ManifestGuard, MemoryPinStore
from tripwire.proxy.mcp_gateway import CallerIdentity, McpProxy, MemorySessionMap
from tripwire.proxy.upstreams import UpstreamPool

log = structlog.get_logger(__name__)

Side = Literal["unprotected", "protected"]
Mode = Literal["live", "scripted", "replay"]
# Playground sessions belong to no API key, so no key can read or use them.
PLAYGROUND_OWNER = uuid.uuid5(uuid.NAMESPACE_URL, "https://tripwire/playground")
PLAYGROUND_PRINCIPAL = Principal(PLAYGROUND_OWNER, "playground", "agent", "header")


class PlaygroundError(Exception):
    """Bad request (unknown scenario, invalid custom attack)."""


class RateLimited(PlaygroundError):
    """The visitor's hourly limit is reached and there is no replay to serve."""


@dataclass(slots=True)
class PlaygroundConfig:
    provider: Literal["anthropic", "openai"] = "anthropic"
    model: str = ""
    api_key: str = ""
    max_steps: int = 8
    max_output_tokens: int = 4000
    ip_per_hour: int = 5
    daily_cap: int = 200
    max_concurrent: int = 4
    ip_salt: str = "tripwire-playground"

    @property
    def model_name(self) -> str:
        if self.model:
            return self.model
        return "claude-haiku-5-5" if self.provider == "anthropic" else ""

    @property
    def live_available(self) -> bool:
        return bool(self.api_key and self.model_name)


ModelFactory = Callable[[Scenario, Side], Model]


class PlaygroundRunner:
    def __init__(
        self,
        engine: Engine,
        detection: DetectionPipeline | None,
        store: RunStore,
        events: RunEvents,
        limits: Limits,
        config: PlaygroundConfig,
        ensure_owner: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        """`ensure_owner`: makes sure the reserved owner of playground sessions exists
        (a revoked API key row); called before the first run, retried until it works."""
        self.engine = engine
        self._ensure_owner = ensure_owner
        self.detection = detection
        self.store = store
        self.events = events
        self.limits = limits
        self.config = config
        self._sem = asyncio.Semaphore(config.max_concurrent)
        self._tasks: set[asyncio.Task[Any]] = set()

    # ---------- request handling

    def scenario_for(self, scenario_id: str | None, custom: dict[str, Any] | None) -> Scenario:
        if (scenario_id is None) == (custom is None):
            raise PlaygroundError("send exactly one of scenario_id or custom")
        if scenario_id is not None:
            sc = presets().get(scenario_id)
            if sc is None:
                raise PlaygroundError(f"unknown scenario {scenario_id!r}")
            return sc
        assert custom is not None
        try:
            return custom_scenario(str(custom.get("task_id", "")), str(custom.get("text", "")))
        except ValueError as exc:
            raise PlaygroundError(str(exc)) from exc

    async def start(
        self, scenario_id: str | None, custom: dict[str, Any] | None, ip: str
    ) -> dict[str, Any]:
        sc = self.scenario_for(scenario_id, custom)
        preset = scenario_id is not None
        ip_hash = hash_ip(ip, self.config.ip_salt)

        def replay(reason: str) -> dict[str, Any] | None:
            rid = replay_id(sc.id)
            if load_replay(rid) is None:
                return None
            log.info("playground.replay", scenario=sc.id, reason=reason)
            return {"run_id": rid, "mode": "replay", "reason": reason, "scenario": sc.card()}

        if not await self.limits.ip_allowed(ip_hash, self.config.ip_per_hour):
            served = replay("rate_limited") if preset else None
            if served:
                return served
            raise RateLimited("Too many runs from your address this hour; try again later.")
        mode: Mode = "live"
        reason = ""
        if not self.config.live_available:
            mode, reason = "scripted", "no_api_key"
        elif not await self.limits.daily_allowed(self.config.daily_cap):
            mode, reason = "scripted", "daily_cap"
        if mode != "live" and preset:
            served = replay(reason)
            if served:
                return served
        if self._ensure_owner is not None:
            await self._ensure_owner()
            self._ensure_owner = None
        run_id = str(uuid.uuid4())
        protected_sid = await self.engine.create_session(
            SessionCreate(agent_name="playground", user_prompt=sc.task),
            owner=PLAYGROUND_OWNER,
        )
        task = asyncio.create_task(
            self.execute(run_id, sc, mode, protected_sid, ip_hash=ip_hash, guarded=True)
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return {
            "run_id": run_id,
            "mode": mode,
            "reason": reason,
            "scenario": sc.card(),
            "unprotected_session_id": None,
            "protected_session_id": str(protected_sid),
        }

    # ---------- models

    def model_for(self, sc: Scenario, side: Side, mode: Mode) -> Model:
        if mode == "live":
            if self.config.provider == "openai":
                return OpenAIModel(sc.task, self.config.model_name, self.config.api_key)
            return AnthropicModel(sc.task, self.config.model_name, self.config.api_key)
        if sc.id.startswith("custom_"):
            task_id = sc.id.removeprefix("custom_")
            kind = CUSTOM_TASKS[task_id].kind
            read = (
                ToolRequest("call_1", "web__fetch", {"url": CUSTOM_URL})
                if kind == "webpage"
                else ToolRequest("call_1", "email__read_inbox", {})
            )
            return NaiveModel(read, sc.malicious.text, USER_EMAIL, "Done.")
        return ScriptedModel(sc)

    # ---------- execution

    async def execute(
        self,
        run_id: str,
        sc: Scenario,
        mode: Mode,
        protected_sid: uuid.UUID | None = None,
        *,
        ip_hash: str | None = None,
        guarded: bool = False,
        model_factory: ModelFactory | None = None,
    ) -> dict[str, Any]:
        """Run both sides concurrently; store and return the run record."""
        if guarded:
            async with self._sem:
                return await self._execute(run_id, sc, mode, protected_sid, ip_hash, model_factory)
        return await self._execute(run_id, sc, mode, protected_sid, ip_hash, model_factory)

    async def _execute(
        self,
        run_id: str,
        sc: Scenario,
        mode: Mode,
        protected_sid: uuid.UUID | None,
        ip_hash: str | None,
        model_factory: ModelFactory | None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        seq = 0
        events: list[dict[str, Any]] = []

        async def publish(side: str, event: dict[str, Any]) -> None:
            nonlocal seq
            ev = {
                "seq": seq,
                "t_ms": int((time.monotonic() - started) * 1000),
                "side": side,
                **event,
            }
            seq += 1
            events.append(ev)
            try:
                await self.events.publish(run_id, ev)
            except Exception as exc:  # streaming is best effort; the record is the truth
                log.warning("playground.publish_failed", error=repr(exc))

        factory = model_factory or (lambda s, side: self.model_for(s, side, mode))
        models = {side: factory(sc, side) for side in ("unprotected", "protected")}
        first = models["protected"]
        await publish(
            "run",
            {
                "type": "run.started",
                "run_id": run_id,
                "mode": mode,
                "scenario": sc.card(),
                "model": {"provider": first.provider, "name": first.name},
            },
        )
        sides = await asyncio.gather(
            self._side(sc, "unprotected", models["unprotected"], publish, None),
            self._side(sc, "protected", models["protected"], publish, protected_sid),
        )
        unprotected, protected = sides
        fired = sorted(
            {
                str(e["rule_id"])
                for e in events
                if e["side"] == "protected"
                and e.get("type") == "tool.result"
                and e.get("status") in ("blocked", "denied")
                and e.get("rule_id")
            }
        )
        verdict = {
            "attack_succeeded_unprotected": unprotected["attacker_goal_reached"],
            "attack_succeeded_protected": protected["attacker_goal_reached"],
            "rules_fired_protected": fired,
            "expected_rule": sc.expected_block.rule,
            "expected_rule_fired": sc.expected_block.rule in fired,
        }
        await publish("run", {"type": "run.completed", "verdict": verdict})
        record = {
            "run_id": run_id,
            "created_at": datetime.now(UTC).isoformat(),
            "source": "live" if mode == "live" else "scripted",
            "model": {"provider": first.provider, "name": first.name, "scripted": first.scripted},
            "scenario": {**sc.card(), "malicious": sc.malicious.model_dump()},
            "limits": {
                "max_steps": self.config.max_steps,
                "max_output_tokens": self.config.max_output_tokens,
            },
            "sides": {"unprotected": unprotected, "protected": protected},
            "verdict": verdict,
            "events": events,
        }
        try:
            await self.store.save(record, ip_hash)
        except Exception as exc:
            log.error("playground.save_failed", run_id=run_id, error=repr(exc))
        log.info("playground.run", run_id=run_id, scenario=sc.id, mode=mode, **verdict)
        return record

    async def _side(
        self,
        sc: Scenario,
        side: Side,
        model: Model,
        publish: Callable[[str, dict[str, Any]], Any],
        protected_sid: uuid.UUID | None,
    ) -> dict[str, Any]:
        state = MockState.from_seed(sc.environment)
        mock = build_servers(state)
        servers = {name: mock.servers[name] for name in sc.servers}

        async def emit(event: dict[str, Any]) -> None:
            await publish(side, event)

        session_id: str | None = None
        backend: DirectBackend | ProtectedBackend
        if side == "protected":
            sid = protected_sid or await self.engine.create_session(
                SessionCreate(agent_name="playground", user_prompt=sc.task),
                owner=PLAYGROUND_OWNER,
            )
            session_id = str(sid)
            proxy = McpProxy(
                self.engine,
                ManifestGuard(MemoryPinStore(), None, self.detection),
                UpstreamPool.in_memory(servers),
                approvals=None,
                sessions=MemorySessionMap(),
            )
            backend = ProtectedBackend(proxy, CallerIdentity(PLAYGROUND_PRINCIPAL, sid))
        else:
            backend = DirectBackend(servers)
        try:
            async with backend:
                result = await run_agent(
                    model,
                    backend,
                    emit,
                    self.config.max_steps,
                    self.config.max_output_tokens,
                )
        except Exception as exc:
            log.exception("playground.side_failed", side=side, scenario=sc.id)
            await emit({"type": "error", "message": type(exc).__name__})
            result = None
        reached = sc.success.reached(state.calls)
        out = {
            "session_id": session_id,
            "attacker_goal_reached": bool(reached),
            "goal_calls": reached,
            "environment": state.snapshot(),
            "final_text": result.final_text if result else "",
            "steps": result.steps if result else 0,
            "output_tokens": result.output_tokens if result else 0,
            "stop": result.stop if result else "error",
        }
        await emit(
            {"type": "side.finished", **{k: v for k, v in out.items() if k != "environment"}}
        )
        return out

    async def aclose(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
