"""Decision engine: orchestrates stages, times each, and fails closed."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

import structlog

from tripwire.models import (
    CONFIDENTIALITY_ORDER,
    Action,
    Decision,
    ResultCheck,
    SessionCreate,
    ToolCall,
    ToolResult,
    Trust,
    max_confidentiality,
)
from tripwire.pipeline.recorder import EventRecord, Recorder, SessionRecord
from tripwire.policy.compiler import UNKNOWN_TOOL_SPEC, CallFacts, CompiledPolicy
from tripwire.policy.evaluate import evaluate
from tripwire.taint.entities import entity_keys
from tripwire.taint.labels import USER_SOURCE, Provenance
from tripwire.taint.propagate import label_args, tag_content, tag_text
from tripwire.taint.store import CallRecord, SessionState, TaintStore

log = structlog.get_logger(__name__)

ENGINE_ERROR_RULE = "engine-error"
UNKNOWN_SESSION_RULE = "unknown-session"
REDACTED = "[REDACTED]"


class UnknownSessionError(Exception):
    pass


class StageTimer:
    def __init__(self) -> None:
        self.timings: dict[str, float] = {}
        self._t0 = time.perf_counter()

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.timings[name] = round((time.perf_counter() - start) * 1000, 3)

    @property
    def total_ms(self) -> float:
        return round((time.perf_counter() - self._t0) * 1000, 3)


class Engine:
    def __init__(
        self,
        store: TaintStore,
        recorder: Recorder,
        policy: CompiledPolicy | None,
        default_mode: str = "enforce",
    ) -> None:
        self.store = store
        self.recorder = recorder
        self.policy = policy  # None => policy failed to load: every decision fails closed
        self.default_mode = default_mode

    # ---------- sessions ----------

    async def create_session(self, req: SessionCreate) -> UUID:
        session_id = uuid.uuid4()
        entities = entity_keys(req.user_prompt)
        await self.store.create_session(SessionState(session_id=session_id, mode=req.mode))
        # The prompt itself is a trusted value; its event id is the session id.
        prompt_label = Provenance(
            source=USER_SOURCE, trust="trusted", confidentiality="internal", event_id=session_id
        )
        if req.user_prompt.strip():
            await self.store.add_values(session_id, [tag_text(req.user_prompt, prompt_label)])
        await self.recorder.record_session(
            SessionRecord(session_id, req.agent_name, req.user_prompt, entities, req.mode)
        )
        return session_id

    # ---------- tool calls ----------

    async def check_call(self, call: ToolCall) -> Decision:
        event_id = uuid.uuid4()
        timer = StageTimer()
        try:
            return await self._check_call(call, event_id, timer)
        except Exception as exc:
            return await self._fail_closed(
                call.session_id, call.tool, "call", call.args, event_id, timer, exc
            )

    async def _check_call(self, call: ToolCall, event_id: UUID, timer: StageTimer) -> Decision:
        policy = self._require_policy()
        with timer.stage("load_session"):
            session = await self.store.get_session(call.session_id)
            if session is None:
                raise UnknownSessionError(str(call.session_id))
            values = await self.store.get_values(call.session_id)
        prompt_entities = {
            k for tv in values if tv.provenance.source == USER_SOURCE for k in tv.entities
        }
        with timer.stage("propagate"):
            labelling = label_args(call.args, values, prompt_entities, session, event_id)
        spec = policy.tool_spec(call.tool)
        facts = CallFacts(
            tool=call.tool,
            tool_spec=spec or UNKNOWN_TOOL_SPEC,
            tool_known=spec is not None,
            arg_labels=labelling.arg_labels,
            arg_text=labelling.arg_text,
            context_confidentiality=session.max_confidentiality,
            session_suspicious=session.suspicious,
        )

        async def counter(rule_id: str) -> int:
            return await self.store.incr_counter(call.session_id, f"rule:{rule_id}")

        with timer.stage("evaluate"):
            ev = await evaluate(policy, facts, counter)

        computed: Action = ev.action
        redacted: dict[str, Any] | None = None
        if computed == "redact":
            targets = ev.redact_args
            names = set(call.args) if None in targets else {t for t in targets if t is not None}
            redacted = {k: (REDACTED if k in names else v) for k, v in call.args.items()}

        enforced = self._enforced(computed, session.mode)
        message = ev.message
        if enforced != computed:
            message = f"[shadow] would {computed}: {message}"

        with timer.stage("persist"):
            await self.store.record_call(
                call.session_id, CallRecord(event_id=event_id, tool=call.tool, args=call.args)
            )
            decision = Decision(
                event_id=event_id,
                action=enforced,
                rule_id=ev.rule_id,
                message=message,
                arg_labels=labelling.arg_labels,
                detectors=[],
                redacted_args=redacted if enforced == "redact" else None,
                latency_ms=0.0,
                approval_id=None,
            )
            await self.recorder.record_event(
                EventRecord(
                    id=event_id,
                    session_id=call.session_id,
                    kind="call",
                    tool=call.tool,
                    payload={"args": call.args},
                    action=computed,
                    enforced_action=enforced,
                    rule_id=ev.rule_id,
                    message=message,
                    labels={
                        k: [p.model_dump(mode="json") for p in v]
                        for k, v in labelling.arg_labels.items()
                    },
                    detectors=[],
                    edges=[e.model_dump(mode="json") for e in labelling.edges],
                    latency_ms=timer.total_ms,
                    stage_timings=timer.timings,
                )
            )
        decision.latency_ms = timer.total_ms
        log.info(
            "decision.call",
            session_id=str(call.session_id),
            tool=call.tool,
            action=enforced,
            computed=computed,
            rule_id=ev.rule_id,
            latency_ms=decision.latency_ms,
        )
        return decision

    # ---------- tool results ----------

    async def check_result(self, result: ToolResult) -> ResultCheck:
        event_id = uuid.uuid4()
        timer = StageTimer()
        try:
            return await self._check_result(result, event_id, timer)
        except Exception as exc:
            decision = await self._fail_closed(
                result.session_id,
                result.tool,
                "result",
                {"call_event_id": str(result.call_event_id)},
                event_id,
                timer,
                exc,
            )
            # Never hand back content we could not vet.
            return ResultCheck(
                content_redacted=REDACTED, labels=[], detectors=[], decision=decision
            )

    async def _check_result(
        self, result: ToolResult, event_id: UUID, timer: StageTimer
    ) -> ResultCheck:
        policy = self._require_policy()
        with timer.stage("load_session"):
            session = await self.store.get_session(result.session_id)
            if session is None:
                raise UnknownSessionError(str(result.session_id))
            call = await self.store.get_call(result.session_id, result.call_event_id)
        spec = policy.tool_spec(result.tool) or UNKNOWN_TOOL_SPEC
        confidentiality = policy.result_confidentiality(result.tool, call.args if call else {})
        # Phase 3 detectors may raise this to "suspicious".
        trust: Trust = spec.trust
        label = Provenance(
            source=result.tool, trust=trust, confidentiality=confidentiality, event_id=event_id
        )
        with timer.stage("tag"):
            tagged = tag_content(result.content, label)
        with timer.stage("persist"):
            await self.store.add_values(result.session_id, tagged)
            await self.store.mark_context(
                result.session_id,
                confidentiality=confidentiality,
                untrusted=trust != "trusted",
                suspicious=trust == "suspicious",
            )
            enforced = self._enforced("allow", session.mode)
            decision = Decision(
                event_id=event_id,
                action=enforced,
                rule_id=None,
                message="Result labelled.",
                arg_labels={},
                detectors=[],
                redacted_args=None,
                latency_ms=0.0,
                approval_id=None,
            )
            ctx_conf = max_confidentiality(session.max_confidentiality, confidentiality)
            await self.recorder.record_event(
                EventRecord(
                    id=event_id,
                    session_id=result.session_id,
                    kind="result",
                    tool=result.tool,
                    payload={"call_event_id": str(result.call_event_id), "content": result.content},
                    action="allow",
                    enforced_action=enforced,
                    rule_id=None,
                    message=decision.message,
                    labels={
                        "result": [label.model_dump(mode="json")],
                        "context_confidentiality": ctx_conf,
                    },
                    detectors=[],
                    edges=[],
                    latency_ms=timer.total_ms,
                    stage_timings=timer.timings,
                )
            )
        decision.latency_ms = timer.total_ms
        return ResultCheck(
            content_redacted=result.content, labels=[label], detectors=[], decision=decision
        )

    # ---------- helpers ----------

    def _require_policy(self) -> CompiledPolicy:
        if self.policy is None:
            raise RuntimeError("no active policy loaded")
        return self.policy

    def _enforced(self, computed: Action, session_mode: str) -> Action:
        shadow = session_mode == "shadow" or self.default_mode == "shadow"
        return "log_only" if shadow and computed != "allow" else computed

    async def _fail_closed(
        self,
        session_id: UUID,
        tool: str,
        kind: str,
        payload: dict[str, Any],
        event_id: UUID,
        timer: StageTimer,
        exc: Exception,
    ) -> Decision:
        unknown = isinstance(exc, UnknownSessionError)
        rule_id = UNKNOWN_SESSION_RULE if unknown else ENGINE_ERROR_RULE
        action: Action = "block"
        if not unknown and self.policy is not None:
            action = self.policy.doc.defaults.on_engine_error
        message = (
            "Unknown session; create one with POST /v1/sessions first."
            if unknown
            else "Tripwire could not evaluate this request and blocked it (fail closed)."
        )
        log.error("decision.fail_closed", tool=tool, kind=kind, rule_id=rule_id, error=repr(exc))
        if not unknown:
            # Best effort: an engine error is worth recording, but recording must not raise.
            try:
                await self.recorder.record_event(
                    EventRecord(
                        id=event_id,
                        session_id=session_id,
                        kind=kind,
                        tool=tool,
                        payload=payload,
                        action=action,
                        enforced_action=action,
                        rule_id=rule_id,
                        message=message,
                        labels={},
                        detectors=[],
                        edges=[],
                        latency_ms=timer.total_ms,
                        stage_timings={**timer.timings, "error": 0.0},
                    )
                )
            except Exception as rec_exc:
                log.error("decision.record_failed", error=repr(rec_exc))
        return Decision(
            event_id=event_id,
            action=action,
            rule_id=rule_id,
            message=message,
            arg_labels={},
            detectors=[],
            redacted_args=None,
            latency_ms=timer.total_ms,
            approval_id=None,
        )


__all__ = ["CONFIDENTIALITY_ORDER", "Engine", "StageTimer", "UnknownSessionError"]
