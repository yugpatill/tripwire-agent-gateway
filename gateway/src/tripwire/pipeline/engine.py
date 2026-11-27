"""Decision engine: orchestrates stages, times each, and fails closed."""

from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

import structlog

from tripwire.approvals.service import ApprovalService
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
from tripwire.pipeline import secrets as secret_scan
from tripwire.pipeline.detect import (
    DetectionPipeline,
    content_text,
    raise_confidentiality,
    redact_secrets_in,
)
from tripwire.pipeline.recorder import EventRecord, Recorder, SessionRecord
from tripwire.policy.compiler import UNKNOWN_TOOL_SPEC, CallFacts, CompiledPolicy
from tripwire.policy.evaluate import Evaluation, evaluate
from tripwire.taint.entities import entity_keys
from tripwire.taint.labels import USER_SOURCE, Provenance
from tripwire.taint.propagate import (
    NO_PROMPT_SOURCE,
    ValueIndex,
    label_args,
    tag_content,
    tag_text,
)
from tripwire.taint.store import CallRecord, SessionState, TaintStore

log = structlog.get_logger(__name__)

ENGINE_ERROR_RULE = "engine-error"
UNKNOWN_SESSION_RULE = "unknown-session"
REDACTED = "[REDACTED]"


def _redact_value(value: Any) -> Any:
    """Mask detected secrets inside a value; if none are found, mask the whole value."""
    if isinstance(value, str):
        found = secret_scan.find_secrets(value)
        return secret_scan.redact(value, found) if found else REDACTED
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return REDACTED


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


MAX_SHADOW_TASKS = 4


class Engine:
    def __init__(
        self,
        store: TaintStore,
        recorder: Recorder,
        policy: CompiledPolicy | None,
        default_mode: str = "enforce",
        index_cache_size: int = 2048,
        detection: DetectionPipeline | None = None,
        approvals: ApprovalService | None = None,
    ) -> None:
        self.store = store
        # None: require_approval decisions get no approval record (callers deny them).
        self.approvals = approvals
        self.recorder = recorder
        self.policy = policy  # None => policy failed to load: every decision fails closed
        self.default_mode = default_mode
        # Per-session value index, extended incrementally (values are append-only in the
        # store, which stays the source of truth across workers).
        self._indexes: OrderedDict[UUID, ValueIndex] = OrderedDict()
        self.index_cache_size = index_cache_size
        self.detection = detection or DetectionPipeline()
        # Background shadow-classifier tasks (detection.classifier_shadow). Bounded so a
        # burst of large results cannot queue unbounded CPU work behind live requests.
        self._shadow_tasks: set[asyncio.Task[None]] = set()
        self.max_shadow_tasks = MAX_SHADOW_TASKS

    async def _value_index(self, session_id: UUID) -> ValueIndex:
        idx = self._indexes.get(session_id)
        stored = await self.store.count_values(session_id)
        if idx is None or len(idx) > stored:
            idx = ValueIndex()
            self._indexes[session_id] = idx
        self._indexes.move_to_end(session_id)
        while len(self._indexes) > self.index_cache_size:
            self._indexes.popitem(last=False)
        if len(idx) < stored:
            start = len(idx)
            new = await self.store.get_values(session_id, start)
            # Another coroutine may have extended the index while we awaited.
            idx.extend(new[len(idx) - start :])
        return idx

    # ---------- sessions ----------

    async def create_session(self, req: SessionCreate, owner: UUID | None = None) -> UUID:
        session_id = uuid.uuid4()
        entities = entity_keys(req.user_prompt)
        await self.store.create_session(
            SessionState(session_id=session_id, mode=req.mode, owner=owner)
        )
        # The prompt itself is a trusted value; its event id is the session id.
        prompt_label = Provenance(
            source=USER_SOURCE, trust="trusted", confidentiality="internal", event_id=session_id
        )
        if req.user_prompt.strip():
            await self.store.add_values(session_id, [tag_text(req.user_prompt, prompt_label)])
        await self.recorder.record_session(
            SessionRecord(session_id, req.agent_name, req.user_prompt, entities, req.mode, owner)
        )
        return session_id

    async def add_user_prompt(self, session_id: UUID, text: str, owner: UUID | None = None) -> bool:
        """Add a user turn to an existing session (trusted, for instruction origin).

        Only the client application may call this (the model cannot set headers or
        call the REST API). Returns False when the same text is already known.
        """
        await self._owned_session(session_id, owner)
        text = text.strip()
        if not text:
            return False
        label = Provenance(
            source=USER_SOURCE, trust="trusted", confidentiality="internal", event_id=uuid.uuid4()
        )
        tagged = tag_text(text, label)
        index = await self._value_index(session_id)
        if tagged.value in index.prompt_texts:
            return False
        await self.store.add_values(session_id, [tagged])
        log.info("session.user_prompt_added", session_id=str(session_id), chars=len(text))
        return True

    # ---------- tool calls ----------

    async def check_call(self, call: ToolCall, owner: UUID | None = None) -> Decision:
        event_id = uuid.uuid4()
        timer = StageTimer()
        try:
            return await self._check_call(call, event_id, timer, owner)
        except Exception as exc:
            return await self._fail_closed(
                call.session_id, call.tool, "call", call.args, event_id, timer, exc
            )

    async def _check_call(
        self, call: ToolCall, event_id: UUID, timer: StageTimer, owner: UUID | None
    ) -> Decision:
        policy = self._require_policy()
        with timer.stage("load_session"):
            session = await self._owned_session(call.session_id, owner)
            index = await self._value_index(call.session_id)
        with timer.stage("propagate"):
            labelling = label_args(
                call.args,
                index,
                session,
                event_id,
                origin_without_prompt=policy.doc.defaults.instruction_origin == "strict",
            )
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

        counts: dict[str, int] = {}

        async def counter(rule_id: str) -> int:
            counts[rule_id] = await self.store.incr_counter(call.session_id, f"rule:{rule_id}")
            return counts[rule_id]

        with timer.stage("evaluate"):
            ev = await evaluate(policy, facts, counter)
            if ev.action == "block" and policy.doc.defaults.no_prompt_action != "block":
                ev = await self._soften_no_prompt_block(policy, facts, ev, counts)

        with timer.stage("secrets"):
            arg_detectors = [secret_scan.scan(content_text(call.args))]
            arg_detectors = [d for d in arg_detectors if d.spans]

        computed: Action = ev.action
        redacted: dict[str, Any] | None = None
        if computed == "redact":
            targets = ev.redact_args
            names = set(call.args) if None in targets else {t for t in targets if t is not None}
            redacted = {k: (_redact_value(v) if k in names else v) for k, v in call.args.items()}

        enforced = self._enforced(computed, session.mode)
        message = ev.message
        if enforced != computed:
            message = f"[shadow] would {computed}: {message}"
        elif (
            enforced == "require_approval"
            and self.approvals is not None
            and await self.approvals.session_granted(call.session_id, call.tool)
        ):
            enforced = "allow"
            message = f"Approved for this session by an operator. Rule said: {message}"

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
            detectors=arg_detectors,
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
                detectors=[d.model_dump(mode="json") for d in arg_detectors],
                edges=[e.model_dump(mode="json") for e in labelling.edges],
                latency_ms=timer.total_ms,
                stage_timings=dict(timer.timings),
            )
        )
        if enforced == "require_approval" and self.approvals is not None:
            with timer.stage("approval"):
                rec = await self.approvals.request_call(
                    call.session_id, event_id, call.tool, call.args, ev.rule_id, message
                )
            decision.approval_id = rec.id
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

    @staticmethod
    async def _soften_no_prompt_block(
        policy: CompiledPolicy, facts: CallFacts, ev: Evaluation, counts: dict[str, int]
    ) -> Evaluation:
        """A block caused only by a missing user prompt becomes `no_prompt_action`.

        Re-evaluates without the no-prompt origin labels. If nothing else blocks,
        the call needs approval instead (the user may simply have typed that
        address in a client that never told Tripwire). Rate-limit counters are not
        incremented a second time.
        """
        if not any(
            p.source == NO_PROMPT_SOURCE for labels in facts.arg_labels.values() for p in labels
        ):
            return ev
        stripped = {
            arg: [p for p in labels if p.source != NO_PROMPT_SOURCE]
            for arg, labels in facts.arg_labels.items()
        }

        async def replay(rule_id: str) -> int:
            # The first pass already counted this call for every limit rule that
            # matched; removing labels can only make fewer rules match.
            return counts.get(rule_id, 0)

        again = await evaluate(policy, dataclasses.replace(facts, arg_labels=stripped), replay)
        if again.action == "block":
            return ev
        return Evaluation(
            action=policy.doc.defaults.no_prompt_action,
            rule_id=ev.rule_id,
            message=(
                f"{ev.message} No user prompt is known for this session, so the address or "
                "value may have come from the user; an operator must approve it."
            ),
            hits=ev.hits,
        )

    # ---------- tool results ----------

    async def check_result(self, result: ToolResult, owner: UUID | None = None) -> ResultCheck:
        event_id = uuid.uuid4()
        timer = StageTimer()
        try:
            return await self._check_result(result, event_id, timer, owner)
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
        self, result: ToolResult, event_id: UUID, timer: StageTimer, owner: UUID | None
    ) -> ResultCheck:
        policy = self._require_policy()
        with timer.stage("load_session"):
            session = await self._owned_session(result.session_id, owner)
            call = await self.store.get_call(result.session_id, result.call_event_id)
        spec = policy.tool_spec(result.tool) or UNKNOWN_TOOL_SPEC
        base_conf = policy.result_confidentiality(result.tool, call.args if call else {})
        defaults = policy.doc.defaults

        analysis = await self.detection.analyze(
            content_text(result.content),
            defaults.suspicious_threshold,
            defaults.classifier_threshold,
            policy.doc.detection.combine,
        )
        timer.timings.update(analysis.timings)

        # Injection-looking content is suspicious whatever tool returned it.
        trust: Trust = "suspicious" if analysis.suspicious else spec.trust
        confidentiality = raise_confidentiality(base_conf, analysis.confidentiality_floor())
        label = Provenance(
            source=result.tool, trust=trust, confidentiality=confidentiality, event_id=event_id
        )
        with timer.stage("tag"):
            # Tag the original content so later exfiltration of a secret still matches,
            # even though the agent only ever sees the redacted copy.
            tagged = tag_content(result.content, label)
        content_out = (
            redact_secrets_in(result.content) if analysis.secrets_found else result.content
        )
        with timer.stage("persist"):
            await self.store.add_values(result.session_id, tagged)
            await self.store.mark_context(
                result.session_id,
                confidentiality=confidentiality,
                untrusted=trust != "trusted",
                suspicious=trust == "suspicious",
            )
            enforced = self._enforced("allow", session.mode)
            message = (
                f"Suspicious content (injection score {analysis.injection_score:.2f}); "
                "session marked suspicious."
                if analysis.suspicious
                else "Result labelled."
            )
            detectors = [d for d in analysis.detectors if d.score > 0 or d.spans]
            decision = Decision(
                event_id=event_id,
                action=enforced,
                rule_id=None,
                message=message,
                arg_labels={},
                detectors=detectors,
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
                    detectors=[d.model_dump(mode="json") for d in detectors],
                    edges=[],
                    latency_ms=timer.total_ms,
                    stage_timings=timer.timings,
                )
            )
        decision.latency_ms = timer.total_ms
        if policy.doc.detection.classifier_shadow:
            self._start_shadow(event_id, content_text(result.content), analysis.suspicious)
        return ResultCheck(
            content_redacted=content_out, labels=[label], detectors=detectors, decision=decision
        )

    # ---------- shadow classifier ----------

    def _start_shadow(self, event_id: UUID, text: str, suspicious: bool) -> None:
        """Classify the result off the request path; the decision is already made."""
        if len(self._shadow_tasks) >= self.max_shadow_tasks:
            log.warning("classifier.shadow_dropped", event_id=str(event_id), reason="busy")
            return
        task = asyncio.create_task(self._shadow(event_id, text, suspicious))
        self._shadow_tasks.add(task)
        task.add_done_callback(self._shadow_tasks.discard)

    async def _shadow(self, event_id: UUID, text: str, suspicious: bool) -> None:
        try:
            await asyncio.sleep(0)  # let the response go out first
            r = await self.detection.shadow_classify(text)
            if r is None:
                return
            log.info(
                "classifier.shadow",
                event_id=str(event_id),
                score=r.score,
                would_flag=r.score >= 0.5,
                decision_suspicious=suspicious,
            )
            await self.recorder.add_detector(event_id, r.model_dump(mode="json"))
        except Exception as exc:  # shadow work must never surface
            log.warning("classifier.shadow_failed", event_id=str(event_id), error=repr(exc))

    async def drain_shadow(self) -> None:
        """Wait for pending shadow tasks (tests and shutdown)."""
        if self._shadow_tasks:
            await asyncio.gather(*self._shadow_tasks, return_exceptions=True)

    # ---------- helpers ----------

    async def _owned_session(self, session_id: UUID, owner: UUID | None) -> SessionState:
        """Load a session; another key's session is reported as unknown (no oracle)."""
        session = await self.store.get_session(session_id)
        if session is None or (session.owner is not None and session.owner != owner):
            raise UnknownSessionError(str(session_id))
        return session

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
