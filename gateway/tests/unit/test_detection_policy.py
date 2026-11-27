"""detection.combine and detection.classifier_shadow, end to end through the engine."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tripwire.models import DetectorResult, ToolCall, ToolResult
from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.engine import Engine
from tripwire.pipeline.recorder import MemoryRecorder
from tripwire.taint.store import InMemoryTaintStore

from .helpers import policy_from, session

CLEAN = "The city council approved the new bike lanes on Tuesday."


class StubClassifier:
    """Flags everything; counts calls and records how it was asked to select windows."""

    available = True

    def __init__(self, score: float = 0.9, delay: float = 0.0) -> None:
        self.calls: list[bool] = []
        self._score = score
        self._delay = delay

    def score(
        self, text: str, focus: list[tuple[int, int]] | None = None, signal_only: bool = False
    ) -> DetectorResult:
        if self._delay:
            import time

            time.sleep(self._delay)
        self.calls.append(signal_only)
        return DetectorResult(detector="classifier", score=self._score, spans=[], reason="stub")


def _policy(combine: str, shadow: bool) -> Any:
    return policy_from(
        f"""version: 1
detection:
  combine: {combine}
  classifier_shadow: {str(shadow).lower()}
tools:
  web__fetch: {{trust: untrusted}}
"""
    )


def _engine(clf: StubClassifier, combine: str, shadow: bool) -> Engine:
    return Engine(
        InMemoryTaintStore(),
        MemoryRecorder(),
        _policy(combine, shadow),
        detection=DetectionPipeline(classifier=clf),  # type: ignore[arg-type]
    )


async def _result(engine: Engine, content: str) -> Any:
    sid = await session(engine, "summarize the page")
    d = await engine.check_call(ToolCall(session_id=sid, tool="web__fetch", args={"url": "u"}))
    return await engine.check_result(
        ToolResult(session_id=sid, tool="web__fetch", call_event_id=d.event_id, content=content)
    )


@pytest.mark.parametrize(("combine", "suspicious"), [("corroborated", False), ("either", True)])
async def test_policy_combine_setting_drives_the_verdict(combine: str, suspicious: bool) -> None:
    clf = StubClassifier()
    res = await _result(_engine(clf, combine, shadow=False), CLEAN)
    assert (res.labels[0].trust == "suspicious") is suspicious
    assert len(clf.calls) == (0 if combine == "corroborated" else 1)


async def test_shadow_runs_after_the_decision_and_never_changes_it() -> None:
    clf = StubClassifier(score=0.9)
    engine = _engine(clf, "corroborated", shadow=True)
    res = await _result(engine, CLEAN)
    assert res.labels[0].trust == "untrusted"  # decision made without the classifier
    assert not any(d.detector.startswith("classifier") for d in res.detectors)
    await engine.drain_shadow()
    assert clf.calls == [False]  # full default window selection
    ev = engine.recorder.events[-1]  # type: ignore[attr-defined]
    assert ev.kind == "result"
    assert [d["detector"] for d in ev.detectors][-1] == "classifier_shadow"


async def test_shadow_off_by_default_and_failures_are_swallowed() -> None:
    clf = StubClassifier()
    engine = _engine(clf, "corroborated", shadow=False)
    await _result(engine, CLEAN)
    await engine.drain_shadow()
    assert clf.calls == []

    class Boom(StubClassifier):
        def score(self, *a: Any, **k: Any) -> DetectorResult:
            raise RuntimeError("boom")

    engine = _engine(Boom(), "corroborated", shadow=True)
    res = await _result(engine, CLEAN)
    await engine.drain_shadow()
    assert res.decision.action == "allow"


async def test_shadow_queue_is_bounded() -> None:
    clf = StubClassifier(delay=0.05)
    engine = _engine(clf, "corroborated", shadow=True)
    engine.max_shadow_tasks = 1
    await asyncio.gather(*[_result(engine, CLEAN) for _ in range(3)])
    await engine.drain_shadow()
    assert 1 <= len(clf.calls) < 3
