"""Detection pipeline for tool results (and the secret scan on call arguments).

Order: heuristics -> classifier (if loaded) -> LLM judge (gray zone, if enabled)
-> secrets -> PII. CPU-heavy stages run in worker threads so the event loop
keeps serving other requests.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from tripwire.models import CONFIDENTIALITY_ORDER, Confidentiality, DetectorResult
from tripwire.pipeline import heuristics, secrets
from tripwire.pipeline.classifier import InjectionClassifier
from tripwire.pipeline.llm_judge import Judge
from tripwire.pipeline.normalize import flatten_strings
from tripwire.pipeline.pii import PiiDetector

T = TypeVar("T")


@dataclass(slots=True)
class Analysis:
    detectors: list[DetectorResult]
    injection_score: float
    suspicious: bool
    secrets_found: bool
    pii_found: bool
    timings: dict[str, float] = field(default_factory=dict)

    def confidentiality_floor(self) -> Confidentiality:
        if self.secrets_found:
            return "secret"
        if self.pii_found:
            return "confidential"
        return "public"


def raise_confidentiality(base: Confidentiality, floor: Confidentiality) -> Confidentiality:
    return base if CONFIDENTIALITY_ORDER[base] >= CONFIDENTIALITY_ORDER[floor] else floor


def content_text(content: Any) -> str:
    return "\n".join(flatten_strings(content))


def redact_secrets_in(content: Any) -> Any:
    """Redact secrets in every string leaf, preserving structure."""
    if isinstance(content, str):
        return secrets.redact(content)
    if isinstance(content, dict):
        return {k: redact_secrets_in(v) for k, v in content.items()}
    if isinstance(content, list):
        return [redact_secrets_in(v) for v in content]
    return content


class DetectionPipeline:
    def __init__(
        self,
        classifier: InjectionClassifier | None = None,
        judge: Judge | None = None,
        pii: PiiDetector | None = None,
    ) -> None:
        self.classifier = classifier
        self.judge = judge
        self.pii = pii

    async def _timed(
        self, timings: dict[str, float], name: str, fn: Callable[[], Awaitable[T]]
    ) -> T:
        start = time.perf_counter()
        try:
            return await fn()
        finally:
            timings[name] = round((time.perf_counter() - start) * 1000, 3)

    async def analyze(
        self, text: str, suspicious_threshold: float, classifier_threshold: float
    ) -> Analysis:
        timings: dict[str, float] = {}
        results: list[DetectorResult] = []

        start = time.perf_counter()
        h = heuristics.score_text(text)
        timings["heuristics"] = round((time.perf_counter() - start) * 1000, 3)
        results.append(h)
        score = h.score

        if self.classifier is not None and self.classifier.available:
            c = await self._timed(
                timings,
                "classifier",
                lambda: asyncio.to_thread(self.classifier.score, text),  # type: ignore[union-attr]
            )
            results.append(c)
            score = max(score, c.score)

        suspicious = score >= suspicious_threshold
        if suspicious and score < classifier_threshold and self.judge is not None:
            spans = [s for r in results for s in r.spans]
            judge = self.judge
            verdict = await self._timed(timings, "llm_judge", lambda: judge.judge(text, spans))
            if verdict is not None:
                results.append(verdict)
                # The judge decides the gray zone; a failed judge keeps it suspicious.
                suspicious = verdict.score >= 0.5
        start = time.perf_counter()
        s = secrets.scan(text)
        timings["secrets"] = round((time.perf_counter() - start) * 1000, 3)
        results.append(s)

        pii_found = False
        if self.pii is not None:
            pii = self.pii
            p = await self._timed(timings, "pii", lambda: asyncio.to_thread(pii.scan, text))
            results.append(p)
            pii_found = bool(p.spans)

        return Analysis(
            detectors=results,
            injection_score=score,
            suspicious=suspicious,
            secrets_found=bool(s.spans),
            pii_found=pii_found,
            timings=timings,
        )
