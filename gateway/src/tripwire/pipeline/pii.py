"""PII detection with Presidio, configured for gateway latency.

Presidio is configured explicitly with spaCy ``en_core_web_sm`` so it never
tries to download ``en_core_web_lg`` at runtime.

Two modes:

* ``patterns`` (default): the model's tokenizer only, no statistical pipes, and
  pattern recognizers for structured identifiers (email, phone, card, SSN, IBAN,
  IP). Presidio's stock phone recognizer (libphonenumber's matcher) is replaced
  by a regex recognizer: on number-dense 50 KB inputs the stock one takes about
  1 s, which no inline gateway can afford.
* ``ner``: the full ``en_core_web_sm`` pipeline adds PERSON and LOCATION. Off by
  default because names appear in nearly every email and would mark every
  result confidential.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Literal

import spacy
from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)
from presidio_analyzer.context_aware_enhancers import ContextAwareEnhancer
from presidio_analyzer.nlp_engine import NlpArtifacts, NlpEngineProvider

from tripwire.models import DetectorResult

# Presidio logs every recognizer it loads (INFO) and every non-English one it skips
# (WARNING); keep startup output readable.
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

PiiMode = Literal["patterns", "ner"]

SPACY_MODEL = "en_core_web_sm"
PATTERN_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "IP_ADDRESS",
)
NER_ENTITIES = ("PERSON", "LOCATION")
MIN_SCORE = 0.4


class _NoContextEnhancer(ContextAwareEnhancer):
    """Skip context scoring. Presidio's lemma enhancer is O(matches x tokens),
    about 0.5 s on a number-dense 50 KB input, and needs lemmas that pattern mode
    does not compute anyway."""

    def __init__(self) -> None:
        super().__init__(
            context_similarity_factor=0.0,
            min_score_with_context_similarity=0.0,
            context_prefix_count=0,
            context_suffix_count=0,
        )

    def enhance_using_context(
        self,
        text: str,
        raw_results: list[RecognizerResult],
        nlp_artifacts: NlpArtifacts,
        recognizers: list[EntityRecognizer],
        context: list[str] | None = None,
    ) -> list[RecognizerResult]:
        return raw_results


_PHONE = PatternRecognizer(
    supported_entity="PHONE_NUMBER",
    name="TripwirePhoneRecognizer",
    patterns=[
        Pattern(
            "intl_or_us_phone",
            r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]\d{3,4}(?!\w)",
            0.6,
        ),
    ],
    context=["phone", "call", "tel", "mobile", "cell", "fax", "whatsapp", "sms"],
)


@dataclass(frozen=True, slots=True)
class PiiMatch:
    entity: str
    start: int
    end: int
    score: float


class PiiDetector:
    def __init__(self, mode: PiiMode = "patterns") -> None:
        self.mode = mode
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
            }
        )
        nlp_engine = provider.create_engine()
        if mode == "patterns":
            # Same tokenizer as en_core_web_sm, none of its statistical pipes.
            full = nlp_engine.nlp["en"]  # type: ignore[attr-defined]
            nlp_engine.nlp["en"] = spacy.load(SPACY_MODEL, exclude=list(full.pipe_names))  # type: ignore[attr-defined]
        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"],
            context_aware_enhancer=_NoContextEnhancer() if mode == "patterns" else None,
        )
        registry = self._analyzer.registry
        registry.remove_recognizer("PhoneRecognizer")
        registry.add_recognizer(_PHONE)
        self.entities = list(PATTERN_ENTITIES) + (list(NER_ENTITIES) if mode == "ner" else [])
        # spaCy pipelines are not guaranteed thread-safe; detection runs in worker threads.
        self._lock = threading.Lock()

    def find(self, text: str) -> list[PiiMatch]:
        if not text.strip():
            return []
        with self._lock:
            results: list[RecognizerResult] = self._analyzer.analyze(
                text=text, language="en", entities=self.entities, score_threshold=MIN_SCORE
            )
        matches = [PiiMatch(r.entity_type, r.start, r.end, float(r.score)) for r in results]
        # Card and IBAN digits also look like phone numbers; keep the stronger entity.
        strong = [(m.start, m.end) for m in matches if m.entity in ("CREDIT_CARD", "IBAN_CODE")]
        matches = [
            m
            for m in matches
            if not (
                m.entity == "PHONE_NUMBER" and any(s <= m.start and m.end <= e for s, e in strong)
            )
        ]
        return sorted(matches, key=lambda m: m.start)

    def scan(self, text: str) -> DetectorResult:
        found = self.find(text)
        kinds = sorted({m.entity for m in found})
        return DetectorResult(
            detector="pii",
            score=max((m.score for m in found), default=0.0),
            spans=[(m.start, m.end) for m in found],
            reason=", ".join(f"{k}x{sum(m.entity == k for m in found)}" for k in kinds) or "no pii",
        )
