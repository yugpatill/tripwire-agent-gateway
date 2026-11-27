"""Label tool-call arguments with the provenance of the data they carry.

Three mechanisms (docs/design.md section 1):

1. **Value matching**: an argument (or part of it) equals or contains a value seen
   earlier in the session; matched exactly, after normalization, or by entity
   (email, URL, path, long number).
2. **Context taint**: the session as a whole records the highest confidentiality
   and whether untrusted or suspicious content was ever seen. Rules read this via
   ``context_confidentiality_at_least`` and ``session_has``; it is kept separate from
   per-argument labels so one web fetch does not taint every later argument.
3. **Instruction origin**: entities in an argument that the user typed in their
   prompt are labelled ``user``/trusted and are not tainted by untrusted copies of
   the same entity. Entities that come from no known source while untrusted content
   is in context are labelled ``untrusted_origin``: the model likely got them from
   an injection, possibly paraphrased.

   When no user prompt is known for the session (typical in MCP mode, where the
   client never sends one), the policy's ``defaults.instruction_origin`` decides:
   ``strict`` (default) keeps labelling unknown entities ``untrusted_origin``
   once untrusted content is in context; ``off`` skips that label. Value matching
   is unaffected, so an entity copied from untrusted content is tainted either way.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

from tripwire.models import DataFlowEdge
from tripwire.pipeline.normalize import flatten_strings, normalize
from tripwire.taint.entities import extract
from tripwire.taint.labels import USER_SOURCE, Provenance, TaggedValue
from tripwire.taint.store import SessionState

MIN_TEXT_MATCH = 8  # characters; shorter residual text is too ambiguous to match
MAX_LEAF_CHARS = 50_000
UNKNOWN_SOURCE = "unknown"

MatchKind = Literal["exact", "normalized", "entity", "user_prompt", "origin"]


def tag_text(text: str, provenance: Provenance) -> TaggedValue:
    text = text[:MAX_LEAF_CHARS]
    return TaggedValue(
        value=text,
        normalized=normalize(text),
        entities=sorted({e.key for e in extract(text)}),
        provenance=provenance,
    )


def tag_content(content: Any, provenance: Provenance) -> list[TaggedValue]:
    return [tag_text(s, provenance) for s in flatten_strings(content) if s.strip()]


class ValueIndex:
    """Session values plus an entity -> values index. Append-only, so it can be
    cached per session and extended incrementally as new results arrive."""

    __slots__ = ("by_entity", "prompt_entities", "prompt_texts", "values")

    def __init__(self, values: Iterable[TaggedValue] = ()) -> None:
        self.values: list[TaggedValue] = []
        self.by_entity: dict[str, list[TaggedValue]] = {}
        self.prompt_entities: set[str] = set()
        self.prompt_texts: set[str] = set()
        self.extend(values)

    @property
    def prompt_known(self) -> bool:
        """At least one user prompt (possibly without entities) is in the session."""
        return bool(self.prompt_texts)

    def __len__(self) -> int:
        return len(self.values)

    def extend(self, values: Iterable[TaggedValue]) -> None:
        for tv in values:
            self.values.append(tv)
            for key in tv.entities:
                self.by_entity.setdefault(key, []).append(tv)
            if tv.provenance.source == USER_SOURCE:
                self.prompt_entities.update(tv.entities)
                self.prompt_texts.add(tv.value)


@dataclass(slots=True)
class ArgLabelling:
    arg_labels: dict[str, list[Provenance]] = field(default_factory=dict)
    arg_text: dict[str, list[str]] = field(default_factory=dict)
    edges: list[DataFlowEdge] = field(default_factory=list)


def _residual(text: str, spans: Iterable[tuple[int, int]]) -> str:
    out, pos = [], 0
    for s, e in sorted(spans):
        out.append(text[pos:s])
        pos = max(pos, e)
    out.append(text[pos:])
    return " ".join(p.strip() for p in out if p.strip())


def _text_match(raw: str, norm: str, tv: TaggedValue) -> MatchKind | None:
    """Return the match kind if raw/normalized text overlaps the tagged value."""
    if len(raw) >= MIN_TEXT_MATCH and (
        raw in tv.value or (len(tv.value) >= MIN_TEXT_MATCH and tv.value in raw)
    ):
        return "exact"
    if len(norm) >= MIN_TEXT_MATCH and (
        norm in tv.normalized or (len(tv.normalized) >= MIN_TEXT_MATCH and tv.normalized in norm)
    ):
        return "normalized"
    return None


class _Collector:
    """Deduplicated labels for one argument, plus the data-flow edges they imply."""

    def __init__(self, arg: str, to_event: UUID, edges: list[DataFlowEdge]) -> None:
        self._arg = arg
        self._to = to_event
        self._edges = edges
        self._labels: dict[tuple[str, str, str, UUID], Provenance] = {}

    def add(self, p: Provenance, matched: str, kind: MatchKind) -> None:
        self._labels.setdefault((p.source, p.trust, p.confidentiality, p.event_id), p)
        if p.source != UNKNOWN_SOURCE:
            self._edges.append(
                DataFlowEdge(
                    from_event=p.event_id,
                    to_event=self._to,
                    arg=self._arg,
                    matched_value=matched[:200],
                    label=p,
                    match=kind,
                )
            )

    def labels(self) -> list[Provenance]:
        return list(self._labels.values())


def label_args(
    args: dict[str, Any],
    index: ValueIndex,
    session: SessionState,
    to_event: UUID,
    origin_without_prompt: bool = True,
) -> ArgLabelling:
    """`origin_without_prompt`: apply instruction origin when no prompt is known."""
    out = ArgLabelling()
    values = index.values
    by_entity = index.by_entity
    prompt_entities = index.prompt_entities
    check_origin = session.has_untrusted and (index.prompt_known or origin_without_prompt)

    for name, value in args.items():
        leaves = [leaf[:MAX_LEAF_CHARS] for leaf in flatten_strings(value)]
        out.arg_text[name] = leaves
        col = _Collector(name, to_event, out.edges)
        add = col.add

        for leaf in leaves:
            ents = extract(leaf)
            for ent in ents:
                if ent.key in prompt_entities:
                    # Instruction origin: the user asked for this exact entity.
                    for tv in by_entity.get(ent.key, []):
                        if tv.provenance.source == USER_SOURCE:
                            add(tv.provenance, ent.text, "user_prompt")
                            break
                    continue
                sources = by_entity.get(ent.key, [])
                for tv in sources:
                    add(tv.provenance, ent.text, "entity")
                # A known value smuggled inside an entity, e.g. a secret in a URL query.
                ent_norm = normalize(ent.text)
                for tv in values:
                    if len(tv.value) < MIN_TEXT_MATCH or tv.provenance.source == USER_SOURCE:
                        continue
                    if tv.value in ent.text:
                        add(tv.provenance, tv.value, "exact")
                    elif len(tv.normalized) >= MIN_TEXT_MATCH and tv.normalized in ent_norm:
                        add(tv.provenance, tv.value, "normalized")
                if not sources and check_origin:
                    add(
                        Provenance(
                            source=UNKNOWN_SOURCE,
                            trust="untrusted_origin",
                            confidentiality="public",
                            event_id=to_event,
                        ),
                        ent.text,
                        "origin",
                    )

            residual = _residual(leaf, ((e.start, e.end) for e in ents))
            norm = normalize(residual)
            if len(norm) < MIN_TEXT_MATCH:
                continue
            for tv in values:
                kind = _text_match(residual, norm, tv)
                if kind is not None:
                    add(tv.provenance, residual, kind)

        out.arg_labels[name] = col.labels()
    return out
