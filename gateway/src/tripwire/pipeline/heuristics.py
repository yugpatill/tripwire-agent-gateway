"""Rule-based prompt-injection heuristics.

Each rule has a weight in (0, 1). A document's score combines the strongest hit
per rule as ``1 - prod(1 - w)``, so one weak signal (e.g. documentation saying
"ignore the previous instructions if you are on v2") stays below the suspicious
threshold, while several signals, or any signal found inside a hidden channel
(HTML comment, base64, URL-encoding, Unicode tag characters), push it over.

Rules run over normalized views (NFKC, casefolded, invisible characters
removed), so case tricks and zero-width splitting do not evade them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from tripwire.models import DetectorResult
from tripwire.pipeline.normalize import View, count_hidden_chars, detection_views


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    family: str
    weight: float
    pattern: re.Pattern[str]


def _r(rule_id: str, family: str, weight: float, pattern: str) -> Rule:
    return Rule(rule_id, family, weight, re.compile(pattern, re.M))


_TARGET = (
    r"(?:instructions?|directions?|prompts?|rules?|guidelines?|directives?|commands?|programming)"
)
_AI = (
    r"(?:ai|llm|large language model|language model|chatbot|ai assistant|ai agent|assistant|agent)"
)
# "assistant"/"agent" are also human job titles: "assistant manager", "agent of record".
_NOT_JOB = r"(?!\s+(?:manager|coach|director|editor|professor|principal|teacher|secretary|attorney|engineer|chef|producer|of record|team|desk))"

RULES: Final[list[Rule]] = [
    # --- direct override -------------------------------------------------
    _r(
        "override-all",
        "override",
        0.92,
        rf"\b(?:ignore|disregard|forget|override|bypass|discard)\s+(?:all|any|every(?:thing)?)\b[^.\n]{{0,30}}?\b{_TARGET}",
    ),
    _r(
        "override-your",
        "override",
        0.9,
        rf"\b(?:ignore|disregard|forget|override|bypass|discard)\s+(?:your|the system'?s?|my)\s+(?:\w+\s+){{0,2}}?{_TARGET}",
    ),
    _r(
        "override-system-prompt",
        "override",
        0.9,
        r"\b(?:ignore|disregard|override|forget)\b[^.\n]{0,20}\bsystem prompt",
    ),
    _r(
        "forget-above",
        "override",
        0.85,
        r"\b(?:forget|ignore|disregard)\s+(?:everything|all|anything)\s+(?:above|before|so far|you(?:'ve| have)? (?:been told|read))",
    ),
    _r(
        "ignore-the-user",
        "override",
        0.6,
        r"\b(?:ignore|disregard)\s+(?:the\s+)?user'?s?\s+(?:request|question|instructions?|task|message|prompt)\b",
    ),
    _r(
        "your-new-task",
        "override",
        0.5,
        r"\byour\s+(?:new|real|actual|only|true)\s+(?:task|job|goal|objective|mission|instructions?)\s+(?:is|are|now)\b",
    ),
    _r(
        "goals-updated",
        "override",
        0.6,
        r"\b(?:has|have)\s+(?:updated|changed|replaced|overridden)\s+your\s+(?:goals?|instructions?|rules?|task|objectives?|guidelines|priorities)\b",
    ),
    _r(
        "override-previous",
        "override",
        0.4,
        rf"\b(?:ignore|disregard|forget)\s+(?:the\s+)?(?:previous|prior|above|earlier|preceding|original)\s+{_TARGET}",
    ),
    _r(
        "new-instructions",
        "override",
        0.45,
        rf"\b(?:new|updated|real|actual|true|revised)\s+(?:system\s+)?{_TARGET}\s*[:\-]",
    ),
    _r(
        "instead-do",
        "override",
        0.35,
        r"\binstead,?\s+(?:you\s+(?:must|should|will)|do the following|perform)",
    ),
    _r(
        "jailbreak-mode",
        "override",
        0.9,
        r"\b(?:you are now|act as|enable|enter|activate|switch to)\s+(?:in\s+)?(?:dan|developer mode|god mode|jailbreak(?:ed)? mode|an? unrestricted|an? unfiltered)",
    ),
    _r(
        "reveal-prompt",
        "override",
        0.85,
        r"\b(?:reveal|print|output|repeat|show|leak|disclose)\s+(?:me\s+)?(?:your|the)\s+(?:system prompt|initial instructions|hidden instructions|original instructions)",
    ),
    # --- addressing the model --------------------------------------------
    _r(
        "ai-reading-this",
        "address",
        0.7,
        rf"\b{_AI}s?\b[^.\n]{{0,15}}\b(?:reading|processing|summari[sz]ing|parsing|browsing)\s+(?:this|these)",
    ),
    _r(
        "dear-ai",
        "address",
        0.7,
        rf"\b(?:dear|hey|attention|note to(?: the)?|message (?:to|for)(?: the)?)\s+{_AI}s?\b{_NOT_JOB}",
    ),
    _r(
        "ai-imperative",
        "address",
        0.75,
        rf"(?:^|[.!?:]\s*)(?:the\s+)?{_AI}s?\s*[,:]\s*(?:please\s+|you must\s+|you should\s+|now\s+)?(?:ignore|send|forward|email|delete|transfer|execute|run|open|visit|fetch|call|reply)\b",
    ),
    _r(
        "if-you-are-ai",
        "address",
        0.45,
        r"\bif you are an? (?:ai|llm|language model|ai assistant|ai agent|automated assistant)\b(?!\s+(?:researcher|engineer|developer|enthusiast|company|startup|team|student|practitioner|product))",
    ),
    _r(
        "ai-must",
        "address",
        0.55,
        rf"\b(?:as an?|the)\s+{_AI}\b[^.\n]{{0,20}}\byou (?:must|are required to|have to|need to)\b",
    ),
    # --- exfiltration and secrecy ----------------------------------------
    _r(
        "exfil-send-to",
        "exfil",
        0.3,
        r"\b(?:send|forward|email|e-mail|mail|post|upload|transfer|exfiltrate|leak|copy)\b[^\n]{0,80}?\b(?:to|at)\s+\S*(?:@|https?://)",
    ),
    _r(
        "secrecy-user",
        "exfil",
        0.6,
        r"\b(?:do not|don't|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|alert(?:ing)?|notify(?:ing)?|let(?:ting)?|asking)\s+(?:the\s+)?(?:user|human|operator)\b",
    ),
    _r(
        "secrecy-adverb",
        "exfil",
        0.6,
        r"\b(?:silently|secretly|quietly|covertly)\s+(?:send|forward|email|transfer|delete|upload|copy|post|exfiltrate)",
    ),
    _r(
        "include-secrets",
        "exfil",
        0.7,
        r"\b(?:include|append|attach|add|embed|paste|insert)\s+(?:the\s+|all\s+|your\s+|any\s+)*(?:conversation|chat history|previous messages|system prompt|api keys?|passwords?|credentials|secrets|session tokens?|private keys?)\b",
    ),
    # --- role / delimiter markers ----------------------------------------
    _r(
        "chat-template-token",
        "role",
        0.9,
        r"<\|\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|>",
    ),
    _r("inst-tag", "role", 0.85, r"\[/?inst\]|<<\s*/?sys\s*>>"),
    _r("xml-role-tag", "role", 0.7, r"</?(?:system|system_prompt|instructions?|admin|developer)>"),
    _r(
        "fake-tool-boundary",
        "role",
        0.7,
        r"</(?:tool_output|tool_result|function_results?|search_results?|document|context|user_input)>",
    ),
    _r("role-line-system", "role", 0.35, r"^\s*(?:system|assistant)\s*:\s+\S"),
    _r(
        "inline-role-command",
        "role",
        0.7,
        r"(?:^|[.!?]\s+)(?:system|admin|developer)\s*:\s*(?:now\s+|you must\s+|please\s+)?(?:ignore|transfer|send|forward|email|delete|reveal|run|execute|call|grant|export)\b",
    ),
    _r("fake-turns", "role", 0.45, r"^\s*(?:human|user)\s*:[^\n]*\n+\s*(?:assistant|ai)\s*:"),
    _r(
        "end-of-context",
        "role",
        0.4,
        r"\b(?:end|close) of (?:the\s+)?(?:user input|document|context|tool output|search results?|email|page content)\b",
    ),
    _r(
        "markdown-role-header",
        "role",
        0.6,
        r"^#{1,4}\s*(?:system|new instructions|instructions for (?:the )?(?:ai|assistant|agent))\s*:?\s*$",
    ),
    # --- tool abuse ------------------------------------------------------
    _r(
        "shell-pipe",
        "tool",
        0.6,
        r"\b(?:curl|wget)\s+[^\n|]{0,200}\|\s*(?:sh|bash|zsh|python)\b|\brm\s+-rf\s+/",
    ),
]

# Markdown image whose URL carries a templated or data-bearing query string: the
# classic zero-click exfiltration channel when the client renders the image.
_MD_IMAGE = re.compile(r"!\[[^\]]{0,200}\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)", re.I)
_PLACEHOLDER = re.compile(r"[{}$<>\[\]]|%7b|%7d|%24|%5b|%5d", re.I)
_DATA_KEYS = re.compile(
    r"[?&](?:data|d|q|secret|token|key|content|msg|message|info|exfil|payload|chat|history|conversation|summary|text|leak|c|p)=([^&#]*)",
    re.I,
)

HIDDEN_KINDS: Final = frozenset(
    {"base64", "url", "tags", "html_comment", "html_entities", "json_escapes"}
)
HIDDEN_BOOST: Final = 0.3
# Signals combine only when they co-occur: weak hits further apart than this (in
# characters) do not add up, so a long benign page with one stray phrase in each
# section is not flagged. Document-wide signals (invisible-character counts)
# apply to every neighbourhood.
LOCAL_RADIUS: Final = 500
# Rules weaker than this are modifiers ("send ... to x@", "System:" lines): common
# in benign text, so they only raise a neighbourhood that already has a real
# signal and never combine only among themselves.
MODIFIER_MAX: Final = 0.4


@dataclass(slots=True)
class _Hit:
    weight: float
    spans: list[tuple[int, int]] = field(default_factory=list)
    where: set[str] = field(default_factory=set)


def _markdown_exfil(text: str) -> list[tuple[float, tuple[int, int], str]]:
    found: list[tuple[float, tuple[int, int], str]] = []
    for m in _MD_IMAGE.finditer(text):
        url = m.group(1)
        if "?" not in url:
            continue
        query = url.split("?", 1)[1]
        if _PLACEHOLDER.search(query):
            found.append((0.85, m.span(), "templated query"))
            continue
        for km in _DATA_KEYS.finditer("?" + query):
            if len(km.group(1)) >= 24:
                found.append((0.6, m.span(), "long data parameter"))
                break
    return found


def _combine(weights: dict[str, float]) -> float:
    if not weights:
        return 0.0
    if max(weights.values()) < MODIFIER_MAX:
        return max(weights.values())
    keep = 1.0
    for w in weights.values():
        keep *= 1.0 - w
    return 1.0 - keep


def _local_score(occurrences: list[tuple[str, float, tuple[int, int]]], text_len: int) -> float:
    """Max over neighbourhoods of the combined score of distinct rules hit there."""
    global_hits: dict[str, float] = {}
    local: list[tuple[str, float, int]] = []
    for rule_id, w, (s, e) in occurrences:
        if s == 0 and e == text_len:
            global_hits[rule_id] = max(global_hits.get(rule_id, 0.0), w)
        else:
            local.append((rule_id, w, s))
    best = _combine(global_hits)
    local.sort(key=lambda x: x[2])
    for _, _, center in local:
        near = dict(global_hits)
        for rule_id, w, pos in local:
            if abs(pos - center) <= LOCAL_RADIUS:
                near[rule_id] = max(near.get(rule_id, 0.0), w)
        best = max(best, _combine(near))
    return best


def score_text(text: str) -> DetectorResult:
    hits: dict[str, _Hit] = {}
    occurrences: list[tuple[str, float, tuple[int, int]]] = []

    def hit(rule_id: str, weight: float, span: tuple[int, int], where: str) -> None:
        occurrences.append((rule_id, weight, span))
        h = hits.setdefault(rule_id, _Hit(0.0))
        h.weight = max(h.weight, weight)
        if span not in h.spans:
            h.spans.append(span)
        h.where.add(where)

    views: list[View] = detection_views(text)
    for view in views:
        hidden = view.kind in HIDDEN_KINDS
        for rule in RULES:
            for m in rule.pattern.finditer(view.text):
                w = min(0.95, rule.weight + HIDDEN_BOOST) if hidden else rule.weight
                hit(rule.id, w, view.span(*m.span()), view.kind)

    invisible, tags = count_hidden_chars(text)
    if tags >= 4:
        hit("unicode-tag-smuggling", 0.95, (0, len(text)), "raw")
    if invisible >= 3:
        # Zero-width characters inside words split keywords; a few are normal
        # in copy-pasted text, many are not.
        hit("zero-width-chars", min(0.7, 0.2 + 0.05 * invisible), (0, len(text)), "raw")

    for weight, span, why in _markdown_exfil(text):
        hit("markdown-image-exfil", weight, span, why)

    score = round(_local_score(occurrences, len(text)), 4)
    spans = sorted({s for h in hits.values() for s in h.spans})
    reason = ", ".join(
        f"{rid}({h.weight:.2f}{'@' + '/'.join(sorted(h.where - {'normalized'})) if h.where - {'normalized'} else ''})"
        for rid, h in sorted(hits.items(), key=lambda kv: -kv[1].weight)
    )
    return DetectorResult(
        detector="heuristic", score=score, spans=spans, reason=reason or "no heuristic matched"
    )


def rule_ids_hit(result: DetectorResult) -> list[str]:
    return [part.split("(", 1)[0] for part in result.reason.split(", ") if "(" in part]
