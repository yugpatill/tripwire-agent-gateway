"""MCP tool manifest security: pinning, poisoning scan, shadowing.

A *manifest* is what an upstream MCP server says about one tool: its name,
description and input schema. Agents read descriptions as instructions, so a
malicious server can hide instructions there (tool poisoning), change them after
the user trusted the tool (rug pull), or imitate another server's tool
(shadowing).

- **Pinning**: SHA-256 over the canonical JSON of name, description and input
  schema. Any change is a rug pull until an operator approves the new version.
- **Poisoning**: every description (the tool's and each parameter's, at any
  depth) goes through the injection pipeline under the corroborated rule, plus
  manifest-specific rules below. Score >= 0.5 quarantines the tool.
- **Shadowing**: a tool whose bare name is within Levenshtein distance 2 of a
  tool on another server, or whose description names another server's tool.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from rapidfuzz.distance import Levenshtein

from tripwire.pipeline.detect import DetectionPipeline
from tripwire.pipeline.normalize import count_hidden_chars

NAMESPACE_SEP = "__"
FLAG_THRESHOLD = 0.5
SHADOW_MAX_DISTANCE = 2  # "rapidfuzz distance < 3"
# Bare names shorter than this are too generic to count as a cross-server reference
# when they appear in a description ("add", "get", "list").
MIN_REFERENCE_NAME = 5


@dataclass(frozen=True, slots=True)
class Manifest:
    server: str
    tool: str  # bare upstream name
    description: str
    input_schema: dict[str, Any]

    @property
    def name(self) -> str:
        return f"{self.server}{NAMESPACE_SEP}{self.tool}"

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    @property
    def hash(self) -> str:
        blob = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class Finding:
    rule: str
    field: str  # "description" or the JSON path of a parameter description
    weight: float
    excerpt: str


@dataclass(slots=True)
class ScanResult:
    score: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.score >= FLAG_THRESHOLD

    def as_json(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "findings": [
                {"rule": f.rule, "field": f.field, "weight": f.weight, "excerpt": f.excerpt}
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------- text fields


def description_fields(m: Manifest) -> Iterator[tuple[str, str]]:
    """(field path, text) for the tool description and every schema description/title."""
    if m.description:
        yield "description", m.description

    def walk(node: Any, path: str) -> Iterator[tuple[str, str]]:
        if isinstance(node, dict):
            for key in ("description", "title"):
                v = node.get(key)
                if isinstance(v, str) and v.strip():
                    yield f"{path}.{key}", v
            for k, v in node.items():
                if k in ("description", "title"):
                    continue
                if isinstance(v, (dict, list)):
                    yield from walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from walk(v, f"{path}[{i}]")

    yield from walk(m.input_schema, "input_schema")


# ---------------------------------------------------------------- manifest rules

_SENSITIVE_PATH = re.compile(
    r"(?<![\w.])(?:~/)?(?:\.env\b|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|"
    r"\.npmrc|\.pypirc|\.git-credentials|/etc/passwd|/etc/shadow|credentials\.json|"
    r"\.kube/config|\.docker/config\.json|mcp\.json|claude_desktop_config\.json)",
    re.IGNORECASE,
)
_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|$)", re.DOTALL)
_INSTRUCTION_TAG = re.compile(
    r"</?\s*(?:important|system|instructions?|secret|hidden|admin"
    r"|note to (?:the )?(?:ai|assistant|model))\s*>",
    re.IGNORECASE,
)
_PASS_AS_ARG = re.compile(
    r"\b(?:pass|send|include|put|add|insert|provide|append)\b[^.\n]{0,80}?"
    r"\b(?:contents?|content of|text of|value of|full|entire|whole)\b[^.\n]{0,80}?"
    r"\b(?:as|in|into|to)\b[^.\n]{0,40}?\b(?:argument|parameter|param|field|notes?|sidenote|context)\b",
    re.IGNORECASE,
)
_CALL_OTHER_TOOL_FIRST = re.compile(
    r"\b(?:before|prior to|first)\b[^.\n]{0,40}\b(?:using|calling|invoking|running)\b"
    r"[^.\n]{0,30}\bthis tool\b[^.\n]{0,80}\b(?:call|use|read|run|invoke|fetch|open)\b"
    r"|\byou must (?:first |always )?(?:call|use|read|run|invoke)\b",
    re.IGNORECASE,
)
_SECRECY = re.compile(
    r"\b(?:do not|don't|never)\b[^.\n]{0,30}\b(?:tell|mention|inform|reveal|show|notify)\b"
    r"[^.\n]{0,20}\b(?:the )?user\b|\bwithout (?:telling|informing|notifying) the user\b",
    re.IGNORECASE,
)
_OVERRIDE_OTHER_TOOLS = re.compile(
    r"\b(?:when|whenever|if)\b[^.\n]{0,40}\b(?:other|another|any)\b[^.\n]{0,20}\btools?\b"
    r"|\binstead of (?:using |calling )?(?:the )?\w+ tool\b",
    re.IGNORECASE,
)

_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    ("sensitive-path", 0.6, _SENSITIVE_PATH),
    ("html-comment", 0.5, _HTML_COMMENT),
    ("instruction-tag", 0.5, _INSTRUCTION_TAG),
    ("pass-data-as-argument", 0.5, _PASS_AS_ARG),
    ("call-other-tool-first", 0.4, _CALL_OTHER_TOOL_FIRST),
    ("hide-from-user", 0.5, _SECRECY),
    ("redirect-other-tools", 0.4, _OVERRIDE_OTHER_TOOLS),
]


def _excerpt(text: str, start: int, end: int, pad: int = 40) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return ("…" if s else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


def _combine(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p


async def scan_poisoning(m: Manifest, detection: DetectionPipeline | None) -> ScanResult:
    findings: list[Finding] = []
    detector_max = 0.0
    for path, text in description_fields(m):
        for rule, weight, rx in _RULES:
            hit = rx.search(text)
            if hit:
                findings.append(Finding(rule, path, weight, _excerpt(text, hit.start(), hit.end())))
        invisible, tags = count_hidden_chars(text)
        if invisible or tags:
            findings.append(
                Finding(
                    "hidden-unicode",
                    path,
                    0.6,
                    f"{invisible} invisible/bidi and {tags} Unicode tag characters",
                )
            )
        if detection is not None:
            a = await detection.analyze(text, 0.5, 0.85, "corroborated")
            if a.injection_score > 0:
                detector_max = max(detector_max, a.injection_score)
                if a.suspicious:
                    reasons = "; ".join(
                        d.reason for d in a.detectors if d.detector in ("heuristic", "classifier")
                    )
                    findings.append(
                        Finding("injection-detector", path, a.injection_score, reasons[:200])
                    )
    # Strongest finding per rule, combined across rules (a rule repeated in many
    # parameter descriptions does not add up on its own).
    per_rule: dict[str, float] = {}
    for f in findings:
        if f.rule != "injection-detector":
            per_rule[f.rule] = max(per_rule.get(f.rule, 0.0), f.weight)
    score = max(_combine(list(per_rule.values())), detector_max)
    return ScanResult(score=score, findings=findings)


# ---------------------------------------------------------------- shadowing


def find_shadowing(m: Manifest, others: list[Manifest]) -> list[Finding]:
    """Shadowing findings for `m` against tools of *other* servers."""
    findings: list[Finding] = []
    texts = [t for _, t in description_fields(m)]
    for o in others:
        if o.server == m.server:
            continue
        d = Levenshtein.distance(m.tool.lower(), o.tool.lower())
        if d <= SHADOW_MAX_DISTANCE:
            findings.append(
                Finding(
                    "name-shadowing",
                    "name",
                    0.6,
                    f"{m.name} is {d} edit(s) from {o.name}",
                )
            )
        ref = re.compile(
            rf"(?<![\w]){re.escape(o.name)}(?![\w])"
            + (
                rf"|(?<![\w]){re.escape(o.tool)}(?![\w])"
                if len(o.tool) >= MIN_REFERENCE_NAME
                else ""
            ),
            re.IGNORECASE,
        )
        for text in texts:
            hit = ref.search(text)
            if hit:
                findings.append(
                    Finding(
                        "cross-server-reference",
                        "description",
                        0.6,
                        f"names {o.name}: " + _excerpt(text, hit.start(), hit.end()),
                    )
                )
                break
    return findings


# ---------------------------------------------------------------- diff


def manifest_diff(before: dict[str, Any], after: dict[str, Any]) -> str:
    """Unified diff of two canonical manifests, one field per block."""

    def lines(c: dict[str, Any]) -> list[str]:
        out = [f"name: {c.get('name', '')}", "description:"]
        out += [f"  {line}" for line in str(c.get("description", "")).splitlines() or [""]]
        out.append("input_schema:")
        out += [
            f"  {line}"
            for line in json.dumps(c.get("input_schema", {}), indent=2, sort_keys=True).splitlines()
        ]
        return out

    return "\n".join(
        difflib.unified_diff(lines(before), lines(after), "pinned", "current", lineterm="")
    )
