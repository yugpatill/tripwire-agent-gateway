"""Compile a validated PolicyDocument into fast rule checks."""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from tripwire.models import CONFIDENTIALITY_ORDER, TRUST_ORDER, Confidentiality
from tripwire.policy.schema import PolicyDocument, Rule, ToolSpec
from tripwire.taint.entities import domains
from tripwire.taint.labels import Provenance

# Conservative facts assumed for a tool the policy does not describe.
UNKNOWN_TOOL_SPEC = ToolSpec(trust="untrusted", confidentiality="internal", sink=True, risk="high")


@dataclass(frozen=True, slots=True)
class CallFacts:
    """Everything a rule condition may look at for one tool call."""

    tool: str
    tool_spec: ToolSpec
    tool_known: bool
    arg_labels: dict[str, list[Provenance]]
    arg_text: dict[str, list[str]]
    context_confidentiality: Confidentiality
    session_suspicious: bool


Predicate = Callable[[CallFacts], bool]


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def tool_matches(pattern: str, tool: str) -> bool:
    return fnmatch.fnmatchcase(tool, pattern) if _is_glob(pattern) else tool == pattern


def domain_allowed(kind: str, domain: str, allow: list[str]) -> bool:
    """`@company.com` entries match email domains (and subdomains); bare entries match hosts."""
    domain = domain.lower()
    for entry in allow:
        entry = entry.lower().strip()
        if entry.startswith("@"):
            base = entry[1:]
            if kind == "email" and (domain == base or domain.endswith("." + base)):
                return True
        elif domain == entry or domain.endswith("." + entry):
            return True
    return False


@dataclass(slots=True)
class CompiledRule:
    rule: Rule
    index: int
    conditions: list[Predicate] = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.rule.id

    def when_matches(self, facts: CallFacts) -> bool:
        return all(cond(facts) for cond in self.conditions)

    def unless_holds(self, facts: CallFacts) -> bool:
        unless = self.rule.unless
        if unless is None:
            return False
        arg = self.rule.when.arg
        texts = (
            facts.arg_text.get(arg, []) if arg else [t for v in facts.arg_text.values() for t in v]
        )
        found = [d for t in texts for d in domains(t)]
        if not found:
            return False
        return all(domain_allowed(kind, dom, unless.arg_domain_in) for kind, dom in found)


def _compile_conditions(rule: Rule) -> list[Predicate]:
    w = rule.when
    conds: list[Predicate] = []
    if w.tool is not None:
        pattern = w.tool
        conds.append(lambda f: tool_matches(pattern, f.tool))
    if w.sink is not None:
        sink = w.sink
        conds.append(lambda f: f.tool_spec.sink is sink)
    if w.risk is not None:
        risk = w.risk
        conds.append(lambda f: f.tool_spec.risk == risk)
    if w.arg is not None:
        arg = w.arg
        conds.append(lambda f: arg in f.arg_text)
    if w.label_any is not None:
        wanted = {TRUST_ORDER[t] for t in w.label_any}
        arg_name = w.arg

        def _labels(f: CallFacts) -> bool:
            if arg_name is not None:
                labels = f.arg_labels.get(arg_name, [])
            else:
                labels = [p for ps in f.arg_labels.values() for p in ps]
            return any(TRUST_ORDER[p.trust] in wanted for p in labels)

        conds.append(_labels)
    if w.context_confidentiality_at_least is not None:
        floor = CONFIDENTIALITY_ORDER[w.context_confidentiality_at_least]
        conds.append(lambda f: CONFIDENTIALITY_ORDER[f.context_confidentiality] >= floor)
    if w.session_has == "suspicious":
        conds.append(lambda f: f.session_suspicious)
    return conds


@dataclass(slots=True)
class CompiledPolicy:
    doc: PolicyDocument
    source: str
    version: str
    rules: list[CompiledRule]
    _exact_tools: dict[str, ToolSpec]
    _glob_tools: list[tuple[str, ToolSpec]]

    def tool_spec(self, tool: str) -> ToolSpec | None:
        spec = self._exact_tools.get(tool)
        if spec is not None:
            return spec
        for pattern, s in self._glob_tools:
            if fnmatch.fnmatchcase(tool, pattern):
                return s
        return None

    def result_confidentiality(self, tool: str, call_args: dict[str, object]) -> Confidentiality:
        spec = self.tool_spec(tool) or UNKNOWN_TOOL_SPEC
        path = call_args.get("path")
        if isinstance(path, str):
            for pattern, level in spec.confidentiality_by_path.items():
                if fnmatch.fnmatchcase(path, pattern):
                    return level
        return spec.confidentiality


def compile_policy(doc: PolicyDocument, source: str = "") -> CompiledPolicy:
    exact = {k: v for k, v in doc.tools.items() if not _is_glob(k)}
    globs = [(k, v) for k, v in doc.tools.items() if _is_glob(k)]
    rules = [CompiledRule(r, i, _compile_conditions(r)) for i, r in enumerate(doc.rules)]
    version = hashlib.sha256(source.encode()).hexdigest()[:12] if source else "inline"
    return CompiledPolicy(doc, source, version, rules, exact, globs)
