"""Evaluate compiled rules against one tool call."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from tripwire.models import ACTION_PRECEDENCE, Action
from tripwire.policy.compiler import CallFacts, CompiledPolicy

UNKNOWN_TOOL_RULE = "default-unknown-tool"

# Increments and returns the per-session counter for a rule (used by `limit`).
Counter = Callable[[str], Awaitable[int]]


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule_id: str
    action: Action
    message: str
    arg: str | None


@dataclass(slots=True)
class Evaluation:
    action: Action
    rule_id: str | None
    message: str
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def redact_args(self) -> list[str | None]:
        return [h.arg for h in self.hits if h.action == "redact"]


async def evaluate(policy: CompiledPolicy, facts: CallFacts, counter: Counter) -> Evaluation:
    """Rules run in file order; the first `block` wins, then `require_approval`, then `redact`."""
    hits: list[RuleHit] = []

    if not facts.tool_known and policy.doc.defaults.unknown_tool != "allow":
        hits.append(
            RuleHit(
                UNKNOWN_TOOL_RULE,
                policy.doc.defaults.unknown_tool,
                f"Tool {facts.tool} is not described in the active policy.",
                None,
            )
        )

    for rule in policy.rules:
        if not rule.when_matches(facts):
            continue
        if rule.unless_holds(facts):
            continue
        if rule.rule.limit is not None:
            # Count every call that meets the `when` clause; trigger once over the limit.
            count = await counter(rule.id)
            if count <= rule.rule.limit.max_calls:
                continue
        hits.append(RuleHit(rule.id, rule.rule.action, rule.rule.message, rule.rule.when.arg))

    if not hits:
        return Evaluation("allow", None, "No rule matched.", hits)

    best = max(ACTION_PRECEDENCE[h.action] for h in hits)
    winner = next(h for h in hits if ACTION_PRECEDENCE[h.action] == best)
    return Evaluation(winner.action, winner.rule_id, winner.message or winner.rule_id, hits)
