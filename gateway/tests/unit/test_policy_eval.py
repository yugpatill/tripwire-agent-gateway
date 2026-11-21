from __future__ import annotations

import uuid
from typing import Any

from tripwire.policy.compiler import UNKNOWN_TOOL_SPEC, CallFacts, CompiledPolicy, domain_allowed
from tripwire.policy.evaluate import UNKNOWN_TOOL_RULE, Evaluation, evaluate
from tripwire.taint.labels import Provenance

from .helpers import policy_from

TOOLS = """
tools:
  mail__send: {trust: trusted, sink: true, risk: high}
  docs__read: {trust: trusted, sink: false, risk: low}
"""


def _label(trust: str) -> Provenance:
    return Provenance(
        source="web__fetch", trust=trust, confidentiality="public", event_id=uuid.uuid4()
    )  # type: ignore[arg-type]


def facts(
    policy: CompiledPolicy,
    tool: str = "mail__send",
    args: dict[str, list[str]] | None = None,
    labels: dict[str, list[Provenance]] | None = None,
    ctx: str = "public",
    suspicious: bool = False,
) -> CallFacts:
    spec = policy.tool_spec(tool)
    return CallFacts(
        tool=tool,
        tool_spec=spec or UNKNOWN_TOOL_SPEC,
        tool_known=spec is not None,
        arg_labels=labels or {},
        arg_text=args if args is not None else {"to": ["bob@company.com"]},
        context_confidentiality=ctx,  # type: ignore[arg-type]
        session_suspicious=suspicious,
    )


async def run(
    policy: CompiledPolicy, f: CallFacts, counts: dict[str, int] | None = None
) -> Evaluation:
    counts = counts if counts is not None else {}

    async def counter(rule_id: str) -> int:
        counts[rule_id] = counts.get(rule_id, 0) + 1
        return counts[rule_id]

    return await evaluate(policy, f, counter)


def pol(rules: str, defaults: str = "") -> CompiledPolicy:
    return policy_from(f"version: 1\n{defaults}{TOOLS}rules:\n{rules}")


async def test_no_rules_allows() -> None:
    ev = await run(pol("  []\n"), facts(pol("  []\n")))
    assert (ev.action, ev.rule_id) == ("allow", None)


async def test_tool_exact_and_glob() -> None:
    p = pol("  - {id: r1, when: {tool: 'mail__*'}, action: block}\n")
    assert (await run(p, facts(p))).action == "block"
    assert (await run(p, facts(p, tool="docs__read"))).action == "allow"


async def test_sink_condition() -> None:
    p = pol("  - {id: r, when: {sink: true}, action: block}\n")
    assert (await run(p, facts(p))).action == "block"
    assert (await run(p, facts(p, tool="docs__read"))).action == "allow"


async def test_risk_condition() -> None:
    p = pol("  - {id: r, when: {risk: low}, action: block}\n")
    assert (await run(p, facts(p, tool="docs__read"))).action == "block"
    assert (await run(p, facts(p))).action == "allow"


async def test_arg_condition_requires_arg_present() -> None:
    p = pol("  - {id: r, when: {arg: cc}, action: block}\n")
    assert (await run(p, facts(p))).action == "allow"
    assert (await run(p, facts(p, args={"cc": ["x"]}))).action == "block"


async def test_label_any_scoped_to_arg() -> None:
    p = pol("  - {id: r, when: {arg: to, label_any: [untrusted]}, action: block}\n")
    body_only = facts(
        p, args={"to": ["a"], "body": ["b"]}, labels={"to": [], "body": [_label("untrusted")]}
    )
    to_tainted = facts(p, args={"to": ["a"]}, labels={"to": [_label("untrusted")]})
    assert (await run(p, body_only)).action == "allow"
    assert (await run(p, to_tainted)).action == "block"


async def test_label_any_without_arg_checks_all_args() -> None:
    p = pol("  - {id: r, when: {label_any: [suspicious]}, action: block}\n")
    f = facts(p, args={"to": ["a"], "body": ["b"]}, labels={"body": [_label("suspicious")]})
    assert (await run(p, f)).action == "block"


async def test_label_any_does_not_match_trusted() -> None:
    p = pol("  - {id: r, when: {label_any: [untrusted, untrusted_origin]}, action: block}\n")
    f = facts(p, labels={"to": [_label("trusted")]})
    assert (await run(p, f)).action == "allow"


async def test_context_confidentiality_at_least() -> None:
    p = pol(
        "  - id: r\n"
        "    when: {context_confidentiality_at_least: confidential}\n"
        "    action: require_approval\n"
    )
    assert (await run(p, facts(p, ctx="internal"))).action == "allow"
    assert (await run(p, facts(p, ctx="confidential"))).action == "require_approval"
    assert (await run(p, facts(p, ctx="secret"))).action == "require_approval"


async def test_session_has_suspicious() -> None:
    p = pol("  - {id: r, when: {session_has: suspicious}, action: block}\n")
    assert (await run(p, facts(p))).action == "allow"
    assert (await run(p, facts(p, suspicious=True))).action == "block"


async def test_unless_domain_allowlist() -> None:
    p = pol(
        "  - {id: r, when: {arg: to}, unless: {arg_domain_in: ['@company.com']}, action: block}\n"
    )
    assert (await run(p, facts(p, args={"to": ["bob@company.com"]}))).action == "allow"
    assert (await run(p, facts(p, args={"to": ["bob@evil.io"]}))).action == "block"
    # Mixed recipients: one outsider is enough to trigger the rule.
    assert (await run(p, facts(p, args={"to": ["bob@company.com, eve@evil.io"]}))).action == "block"


async def test_unless_without_domains_does_not_exempt() -> None:
    p = pol(
        "  - {id: r, when: {arg: to}, unless: {arg_domain_in: ['@company.com']}, action: block}\n"
    )
    assert (await run(p, facts(p, args={"to": ["no address here"]}))).action == "block"


def test_domain_allowed_semantics() -> None:
    assert domain_allowed("email", "sub.company.com", ["@company.com"])
    assert not domain_allowed("url", "company.com", ["@company.com"])
    assert domain_allowed("url", "api.company.com", ["company.com"])
    assert not domain_allowed("url", "evilcompany.com", ["company.com"])


async def test_limit_triggers_after_max_calls() -> None:
    p = pol("  - {id: lim, when: {tool: mail__send}, limit: {max_calls: 2}, action: block}\n")
    counts: dict[str, int] = {}
    results = [(await run(p, facts(p), counts)).action for _ in range(4)]
    assert results == ["allow", "allow", "block", "block"]


async def test_limit_counts_only_matching_calls() -> None:
    p = pol("  - {id: lim, when: {tool: mail__send}, limit: {max_calls: 1}, action: block}\n")
    counts: dict[str, int] = {}
    await run(p, facts(p, tool="docs__read"), counts)
    assert counts == {}


async def test_precedence_block_beats_earlier_approval() -> None:
    p = pol(
        "  - {id: a, when: {tool: mail__send}, action: require_approval}\n"
        "  - {id: b, when: {tool: mail__send}, action: block}\n"
        "  - {id: c, when: {tool: mail__send}, action: block}\n"
    )
    ev = await run(p, facts(p))
    assert (ev.action, ev.rule_id) == ("block", "b")
    assert [h.rule_id for h in ev.hits] == ["a", "b", "c"]


async def test_precedence_approval_beats_redact() -> None:
    p = pol(
        "  - {id: r, when: {tool: mail__send}, action: redact}\n"
        "  - {id: a, when: {tool: mail__send}, action: require_approval}\n"
    )
    assert (await run(p, facts(p))).rule_id == "a"


async def test_unknown_tool_default() -> None:
    p = pol("  []\n")
    ev = await run(p, facts(p, tool="other__thing"))
    assert (ev.action, ev.rule_id) == ("require_approval", UNKNOWN_TOOL_RULE)
    p2 = pol("  []\n", defaults="defaults: {unknown_tool: allow}\n")
    assert (await run(p2, facts(p2, tool="other__thing"))).action == "allow"


async def test_unknown_tool_treated_as_high_risk_sink() -> None:
    p = pol(
        "  - {id: r, when: {sink: true, risk: high}, action: block}\n",
        defaults="defaults: {unknown_tool: allow}\n",
    )
    assert (await run(p, facts(p, tool="other__thing"))).action == "block"


def test_confidentiality_by_path() -> None:
    p = policy_from(
        "version: 1\ntools:\n  files__read:\n    confidentiality: internal\n"
        "    confidentiality_by_path: {'*/.ssh/*': secret}\n"
    )
    args: dict[str, Any] = {"path": "/home/bob/.ssh/id_rsa"}
    assert p.result_confidentiality("files__read", args) == "secret"
    assert p.result_confidentiality("files__read", {"path": "/tmp/notes.txt"}) == "internal"
