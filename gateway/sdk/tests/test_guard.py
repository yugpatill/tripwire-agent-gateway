"""Core guard against a scripted fake gateway (httpx.MockTransport, no network)."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from tests.scenario import SENT, email__send_email
from tripwire_guard import AsyncTripwireClient, Guard, ToolBlocked, TripwireClient


class FakeGateway:
    def __init__(self, action: str = "allow", approval: list[str] | None = None) -> None:
        self.action = action
        self.approval = approval or ["approved"]
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result_status = 200
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("refused")
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.calls.append((path, body))
        if path.endswith("/prompts"):
            return httpx.Response(200, json={"added": True})
        if path == "/v1/sessions":
            return httpx.Response(201, json={"session_id": str(uuid.uuid4())})
        if path == "/v1/check/call":
            d: dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "action": self.action,
                "rule_id": None if self.action == "allow" else "test-rule",
                "message": "Test rule message.",
            }
            if self.action == "redact":
                d["redacted_args"] = {**body["args"], "body": "[REDACTED]"}
            if self.action == "require_approval":
                d["approval_id"] = str(uuid.uuid4())
            return httpx.Response(200, json=d)
        if path == "/v1/check/result":
            if self.result_status != 200:
                return httpx.Response(self.result_status, json={"detail": "boom"})
            content = body["content"]
            red = (
                content.replace("secret-token", "[REDACTED:token]")
                if isinstance(content, str)
                else content
            )
            return httpx.Response(
                200,
                json={
                    "content_redacted": red,
                    "labels": [],
                    "detectors": [],
                    "decision": {"event_id": str(uuid.uuid4()), "action": "allow"},
                },
            )
        if path.startswith("/v1/approvals/"):
            status = self.approval.pop(0) if len(self.approval) > 1 else self.approval[0]
            return httpx.Response(
                200, json={"id": path.rsplit("/", 1)[1], "status": status, "tool": "t"}
            )
        return httpx.Response(404)


def guard_for(gw: FakeGateway, **kw: Any) -> Guard:
    transport = httpx.MockTransport(gw.handler)
    client = TripwireClient("http://tw", "tw_test", http_client=httpx.Client(transport=transport))
    aclient = AsyncTripwireClient(
        "http://tw", "tw_test", http_client=httpx.AsyncClient(transport=transport)
    )
    return Guard(client=client, async_client=aclient, poll_interval=0.01, **kw)


ARGS = {"to": "a@b.example", "subject": "s", "body": "hello"}


def test_allowed_call_runs_and_result_is_vetted() -> None:
    gw = FakeGateway("allow")
    g = guard_for(gw, user_prompt="hi")
    out = g.call("email__send_email", ARGS, lambda **kw: "sent with secret-token")
    assert out.status == "allowed" and out.ran and not out.is_error
    assert out.content == "sent with [REDACTED:token]"
    assert [p for p, _ in gw.calls] == ["/v1/sessions", "/v1/check/call", "/v1/check/result"]
    assert gw.calls[0][1]["user_prompt"] == "hi"


def test_blocked_call_never_runs() -> None:
    g = guard_for(FakeGateway("block"))
    out = g.call("email__send_email", ARGS, email__send_email)
    assert out.blocked and not out.ran and SENT == []
    assert out.content == "Blocked by Tripwire (test-rule): Test rule message."


def test_redact_runs_with_redacted_arguments() -> None:
    seen: dict[str, Any] = {}
    g = guard_for(FakeGateway("redact"))
    g.call("email__send_email", ARGS, lambda **kw: seen.update(kw) or "ok")
    assert seen["body"] == "[REDACTED]"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (["pending", "approved"], "allowed"),
        (["pending", "denied"], "denied"),
        (["expired"], "expired"),
    ],
)
def test_approval_outcomes(statuses: list[str], expected: str) -> None:
    g = guard_for(FakeGateway("require_approval", statuses))
    out = g.call("email__send_email", ARGS, email__send_email)
    assert out.status == expected
    assert (SENT != []) == (expected == "allowed")


def test_approval_client_timeout_denies() -> None:
    g = guard_for(FakeGateway("require_approval", ["pending"]), approval_timeout=0.05)
    out = g.call("email__send_email", ARGS, email__send_email)
    assert out.status == "expired" and SENT == []


def test_gateway_down_fails_closed() -> None:
    gw = FakeGateway("allow")
    gw.down = True
    out = guard_for(gw).call("email__send_email", ARGS, email__send_email)
    assert out.status == "unavailable" and not out.ran and SENT == []


def test_unvetted_result_is_withheld() -> None:
    gw = FakeGateway("allow")
    gw.result_status = 500
    out = guard_for(gw).call("web__fetch", {"url": "u"}, lambda **kw: "page text")
    assert out.is_error and out.ran and "page text" not in out.content


def test_tool_exception_is_an_error_result() -> None:
    def boom(**kw: Any) -> str:
        raise ValueError("disk full")

    out = guard_for(FakeGateway("allow")).call("files__write_file", {"path": "p"}, boom)
    assert out.status == "error" and out.is_error and "disk full" in out.content


def test_tool_decorator_keeps_signature_and_can_raise() -> None:
    g = guard_for(FakeGateway("block"))
    wrapped = g.tool(email__send_email)
    assert wrapped.__doc__ == email__send_email.__doc__
    assert wrapped("x@y.example", "s", "b").startswith("Blocked by Tripwire")
    with pytest.raises(ToolBlocked):
        g.tool(email__send_email, on_block="raise")("x@y.example", "s", "b")


def test_tool_name_mapping() -> None:
    gw = FakeGateway("allow")
    g = guard_for(gw, tool_names={"send_email": "email__send_email"})
    g.call("send_email", ARGS, email__send_email)
    assert gw.calls[1][1]["tool"] == "email__send_email"


async def test_async_call_with_async_tool() -> None:
    gw = FakeGateway("allow")
    g = guard_for(gw)

    async def fetch(url: str) -> str:
        return "async page"

    out = await g.acall("web__fetch", {"url": "u"}, fetch)
    assert out.content == "async page" and out.status == "allowed"
    blocked = await guard_for(FakeGateway("block")).acall("web__fetch", {"url": "u"}, fetch)
    assert blocked.blocked


def test_one_session_per_guard() -> None:
    gw = FakeGateway("allow")
    g = guard_for(gw)
    for _ in range(3):
        g.call("web__fetch", {"url": "u"}, lambda **kw: "x")
    g.user_turn("now email it to bob@company.example")
    sessions = [p for p, _ in gw.calls if p == "/v1/sessions"]
    assert len(sessions) == 1
    assert gw.calls[-1][0].endswith("/prompts")
