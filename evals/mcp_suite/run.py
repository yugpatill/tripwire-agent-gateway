"""Run the Tripwire MCP suite (cases/*.yaml) against a gateway. No model calls.

    TRIPWIRE_URL=http://127.0.0.1:8100 TRIPWIRE_API_KEY=tw_... uv run python mcp_suite/run.py

Use a gateway with its own database (see local_stack.sh): the suite creates sessions
and approval rows. MCP cases need the mock servers (`MOCK_URL`, reset before each case)
and a short TRIPWIRE_APPROVAL_TIMEOUT_S on the gateway, because a held MCP call waits
for an operator. Writes results/mcp_suite.json.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import httpx2
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("TRIPWIRE_URL", "http://127.0.0.1:8100")
KEY = os.environ["TRIPWIRE_API_KEY"]
MOCK = os.environ.get("MOCK_URL", "http://127.0.0.1:9100")
H = {"Authorization": f"Bearer {KEY}"}
STOP = {"block", "require_approval"}
PASS = {"allow", "redact", "log_only"}


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def session(http: httpx.Client, prompt: str) -> str:
    r = http.post("/v1/sessions", json={"agent_name": "mcp-suite", "user_prompt": prompt})
    r.raise_for_status()
    return str(r.json()["session_id"])


def run_api(http: httpx.Client, case: dict[str, Any]) -> list[dict[str, Any]]:
    sid = session(http, case["user_prompt"])
    acts = []
    for step in case["steps"]:
        if "read" in step:
            s = step["read"]
            d = http.post("/v1/check/call", json={"session_id": sid, "tool": s["tool"], "args": s["args"]}).json()
            r = http.post("/v1/check/result", json={"session_id": sid, "tool": s["tool"], "call_event_id": d["event_id"], "content": s["content"]})
            r.raise_for_status()
        else:
            s = step["act"]
            d = http.post("/v1/check/call", json={"session_id": sid, "tool": s["tool"], "args": s["args"]}).json()
            acts.append({"tool": s["tool"], "malicious": bool(s.get("malicious", False)), "action": d["action"], "rule_id": d.get("rule_id")})
    return acts


def _meta(r: CallToolResult) -> dict[str, Any]:
    meta = r.meta or {}
    t = meta.get("tripwire") if isinstance(meta, dict) else None
    return t if isinstance(t, dict) else {}


async def run_mcp(http: httpx.Client, case: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    httpx.post(f"{MOCK}/reset").raise_for_status()
    sid = session(http, case["user_prompt"])
    m = case["mcp"]
    notes: list[str] = []
    headers = {**H, "X-Tripwire-Session": sid, "X-Tripwire-User-Prompt": quote(case["user_prompt"])}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=120.0)) as h2,
        Client(streamable_http_client(f"{BASE}/v1/mcp", http_client=h2)) as client,
    ):
        names = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
        for t in m.get("expect_hidden", []):
            notes.append(f"{t} {'hidden' if t not in names else 'VISIBLE'} at first listing")
        if "warmup" in m:
            w = m["warmup"]
            await client.call_tool(w["tool"], w["args"])
            names = {t.name for t in (await client.list_tools(cache_mode="refresh")).tools}
            for t in m.get("expect_hidden_after_warmup", []):
                notes.append(f"{t} {'hidden' if t not in names else 'VISIBLE'} after its description changed")
        for rd in m.get("reads", []):
            await client.call_tool(rd["tool"], rd["args"])
        a = m["act"]
        res = await client.call_tool(a["tool"], a["args"])
        meta = _meta(res)
        action = meta.get("action") or ("block" if res.is_error else "allow")
        return [{"tool": a["tool"], "malicious": bool(a.get("malicious", False)), "action": action, "rule_id": meta.get("rule_id"), "status": meta.get("status")}], notes


def verdict(case: dict[str, Any], acts: list[dict[str, Any]]) -> dict[str, Any]:
    if case["kind"] == "attack":
        mal = [x for x in acts if x["malicious"]]
        stopped = any(x["action"] in STOP for x in mal)
        held = stopped and all(x["action"] == "require_approval" for x in mal if x["action"] in STOP)
        return {"stopped": stopped, "held_only": held}
    passed = all(x["action"] in PASS for x in acts)
    return {"passed": passed, "held": any(x["action"] == "require_approval" for x in acts), "blocked": any(x["action"] == "block" for x in acts)}


def main() -> None:
    cases = [c for f in sorted((ROOT / "mcp_suite" / "cases").glob("*.yaml")) for c in yaml.safe_load(f.read_text())["cases"]]
    out_rows = []
    with httpx.Client(base_url=BASE, headers=H, timeout=60) as http:
        for c in cases:
            notes: list[str] = []
            try:
                if c.get("transport", "api") == "mcp":
                    acts, notes = asyncio.run(run_mcp(http, c))
                else:
                    acts = run_api(http, c)
                v, err = verdict(c, acts), None
            except Exception as exc:
                acts, v, err = [], {}, repr(exc)[:300]
            row = {"id": c["id"], "category": c["category"], "kind": c["kind"], "transport": c.get("transport", "api"),
                   "expect_gap": bool(c.get("expect_gap", False)), "acts": acts, "notes": notes, "error": err, **v}
            out_rows.append(row)
            mark = ("STOPPED" if v.get("stopped") else "MISSED") if c["kind"] == "attack" else ("ok" if v.get("passed") else "FRICTION")
            print(f"{c['id']:34} {c['kind']:6} {mark:8} {[(x['tool'], x['action'], x.get('rule_id')) for x in acts]} {notes or ''} {err or ''}", flush=True)

    ok = [r for r in out_rows if r["error"] is None]
    att = [r for r in ok if r["kind"] == "attack"]
    att_nogap = [r for r in att if not r["expect_gap"]]
    ben = [r for r in ok if r["kind"] == "benign"]

    def frac(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
        k, n = sum(bool(r.get(key)) for r in rows), len(rows)
        return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": wilson(k, n)}

    cats = sorted({r["category"] for r in att})
    summary = {
        "cases": len(out_rows), "errors": len(out_rows) - len(ok),
        "attacks_stopped": frac(att, "stopped"),
        "attacks_stopped_excluding_known_gaps": frac(att_nogap, "stopped"),
        "attacks_stopped_by_hold_only": frac(att, "held_only"),
        "benign_passed": frac(ben, "passed"),
        "benign_held": frac(ben, "held"),
        "benign_blocked": frac(ben, "blocked"),
        "by_category": {c: frac([r for r in att if r["category"] == c], "stopped") for c in cats},
        "missed": [r["id"] for r in att if not r["stopped"]],
        "benign_friction": [r["id"] for r in ben if not r["passed"]],
    }
    (ROOT / "results" / "mcp_suite.json").write_text(json.dumps({"summary": summary, "cases": out_rows}, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "by_category"}, indent=2))
    sys.exit(1 if summary["errors"] else 0)


if __name__ == "__main__":
    main()
