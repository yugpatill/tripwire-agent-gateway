"""Latency overhead of the Tripwire MCP proxy for a tools/call with a small result.

    TRIPWIRE_API_KEY=tw_... uv run python scripts/bench_mcp_proxy.py \
        --gateway http://localhost:8000 --upstream http://localhost:9100 [-n 300]

Calls `files__read_file` (a 38-byte result) n times through Tripwire and
`read_file` n times directly on the mock upstream, each over one persistent SDK
client, sequentially, after a warm-up. Overhead = proxied minus direct.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import time
from collections.abc import Awaitable, Callable

import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

ARGS = {"path": "/home/user/notes.txt"}


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(q * len(s)))]


async def timed(fn: Callable[[], Awaitable[object]], n: int) -> list[float]:
    for _ in range(10):
        await fn()
    out = []
    for _ in range(n):
        t = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://localhost:8000")
    ap.add_argument("--upstream", default="http://localhost:9100")
    ap.add_argument("-n", type=int, default=300)
    a = ap.parse_args()
    key = os.environ["TRIPWIRE_API_KEY"]

    async with httpx.AsyncClient() as rest:
        r = await rest.post(
            f"{a.gateway}/v1/sessions",
            json={"agent_name": "bench-mcp", "user_prompt": "Read my notes"},
            headers={"Authorization": f"Bearer {key}"},
        )
        sid = r.json()["session_id"]
    headers = {"Authorization": f"Bearer {key}", "X-Tripwire-Session": sid}

    async with (
        httpx2.AsyncClient(timeout=30) as plain,
        Client(streamable_http_client(f"{a.upstream}/files/mcp", http_client=plain)) as direct,
        httpx2.AsyncClient(headers=headers, timeout=30) as authed,
        Client(streamable_http_client(f"{a.gateway}/v1/mcp", http_client=authed)) as proxied,
    ):
        r = await proxied.call_tool("files__read_file", ARGS)
        assert not r.is_error, r
        d = await timed(lambda: direct.call_tool("read_file", ARGS), a.n)
        p = await timed(lambda: proxied.call_tool("files__read_file", ARGS), a.n)

    print(f"tools/call, small result, n={a.n} each, sequential\n")
    print("| path | p50 | p95 |\n|---|---|---|")
    print(f"| direct to upstream | {statistics.median(d):.1f} ms | {pct(d, 0.95):.1f} ms |")
    print(f"| through Tripwire | {statistics.median(p):.1f} ms | {pct(p, 0.95):.1f} ms |")
    print(
        f"| **overhead** | **{statistics.median(p) - statistics.median(d):.1f} ms** "
        f"| **{pct(p, 0.95) - pct(d, 0.95):.1f} ms** |"
    )


if __name__ == "__main__":
    asyncio.run(main())
