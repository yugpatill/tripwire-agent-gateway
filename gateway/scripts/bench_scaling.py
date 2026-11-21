"""Scaling benchmark for POST /v1/check/call.

A session holds N prior tool results of SIZE bytes each (realistic prose with
emails, URLs and numbers sprinkled in); then we time calls with 5 string args.

    uv run python scripts/bench_scaling.py --url http://localhost:8000 [--api-key tw_...]
"""

from __future__ import annotations

import argparse
import random
import statistics
import time

import httpx

WORDS = (
    "the quarterly report shows revenue growth across regions while support tickets "
    "mention billing delays shipping updates and a request to reset passwords for the team"
).split()


def make_doc(rng: random.Random, size: int, i: int) -> str:
    parts: list[str] = []
    n = 0
    while n < size:
        r = rng.random()
        if r < 0.02:
            w = f"user{rng.randint(0, 10_000)}@corp{i}.example"
        elif r < 0.03:
            w = f"https://site{i}.example/p/{rng.randint(0, 99_999)}"
        elif r < 0.04:
            w = str(rng.randint(10_000, 99_999_999))
        else:
            w = rng.choice(WORDS)
        parts.append(w)
        n += len(w) + 1
    return " ".join(parts)[:size]


def pct(xs: list[float], p: int) -> float:
    return statistics.quantiles(xs, n=100)[p - 1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--results", type=int, default=20)
    ap.add_argument("--size", type=int, default=50_000)
    ap.add_argument("--calls", type=int, default=300)
    ap.add_argument("--warmup", type=int, default=20)
    a = ap.parse_args()

    rng = random.Random(42)
    headers = {"Authorization": f"Bearer {a.api_key}"} if a.api_key else {}
    c = httpx.Client(base_url=a.url + "/v1", headers=headers, timeout=30)
    sid = c.post(
        "/sessions",
        json={"agent_name": "bench", "user_prompt": "Summarize and email alice@company.com"},
    ).json()["session_id"]
    for i in range(a.results):
        d = c.post(
            "/check/call",
            json={
                "session_id": sid,
                "tool": "web__fetch",
                "args": {"url": f"https://s{i}.example"},
            },
        ).json()
        c.post(
            "/check/result",
            json={
                "session_id": sid,
                "tool": "web__fetch",
                "call_event_id": d["event_id"],
                "content": make_doc(rng, a.size, i),
            },
        ).raise_for_status()

    server: list[float] = []
    client: list[float] = []
    for k in range(a.warmup + a.calls):
        args = {
            "to": "alice@company.com" if k % 2 else f"user{k}@corp3.example",
            "cc": "bob@company.com",
            "subject": "Quarterly summary for the team",
            "body": " ".join(rng.choice(WORDS) for _ in range(120)),
            "footer": "Sent by the reporting agent, do not reply to this message",
        }
        t = time.perf_counter()
        r = c.post(
            "/check/call", json={"session_id": sid, "tool": "email__send_email", "args": args}
        )
        elapsed = (time.perf_counter() - t) * 1000
        r.raise_for_status()
        if k >= a.warmup:
            client.append(elapsed)
            server.append(r.json()["latency_ms"])

    print(f"results={a.results} x {a.size} B, calls={a.calls}, 5 string args")
    print(f"engine  p50={pct(server, 50):6.2f} ms  p95={pct(server, 95):6.2f} ms")
    print(f"http    p50={pct(client, 50):6.2f} ms  p95={pct(client, 95):6.2f} ms")


if __name__ == "__main__":
    main()
