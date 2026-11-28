"""Turn Locust CSV stats (results/load/load_<kb>kb_stats.csv) into results/load_test.json and a table.

    uv run python load/summarize.py results/load [--users 20 --duration 60s]
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", type=Path)
    ap.add_argument("--users", type=int, default=20)
    ap.add_argument("--duration", default="60s")
    ap.add_argument("--cpu", default=platform.processor())
    a = ap.parse_args()
    rows = []
    for f in sorted(a.folder.glob("load_*kb_stats.csv"), key=lambda p: int(re.findall(r"(\d+)kb", p.name)[0])):
        kb = int(re.findall(r"(\d+)kb", f.name)[0])
        for r in csv.DictReader(f.open()):
            if r["Name"] in ("Aggregated", "sessions"):
                continue
            n = int(r["Request Count"])
            rows.append({
                "payload_kb": kb, "endpoint": re.sub(r" \d+KB$", "", r["Name"]), "requests": n,
                "failures": int(r["Failure Count"]), "rps": round(float(r["Requests/s"]), 1),
                "p50_ms": float(r["50%"]), "p95_ms": float(r["95%"]), "p99_ms": float(r["99%"]),
            })
    out = {"users": a.users, "duration_per_size": a.duration, "cpu": a.cpu, "workers": 1, "rows": rows}
    (ROOT / "results" / "load_test.json").write_text(json.dumps(out, indent=2))
    print(f"Locust: {a.users} concurrent agents, {a.duration} per payload size, one uvicorn worker, {a.cpu}\n")
    print("| Payload | Endpoint | Requests | Failures | Req/s | p50 ms | p95 ms | p99 ms |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['payload_kb']} KB | {r['endpoint']} | {r['requests']} | {r['failures']} | {r['rps']} | {r['p50_ms']:.0f} | {r['p95_ms']:.0f} | {r['p99_ms']:.0f} |")


if __name__ == "__main__":
    main()
