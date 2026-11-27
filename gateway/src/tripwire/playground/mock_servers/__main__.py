"""Run the mock MCP servers: `python -m tripwire.playground.mock_servers [--port 9100]`."""

from __future__ import annotations

import argparse
import os

import uvicorn

from tripwire.playground.mock_servers.servers import build_app


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("MOCK_MCP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("MOCK_MCP_PORT", "9100")))
    a = ap.parse_args()
    uvicorn.run(build_app(), host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
