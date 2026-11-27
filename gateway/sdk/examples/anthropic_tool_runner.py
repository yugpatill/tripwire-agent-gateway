"""Anthropic Tool Runner guarded by Tripwire.

    uv run python examples/anthropic_tool_runner.py           # scripted model, no API key
    uv run python examples/anthropic_tool_runner.py --live    # Claude (ANTHROPIC_API_KEY)

Needs a running gateway (TRIPWIRE_URL, TRIPWIRE_API_KEY) with the demo policy.
With --live, whether Claude follows the injected instruction is up to Claude;
either way the email to the attacker cannot be sent.
"""

from __future__ import annotations

import argparse
import sys

import anthropic
from _scenario import (
    USER_PROMPT,
    email__send_email,
    report,
    require_gateway,
    scripted_anthropic_client,
    web__fetch,
)

from tripwire_guard import Guard
from tripwire_guard.adapters.anthropic import guard_tools


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use Claude instead of the script")
    a = ap.parse_args()
    require_gateway()

    # One guard = one Tripwire session = one run for one user.
    guard = Guard(agent_name="example-anthropic", user_prompt=USER_PROMPT)
    client = anthropic.Anthropic() if a.live else scripted_anthropic_client()
    extra = (
        # Server-side fallback when a request is declined by a safety classifier.
        {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"} if a.live else {}
    )
    runner = client.beta.messages.tool_runner(
        model="claude-opus-5-5",
        max_tokens=16000,
        tools=guard_tools(guard, [web__fetch, email__send_email]),
        messages=[{"role": "user", "content": USER_PROMPT}],
        **extra,
    )
    final = runner.until_done()
    if final.stop_reason == "refusal":
        text = "(the model declined the request)"
    else:
        text = " ".join(b.text for b in final.content if b.type == "text")
    print(f"User: {USER_PROMPT}")
    return report(guard, text)


if __name__ == "__main__":
    sys.exit(main())
