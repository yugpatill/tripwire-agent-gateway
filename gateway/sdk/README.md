# tripwire-guard

Guard an LLM agent's tool calls with a [Tripwire](https://github.com/yugpatill/tripwire-agent-gateway) gateway. Every tool call is checked before it runs (taint labels, policy: allow, block, redact, require approval) and every tool result is checked before the model sees it (prompt injection, secrets, PII). A blocked call is never executed; the model gets the reason as the tool result.

The core needs only `httpx` and `pydantic`. Framework adapters are optional extras:

```bash
pip install "tripwire-guard[anthropic]"       # Anthropic tool use (Tool Runner or manual loop)
pip install "tripwire-guard[langgraph]"       # LangGraph ToolNode
pip install "tripwire-guard[openai-agents]"   # OpenAI Agents SDK
```

Configuration: `TRIPWIRE_URL` (default `http://localhost:8000`) and `TRIPWIRE_API_KEY` (an agent key: `tripwire keys create --name my-agent`), or pass `base_url=` / `api_key=`.

## One guard per run

```python
from tripwire_guard import Guard

guard = Guard(agent_name="support-bot", user_prompt=user_message)
```

A `Guard` is one Tripwire session: one agent run for one end user. Create a new one per run, never share one across users. Pass the user's own message as `user_prompt` (and later messages with `guard.user_turn(text)`), so addresses and accounts the user named count as user-given (instruction origin) and are not mistaken for injected ones. Never pass model output there.

## Anthropic

Tool Runner:

```python
import anthropic
from tripwire_guard.adapters.anthropic import guard_tools

client = anthropic.Anthropic()
runner = client.beta.messages.tool_runner(
    model="claude-opus-5-5",
    max_tokens=16000,
    tools=guard_tools(guard, [web__fetch, email__send_email]),  # plain functions
    messages=[{"role": "user", "content": user_message}],
)
final = runner.until_done()
```

The tool schema still comes from each function's signature and docstring. A blocked, denied or timed-out call raises the SDK's `ToolError`, so Claude receives a `tool_result` with `is_error: true` and the reason.

Manual loop: `run_tool_calls(guard, response, {"web__fetch": web__fetch, ...})` returns the `tool_result` blocks for every `tool_use` in a response (`arun_tool_calls` for async).

## LangGraph

```python
from langgraph.prebuilt import ToolNode
from tripwire_guard.adapters.langgraph import guard_tool_node

tools = guard_tool_node(guard, ToolNode([fetch_page, send_email]))
```

Uses ToolNode's `wrap_tool_call` / `awrap_tool_call` interceptors, so injected state and runtime arguments keep working and existing interceptors run inside the guard. A blocked call becomes a `ToolMessage` with `status="error"`. Tools that return a `Command` are checked before they run, but their state updates are not scanned.

## OpenAI Agents SDK

```python
from agents import Runner
from tripwire_guard.adapters.openai_agents import guard_agent

result = await Runner.run(guard_agent(guard, agent), user_message)
```

Every function tool, on the agent and on agents it hands off to, is guarded. Hosted tools (web search, file search, code interpreter, computer use, hosted MCP) run on OpenAI's side where Tripwire cannot see them, and custom `Handoff` objects cannot be guarded; `guard_agent` refuses both unless `allow_unguarded=True`.

## Generic

```python
from tripwire_guard import wrap

tools = wrap([web__fetch, email__send_email], user_prompt=user_message)  # Anthropic
node = wrap(ToolNode([...]), guard=guard)  # LangGraph
agent = wrap(agent, guard=guard)  # OpenAI Agents

outcome = guard.call("files__read_file", {"path": p}, read_file)  # any framework
safe_read = guard.tool(read_file)  # decorator, same signature
```

`GuardOutcome` has `status` (`allowed`, `blocked`, `denied`, `expired`, `error`, `unavailable`), `content` (what the model should see), `is_error`, `ran`, the gateway `decision`, and `suspicious_result` (the result looked like an injection). `guard.outcomes` keeps every call of the run.

Tool names must match the names in the Tripwire policy (the demo policy uses `server__tool`, for example `email__send_email`). Use `Guard(tool_names={"send_email": "email__send_email"})` to map framework names.

## Behaviour

| Gateway says | The tool | The model sees |
|---|---|---|
| `allow` / `log_only` | runs | the result, as Tripwire returns it (secrets redacted) |
| `redact` | runs with the redacted arguments | the result |
| `block` | does not run | `Blocked by Tripwire (<rule>): <message>` |
| `require_approval` | waits (polling, up to `approval_timeout`, 130 s) for an operator; runs if approved | the result, or `An operator denied this call…` / `No operator approved this call in time…` |
| gateway unreachable | does not run | `Tripwire is unavailable, so this call was not executed` |
| result cannot be vetted | ran | `…could not vet its result, so it was withheld` |

## Examples

`examples/` has one script per adapter. Each runs end to end against a local gateway with the demo policy: the user asks for a page summary, the page hides an instruction to email `attacker@evil.io`, the model follows it, and Tripwire blocks the email.

```bash
docker compose up -d                 # from the repository root
export TRIPWIRE_API_KEY=$(docker compose exec -T gateway tripwire keys create --name demo | grep -o 'tw_[A-Za-z0-9_-]*')
cd gateway/sdk && uv sync --all-extras
uv run python examples/anthropic_tool_runner.py      # --live: real Claude (ANTHROPIC_API_KEY)
uv run python examples/langgraph_agent.py
uv run python examples/openai_agents_agent.py        # --live: SDK default model (OPENAI_API_KEY)
```

Without `--live` the model is scripted, so no LLM API key is needed. With `--live`, whether the model follows the injected instruction is up to the model; the email still cannot be sent.

Tests: `uv run pytest` (unit tests, no gateway) and `TRIPWIRE_URL=... TRIPWIRE_API_KEY=... uv run pytest -m live` (each adapter: an injected tool result leads to a blocked tool call, against a real gateway).

License: MIT.
