"""tripwire-guard: guard an LLM agent's tool calls with a Tripwire gateway.

Core (httpx + pydantic only): `Guard`, `TripwireClient`, `AsyncTripwireClient`.
Adapters (optional extras): `tripwire_guard.adapters.anthropic`,
`tripwire_guard.adapters.langgraph`, `tripwire_guard.adapters.openai_agents`,
and `wrap()` which picks one by the object's type.
"""

from tripwire_guard.client import (
    AsyncTripwireClient,
    Decision,
    ResultCheck,
    TripwireClient,
    TripwireError,
    TripwireUnavailable,
)
from tripwire_guard.wrap import Guard, GuardOutcome, ToolBlocked
from tripwire_guard.wrapper import wrap

__all__ = [
    "AsyncTripwireClient",
    "Decision",
    "Guard",
    "GuardOutcome",
    "ResultCheck",
    "ToolBlocked",
    "TripwireClient",
    "TripwireError",
    "TripwireUnavailable",
    "wrap",
]
__version__ = "0.1.0"
