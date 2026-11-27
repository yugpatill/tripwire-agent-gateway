"""HTTP client for the Tripwire gateway's decision API (`/v1`).

Only `httpx` and `pydantic`. Every network or HTTP failure raises
`TripwireUnavailable`; the guard treats that as a block (fail closed).
"""

from __future__ import annotations

import os
from typing import Any, Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict

Action = Literal["allow", "block", "redact", "require_approval", "log_only"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]
DEFAULT_URL = "http://localhost:8000"


class TripwireError(Exception):
    """Base class for tripwire-guard errors."""


class TripwireUnavailable(TripwireError):
    """The gateway could not be reached or returned an error."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Detector(_Model):
    detector: str
    score: float
    reason: str = ""


class Decision(_Model):
    event_id: UUID
    action: Action
    rule_id: str | None = None
    message: str = ""
    detectors: list[Detector] = []
    redacted_args: dict[str, Any] | None = None
    latency_ms: float = 0.0
    approval_id: UUID | None = None


class ResultCheck(_Model):
    content_redacted: Any
    decision: Decision
    detectors: list[Detector] = []

    @property
    def suspicious(self) -> bool:
        return any(
            d.detector in ("heuristic", "classifier") and d.score >= 0.5 for d in self.detectors
        )


class Approval(_Model):
    id: UUID
    status: ApprovalStatus
    tool: str


def _settings(base_url: str | None, api_key: str | None) -> tuple[str, str]:
    url = (base_url or os.environ.get("TRIPWIRE_URL") or DEFAULT_URL).rstrip("/")
    key = api_key or os.environ.get("TRIPWIRE_API_KEY") or ""
    if not key:
        raise TripwireError("no API key: pass api_key= or set TRIPWIRE_API_KEY")
    return url, key


def _raise_for(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        detail = resp.text[:300]
        raise TripwireUnavailable(f"Tripwire returned {resp.status_code}: {detail}")


class TripwireClient:
    """Synchronous client. `base_url`/`api_key` default to TRIPWIRE_URL/TRIPWIRE_API_KEY."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url, key = _settings(base_url, api_key)
        self._http = http_client or httpx.Client(base_url=self.base_url, timeout=timeout)
        self._headers = {"Authorization": f"Bearer {key}"}

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        try:
            resp = self._http.post(f"{self.base_url}{path}", json=body, headers=self._headers)
        except httpx.HTTPError as exc:
            raise TripwireUnavailable(f"Tripwire unreachable: {exc!r}") from exc
        _raise_for(resp)
        return resp.json()

    def _get(self, path: str) -> Any:
        try:
            resp = self._http.get(f"{self.base_url}{path}", headers=self._headers)
        except httpx.HTTPError as exc:
            raise TripwireUnavailable(f"Tripwire unreachable: {exc!r}") from exc
        _raise_for(resp)
        return resp.json()

    def create_session(
        self, agent_name: str, user_prompt: str = "", mode: Literal["enforce", "shadow"] = "enforce"
    ) -> UUID:
        data = self._post(
            "/v1/sessions", {"agent_name": agent_name, "user_prompt": user_prompt, "mode": mode}
        )
        return UUID(data["session_id"])

    def add_prompt(self, session_id: UUID, text: str) -> bool:
        return bool(self._post(f"/v1/sessions/{session_id}/prompts", {"text": text})["added"])

    def check_call(self, session_id: UUID, tool: str, args: dict[str, Any]) -> Decision:
        body = {"session_id": str(session_id), "tool": tool, "args": args}
        return Decision.model_validate(self._post("/v1/check/call", body))

    def check_result(
        self, session_id: UUID, tool: str, call_event_id: UUID, content: Any
    ) -> ResultCheck:
        body = {
            "session_id": str(session_id),
            "tool": tool,
            "call_event_id": str(call_event_id),
            "content": content,
        }
        return ResultCheck.model_validate(self._post("/v1/check/result", body))

    def get_approval(self, approval_id: UUID) -> Approval:
        return Approval.model_validate(self._get(f"/v1/approvals/{approval_id}"))

    def close(self) -> None:
        self._http.close()


class AsyncTripwireClient:
    """Asynchronous client with the same methods as `TripwireClient`."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url, key = _settings(base_url, api_key)
        self._http = http_client or httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        self._headers = {"Authorization": f"Bearer {key}"}

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        try:
            resp = await self._http.post(f"{self.base_url}{path}", json=body, headers=self._headers)
        except httpx.HTTPError as exc:
            raise TripwireUnavailable(f"Tripwire unreachable: {exc!r}") from exc
        _raise_for(resp)
        return resp.json()

    async def _get(self, path: str) -> Any:
        try:
            resp = await self._http.get(f"{self.base_url}{path}", headers=self._headers)
        except httpx.HTTPError as exc:
            raise TripwireUnavailable(f"Tripwire unreachable: {exc!r}") from exc
        _raise_for(resp)
        return resp.json()

    async def create_session(
        self, agent_name: str, user_prompt: str = "", mode: Literal["enforce", "shadow"] = "enforce"
    ) -> UUID:
        data = await self._post(
            "/v1/sessions", {"agent_name": agent_name, "user_prompt": user_prompt, "mode": mode}
        )
        return UUID(data["session_id"])

    async def add_prompt(self, session_id: UUID, text: str) -> bool:
        data = await self._post(f"/v1/sessions/{session_id}/prompts", {"text": text})
        return bool(data["added"])

    async def check_call(self, session_id: UUID, tool: str, args: dict[str, Any]) -> Decision:
        body = {"session_id": str(session_id), "tool": tool, "args": args}
        return Decision.model_validate(await self._post("/v1/check/call", body))

    async def check_result(
        self, session_id: UUID, tool: str, call_event_id: UUID, content: Any
    ) -> ResultCheck:
        body = {
            "session_id": str(session_id),
            "tool": tool,
            "call_event_id": str(call_event_id),
            "content": content,
        }
        return ResultCheck.model_validate(await self._post("/v1/check/result", body))

    async def get_approval(self, approval_id: UUID) -> Approval:
        return Approval.model_validate(await self._get(f"/v1/approvals/{approval_id}"))

    async def aclose(self) -> None:
        await self._http.aclose()
