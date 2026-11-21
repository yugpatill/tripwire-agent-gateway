"""FastAPI dependency enforcing agent API keys on /v1 endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from tripwire.auth.api_keys import ApiKeyAuthenticator, Principal

bearer = HTTPBearer(auto_error=False, description="Agent API key: `Bearer tw_...`")


async def require_api_key(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None or creds.scheme.lower() != "bearer":
        raise unauthorized
    auth: ApiKeyAuthenticator = request.app.state.authenticator
    try:
        principal = await auth.authenticate(creds.credentials)
    except Exception as exc:  # auth backend down: refuse, never allow
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Auth unavailable"
        ) from exc
    if principal is None:
        raise unauthorized
    request.state.principal = principal
    return principal
