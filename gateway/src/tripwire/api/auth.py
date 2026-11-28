"""Console sign-in: POST /v1/auth/login, logout, me, and the public demo credentials."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from tripwire.auth.console import (
    COOKIE,
    DEMO_USER,
    TOKEN_TTL_S,
    ConsoleUser,
    UserStore,
    console_reader,
    demo_password,
    issue_token,
    secret_usable,
)
from tripwire.config import Settings
from tripwire.playground.store import hash_ip

router = APIRouter(prefix="/v1/auth", tags=["auth"])
LOGIN_ATTEMPTS_PER_10_MIN = 10


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1000)


class Me(BaseModel):
    username: str
    role: str
    can_write: bool


def _me(user: ConsoleUser) -> Me:
    return Me(username=user.name, role=user.role, can_write=user.can_write)


@router.post("/login", response_model=Me)
async def login(body: LoginRequest, request: Request, response: Response) -> Me:
    settings: Settings = request.app.state.settings
    if not secret_usable(settings):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Set JWT_SECRET to enable sign-in")
    redis = request.app.state.redis
    ip = request.client.host if request.client else "unknown"
    key = f"tripwire:login:{hash_ip(ip, settings.jwt_secret.get_secret_value())}"
    try:
        attempts = await redis.incr(key)
        if attempts == 1:
            await redis.expire(key, 600)
    except Exception:
        attempts = 0  # rate limiting is best effort; the password check still applies
    if attempts > LOGIN_ATTEMPTS_PER_10_MIN:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts; wait a few minutes"
        )
    users: UserStore = request.app.state.users
    user = await users.check(body.username, body.password)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password")
    response.set_cookie(
        COOKIE,
        issue_token(user, settings),
        max_age=TOKEN_TTL_S,
        httponly=True,
        secure=settings.tripwire_env == "production",
        samesite="lax",
        path="/",
    )
    return _me(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/")


@router.get("/me", response_model=Me)
async def me(user: Annotated[ConsoleUser, Depends(console_reader)]) -> Me:
    return _me(user)


class DemoCredentials(BaseModel):
    username: str
    password: str


@router.get("/demo", response_model=DemoCredentials)
async def demo_credentials(request: Request) -> DemoCredentials:
    """The read-only demo account, shown on the login page (public by design)."""
    pw = demo_password(request.app.state.settings)
    if pw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No demo account on this deployment")
    return DemoCredentials(username=DEMO_USER, password=pw)
