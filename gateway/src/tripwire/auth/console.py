"""Console authentication: users, JWT session cookie, and console access checks.

Two users are seeded on first use:
- the admin, from ADMIN_EMAIL / ADMIN_PASSWORD (only when both are set);
- `demo`, read-only, password DEMO_READONLY_PASSWORD. Its credentials are public
  on purpose (the login page shows them). In development it defaults to `demo`;
  in production it exists only when DEMO_READONLY_PASSWORD is set.

The browser holds an HS256 JWT in an httpOnly cookie. Console endpoints accept
that cookie or an operator API key. Read-only users may read; only admins (and
operator keys) may decide approvals, re-pin tools or change the policy.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import jwt
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tripwire.auth.api_keys import ApiKeyAuthenticator
from tripwire.auth.deps import bearer
from tripwire.config import Settings
from tripwire.db import models as db

log = structlog.get_logger(__name__)

COOKIE = "tripwire_session"
TOKEN_TTL_S = 12 * 3600
DEMO_USER = "demo"
PLACEHOLDER_SECRET = "change-me"  # noqa: S105  # the default we refuse in production
_hasher = PasswordHasher()

Role = Literal["admin", "readonly"]


@dataclass(frozen=True, slots=True)
class ConsoleUser:
    name: str
    role: Role
    via: Literal["cookie", "api_key"] = "cookie"

    @property
    def can_write(self) -> bool:
        return self.role == "admin"


def demo_password(settings: Settings) -> str | None:
    pw = settings.demo_readonly_password.get_secret_value()
    if pw:
        return pw
    return None if settings.tripwire_env == "production" else "demo"


def secret_usable(settings: Settings) -> bool:
    s = settings.jwt_secret.get_secret_value()
    return bool(s) and not (settings.tripwire_env == "production" and s == PLACEHOLDER_SECRET)


class UserStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession], settings: Settings) -> None:
        self._factory = factory
        self._settings = settings
        self._seeded = False

    async def seed(self) -> None:
        """Create or update the admin and demo users (idempotent, retried until it works)."""
        if self._seeded:
            return
        wanted: list[tuple[str, str, Role]] = []
        admin_pw = self._settings.admin_password.get_secret_value()
        if self._settings.admin_email and admin_pw:
            wanted.append((self._settings.admin_email.lower(), admin_pw, "admin"))
        demo_pw = demo_password(self._settings)
        if demo_pw:
            wanted.append((DEMO_USER, demo_pw, "readonly"))
        async with self._factory() as s, s.begin():
            for email, pw, role in wanted:
                row = await s.scalar(select(db.User).where(db.User.email == email))
                if row is not None and _verify(row.password_hash, pw) and row.role == role:
                    continue
                pw_hash = await asyncio.to_thread(_hasher.hash, pw)
                if row is None:
                    s.add(db.User(email=email, password_hash=pw_hash, role=role))
                else:
                    row.password_hash, row.role = pw_hash, role
            if not demo_pw:  # demo disabled: make sure an old demo row cannot log in
                old = await s.scalar(select(db.User).where(db.User.email == DEMO_USER))
                if old is not None:
                    await s.delete(old)
        self._seeded = True

    async def check(self, name: str, password: str) -> ConsoleUser | None:
        await self.seed()
        async with self._factory() as s:
            row = await s.scalar(select(db.User).where(db.User.email == name.strip().lower()))
        if row is None:
            await asyncio.to_thread(_verify, _DUMMY_HASH, password)  # same cost either way
            return None
        if not await asyncio.to_thread(_verify, row.password_hash, password):
            return None
        return ConsoleUser(row.email, "admin" if row.role == "admin" else "readonly")


def _verify(hashed: str, password: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


_DUMMY_HASH = _hasher.hash("not-a-real-password")


def issue_token(user: ConsoleUser, settings: Settings) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": user.name, "role": user.role, "iat": now, "exp": now + TOKEN_TTL_S},
        settings.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


def read_token(token: str, settings: Settings) -> ConsoleUser | None:
    if not secret_usable(settings):
        return None
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            options={"require": ["exp", "sub", "role"]},
        )
    except jwt.PyJWTError:
        return None
    role: Role = "admin" if claims.get("role") == "admin" else "readonly"
    return ConsoleUser(str(claims["sub"]), role)


async def _from_request(
    request: Request | WebSocket, creds: HTTPAuthorizationCredentials | None
) -> ConsoleUser | None:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(COOKIE)
    if token:
        user = read_token(token, settings)
        if user is not None:
            return user
    if creds is not None and creds.scheme.lower() == "bearer":
        auth: ApiKeyAuthenticator = request.app.state.authenticator
        try:
            principal = await auth.authenticate(creds.credentials)
        except Exception as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Auth unavailable") from exc
        if principal is not None:
            if not principal.is_operator:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Operator API key required")
            return ConsoleUser(f"key:{principal.name}", "admin", "api_key")
    return None


async def console_reader(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> ConsoleUser:
    """Any signed-in console user, or an operator API key."""
    user = await _from_request(request, creds)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to the console")
    return user


async def console_writer(user: Annotated[ConsoleUser, Depends(console_reader)]) -> ConsoleUser:
    """Admins and operator API keys only (the demo account is read-only)."""
    if not user.can_write:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The demo account is read-only")
    return user


async def websocket_user(ws: WebSocket) -> ConsoleUser | None:
    """Console user for a WebSocket: session cookie, or `Authorization: Bearer <operator key>`."""
    header = ws.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    creds = HTTPAuthorizationCredentials(scheme=scheme, credentials=token) if token else None
    try:
        return await _from_request(ws, creds)
    except HTTPException:
        return None
