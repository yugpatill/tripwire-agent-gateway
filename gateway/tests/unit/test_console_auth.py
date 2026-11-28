"""Console JWT and access rules (no database)."""

from __future__ import annotations

import time

import jwt
import pytest

from tripwire.auth.console import (
    ConsoleUser,
    demo_password,
    issue_token,
    read_token,
    secret_usable,
)
from tripwire.config import Settings

SECRET = "s3cret-for-tests"


def settings(**kw: object) -> Settings:
    values: dict[str, object] = {"jwt_secret": SECRET, "log_json": False, **kw}
    return Settings(**values)  # type: ignore[arg-type]


def test_token_roundtrip_and_roles() -> None:
    s = settings()
    admin = ConsoleUser("a@x", "admin")
    assert read_token(issue_token(admin, s), s) == admin
    demo = read_token(issue_token(ConsoleUser("demo", "readonly"), s), s)
    assert demo is not None and not demo.can_write


def test_tampered_expired_or_foreign_tokens_are_rejected() -> None:
    s = settings()
    good = issue_token(ConsoleUser("a@x", "admin"), s)
    assert read_token(good + "x", s) is None
    foreign = issue_token(ConsoleUser("a@x", "admin"), settings(jwt_secret="other"))
    assert read_token(foreign, s) is None
    expired = jwt.encode({"sub": "a", "role": "admin", "exp": int(time.time()) - 10}, SECRET)
    assert read_token(expired, s) is None
    unsigned = jwt.encode({"sub": "a", "role": "admin", "exp": 9999999999}, None, "none")
    assert read_token(unsigned, s) is None


def test_unknown_role_is_read_only() -> None:
    tok = jwt.encode({"sub": "a", "role": "root", "exp": 9999999999}, SECRET)
    user = read_token(tok, settings())
    assert user is not None and user.role == "readonly"


@pytest.mark.parametrize(
    ("env", "secret", "usable"),
    [
        ("development", "change-me", True),
        ("production", "change-me", False),
        ("production", "x" * 32, True),
    ],
)
def test_placeholder_secret_refused_in_production(env: str, secret: str, usable: bool) -> None:
    assert secret_usable(settings(tripwire_env=env, jwt_secret=secret)) is usable


def test_demo_password_defaults() -> None:
    assert demo_password(settings()) == "demo"
    assert demo_password(settings(tripwire_env="production")) is None
    assert demo_password(settings(tripwire_env="production", demo_readonly_password="pw")) == "pw"
