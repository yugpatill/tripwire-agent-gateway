"""`tripwire` command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from collections.abc import Awaitable, Callable

from tripwire import __version__


def _with_keys[T](fn: Callable[..., Awaitable[T]]) -> T:
    from tripwire.auth.api_keys import SqlKeyRepository
    from tripwire.config import get_settings
    from tripwire.db.session import make_engine, make_sessionmaker

    async def run() -> T:
        engine = make_engine(get_settings().database_url)
        try:
            return await fn(SqlKeyRepository(make_sessionmaker(engine)))
        finally:
            await engine.dispose()

    return asyncio.run(run())


def _keys(args: argparse.Namespace) -> int:
    if args.keys_command == "create":
        key = _with_keys(lambda repo: repo.create(args.name))
        print(f"Created API key {key.id} for {key.name!r}.")
        print("Store it now; it cannot be shown again:\n")
        print(key.token)
        return 0
    if args.keys_command == "list":
        for rec in _with_keys(lambda repo: repo.list()):
            status = "revoked" if rec.revoked else "active"
            print(f"{rec.id}  tw_{rec.prefix}_...  {status:7}  {rec.name}")
        return 0
    if args.keys_command == "revoke":
        ok = _with_keys(lambda repo: repo.revoke(uuid.UUID(args.key_id)))
        print("revoked (active caches expire within 60 s)" if ok else "no such key")
        return 0 if ok else 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tripwire")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("openapi", help="print the OpenAPI schema as JSON")

    keys = sub.add_parser("keys", help="manage agent API keys")
    ksub = keys.add_subparsers(dest="keys_command", required=True)
    create = ksub.add_parser("create", help="create a key and print it once")
    create.add_argument("--name", required=True, help="agent name, e.g. support-bot")
    ksub.add_parser("list", help="list keys (prefix only)")
    revoke = ksub.add_parser("revoke", help="revoke a key by id")
    revoke.add_argument("key_id")

    args = parser.parse_args(argv)
    if args.command == "openapi":
        from tripwire.main import create_app

        json.dump(create_app().openapi(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "keys":
        return _keys(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
