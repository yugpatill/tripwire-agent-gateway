"""`tripwire` command line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from tripwire import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tripwire")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("openapi", help="print the OpenAPI schema as JSON")
    args = parser.parse_args(argv)

    if args.command == "openapi":
        from tripwire.main import create_app

        json.dump(create_app().openapi(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
