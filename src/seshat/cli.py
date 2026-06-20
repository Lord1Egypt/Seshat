"""Seshat command-line interface.

Phase 0 ships ``seshat init``. Later phases add ingest / scan / query / diff /
report. The CLI is non-blocking: it never drops into an interactive prompt when
arguments are supplied (so automation and CI never hang).
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .db import init_db


def _cmd_init(args: argparse.Namespace) -> int:
    conn, version, created = init_db(args.db)
    conn.close()
    state = "created" if created else "already present"
    print(f"📜 Seshat archive {state}: {args.db} (schema v{version})")
    if not created:
        print("   nothing to do — schema is up to date.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seshat",
        description="Offline-first smart-contract vulnerability scanner + local archive.",
    )
    parser.add_argument(
        "--version", action="version", version=f"seshat {__version__}"
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_init = sub.add_parser(
        "init", help="create/upgrade a local seshat.db archive (idempotent)"
    )
    p_init.add_argument(
        "--db", default="seshat.db", help="path to the archive (default: seshat.db)"
    )
    p_init.set_defaults(func=_cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
