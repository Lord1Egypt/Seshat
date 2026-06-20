"""Seshat command-line interface.

Phase 0 ships ``seshat init``. Later phases add ingest / scan / query / diff /
report. The CLI is non-blocking: it never drops into an interactive prompt when
arguments are supplied (so automation and CI never hang).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, ingest
from .db import init_db
from .explorer import ExplorerError
from .store import IngestResult


def _cmd_init(args: argparse.Namespace) -> int:
    conn, version, created = init_db(args.db)
    conn.close()
    state = "created" if created else "already present"
    print(f"📜 Seshat archive {state}: {args.db} (schema v{version})")
    if not created:
        print("   nothing to do — schema is up to date.")
    return 0


def _detect_type(target: str | None, address: str | None) -> str:
    if address and not target:
        return "address"
    if not target:
        return "address"
    p = Path(target)
    if p.is_dir():
        return "project"
    suffix = p.suffix.lower()
    if suffix == ".sol":
        return "sol"
    if suffix in (".json", ".txt"):
        return "standard-json"
    return "sol"


def _report(results: list[IngestResult], db: str) -> int:
    if not results:
        print("📥 nothing ingested (no source found).")
        return 0
    created = sum(1 for r in results if r.created)
    existing = len(results) - created
    verified = sum(1 for r in results if r.has_verified_source)
    print(
        f"📥 ingested into {db}: {created} new, {existing} already present "
        f"({len(results)} contracts, {verified} with verified source)"
    )
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    conn, _, _ = init_db(args.db)
    kind = args.type if args.type != "auto" else _detect_type(args.target, args.address)
    try:
        if kind == "address":
            if not (args.chain and args.address):
                print("error: address ingest needs --chain and --address", file=sys.stderr)
                return 2
            results = [
                ingest.ingest_address(
                    conn, args.chain, args.address, online=args.online,
                    api_key=args.api_key, force=args.force,
                )
            ]
        elif kind in ("project", "foundry", "hardhat"):
            origin = None if kind == "project" else kind
            results = ingest.ingest_project(conn, args.target, chain=args.chain, origin=origin)
        elif kind == "sol":
            results = [ingest.ingest_solidity_file(
                conn, args.target, chain=args.chain, address=args.address, name=args.name,
            )]
        elif kind == "standard-json":
            results = [ingest.ingest_standard_json(
                conn, args.target, chain=args.chain, address=args.address, name=args.name,
            )]
        elif kind == "bytecode":
            code = Path(args.target).read_text(encoding="utf-8", errors="replace")
            results = [ingest.ingest_bytecode(
                conn, code, chain=args.chain, address=args.address, name=args.name,
            )]
        elif kind == "registry":
            results = ingest.ingest_maateye_registry(conn, args.target)
        else:
            print(f"error: unknown ingest type '{kind}'", file=sys.stderr)
            return 2
    except (ExplorerError, FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return _report(results, args.db)


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

    p_ing = sub.add_parser(
        "ingest", help="import contracts into the archive (offline-first)"
    )
    p_ing.add_argument(
        "target", nargs="?",
        help="path to a .sol file, Standard-JSON, project dir, or registry "
             "(omit when using --address)",
    )
    p_ing.add_argument("--db", default="seshat.db", help="archive path (default: seshat.db)")
    p_ing.add_argument(
        "--type", default="auto",
        choices=[
            "auto", "sol", "standard-json", "project", "foundry", "hardhat",
            "bytecode", "registry", "address",
        ],
        help="source type (default: auto-detect)",
    )
    p_ing.add_argument("--chain", help="chain key, e.g. ethereum, base, polygon")
    p_ing.add_argument("--address", help="contract address (for on-chain contracts)")
    p_ing.add_argument("--name", help="contract name override")
    p_ing.add_argument(
        "--online", action="store_true",
        help="allow a network fetch for --address (off by default; offline-first)",
    )
    p_ing.add_argument("--api-key", help="explorer API key (for --online)")
    p_ing.add_argument(
        "--force", action="store_true", help="re-fetch even if cached (--address)"
    )
    p_ing.set_defaults(func=_cmd_ingest)

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
