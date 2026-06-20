"""Seshat command-line interface.

Phase 0 ships ``seshat init``. Later phases add ingest / scan / query / diff /
report. The CLI is non-blocking: it never drops into an interactive prompt when
arguments are supplied (so automation and CI never hang).
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

from . import __version__, engine, ingest
from . import patterns as patterns_mod
from . import query as query_mod
from .db import init_db
from .diff import diff_scans
from .explorer import ExplorerError
from .scan import run_scan
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


def _load_catalog(args: argparse.Namespace):
    catalog = args.patterns or str(patterns_mod.default_catalog_dir())
    return patterns_mod.load_patterns(catalog), catalog


def _cmd_scan(args: argparse.Namespace) -> int:
    pats, catalog = _load_catalog(args)
    if not pats:
        print(f"error: no patterns found in {catalog}", file=sys.stderr)
        return 1
    conn, _, _ = init_db(args.db)
    try:
        stats = run_scan(
            conn, pats, min_confidence=args.min_confidence, incremental=args.incremental
        )
    finally:
        conn.close()
    sev = stats.by_severity
    order = ("critical", "high", "medium", "low", "info")
    breakdown = " · ".join(f"{s}:{sev.get(s, 0)}" for s in order if sev.get(s))
    print(
        f"🔍 scan #{stats.scan_id}: {stats.contracts_scanned} contracts, "
        f"{len(pats)} patterns → {stats.findings} review flags"
        + (f" ({breakdown})" if breakdown else "")
    )
    if args.incremental:
        print(f"   ♻️  incremental: {stats.rescanned} re-scanned, {stats.reused} reused")
    print("   ⚠️  flags are heuristic review pointers, not confirmed vulnerabilities.")
    return 0


def _print_rows(rows) -> None:
    if not rows:
        print("(no rows)")
        return
    cols = list(rows[0].keys())
    widths = [len(c) for c in cols]
    data = [[("" if r[c] is None else str(r[c])) for c in cols] for r in rows]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    print("  ".join(c.ljust(widths[i]) for i, c in enumerate(cols)))
    print("  ".join("-" * widths[i] for i in range(len(cols))))
    for row in data:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    print(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")


def _cmd_query(args: argparse.Namespace) -> int:
    if args.list:
        print("canned queries: " + ", ".join(sorted(query_mod.CANNED)))
        return 0
    if not (args.sql or args.canned):
        print("error: provide SQL, --canned NAME, or --list", file=sys.stderr)
        return 2
    try:
        conn = query_mod.connect_ro(args.db)
    except sqlite3.OperationalError as exc:
        print(f"error: cannot open {args.db}: {exc}", file=sys.stderr)
        return 1
    try:
        if args.canned:
            rows = query_mod.run_canned(conn, args.canned, scan=args.scan)
        else:
            rows = query_mod.run_sql(conn, args.sql)
    except (sqlite3.Error, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    _print_rows(rows)
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    try:
        conn = query_mod.connect_ro(args.db)
    except sqlite3.OperationalError as exc:
        print(f"error: cannot open {args.db}: {exc}", file=sys.stderr)
        return 1
    try:
        hits = query_mod.search_source(
            conn, args.term, regex=args.regex, kind=args.kind, limit=args.limit
        )
    except re.error as exc:
        print(f"error: bad regex: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    if not hits:
        print("(no matches)")
        return 0
    for h in hits:
        loc = f"{h.chain_key or '(local)'}#{h.contract_id}"
        print(f"{loc:<18} L{h.line:<5} {h.text}")
    print(f"({len(hits)} match{'es' if len(hits) != 1 else ''})")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        conn = query_mod.connect_ro(args.db)
    except sqlite3.OperationalError as exc:
        print(f"error: cannot open {args.db}: {exc}", file=sys.stderr)
        return 1
    try:
        result = diff_scans(conn, args.scan_a, args.scan_b)
    finally:
        conn.close()
    print(f"⚖️  diff scan #{result.scan_a} → #{result.scan_b}")
    print(f"   🆕 new: {len(result.new)}   ✅ fixed: {len(result.fixed)}   "
          f"🔁 regressed: {len(result.regressed)}")
    if args.verbose:
        for label, items in (("new", result.new), ("fixed", result.fixed),
                             ("regressed", result.regressed)):
            for contract_id, pattern_id, line in items:
                print(f"   [{label}] contract#{contract_id} {pattern_id} L{line}")
    return 0


def _cmd_patterns(args: argparse.Namespace) -> int:
    pats, catalog = _load_catalog(args)
    if args.validate:
        problems: list[str] = []
        for p in pats:
            problems.extend(patterns_mod.validate_pattern(p))
            problems.extend(engine.check_pattern_fixtures(p))
        if problems:
            print(f"❌ {len(problems)} problem(s) in {len(pats)} patterns:", file=sys.stderr)
            for prob in problems:
                print(f"   - {prob}", file=sys.stderr)
            return 1
        print(f"✅ {len(pats)} patterns valid — all fixtures pass ({catalog})")
        return 0
    print(f"📋 {len(pats)} patterns ({catalog}):")
    for p in pats:
        print(f"   {p.id}  {p.severity:<8} {p.category:<18} {p.name}")
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

    p_scan = sub.add_parser("scan", help="run the pattern engine over the archive")
    p_scan.add_argument("--db", default="seshat.db", help="archive path")
    p_scan.add_argument("--patterns", help="pattern catalog dir (default: bundled)")
    p_scan.add_argument(
        "--min-confidence", type=float, default=0.0,
        help="drop detectors below this confidence (default: 0.0)",
    )
    p_scan.add_argument(
        "--incremental", action="store_true",
        help="reuse results for contracts unchanged since the last scan",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_q = sub.add_parser("query", help="run raw SQL or a canned query (read-only)")
    p_q.add_argument("sql", nargs="?", help="a SELECT statement")
    p_q.add_argument("--db", default="seshat.db", help="archive path")
    p_q.add_argument("--canned", help="a named query (see --list)")
    p_q.add_argument("--scan", type=int, help="scan id for canned queries (default: latest)")
    p_q.add_argument("--list", action="store_true", help="list canned queries")
    p_q.set_defaults(func=_cmd_query)

    p_s = sub.add_parser("search", help="full-text search over stored source")
    p_s.add_argument("term", help="substring (or regex with --regex)")
    p_s.add_argument("--db", default="seshat.db", help="archive path")
    p_s.add_argument("--regex", action="store_true", help="treat term as a regex")
    p_s.add_argument("--kind", default="normalized",
                     choices=["normalized", "raw", "all"], help="source kind to search")
    p_s.add_argument("--limit", type=int, default=100, help="max hits (default: 100)")
    p_s.set_defaults(func=_cmd_search)

    p_d = sub.add_parser("diff", help="diff two scans (new / fixed / regressed)")
    p_d.add_argument("scan_a", type=int, help="baseline scan id")
    p_d.add_argument("scan_b", type=int, help="comparison scan id")
    p_d.add_argument("--db", default="seshat.db", help="archive path")
    p_d.add_argument("-v", "--verbose", action="store_true", help="list each finding")
    p_d.set_defaults(func=_cmd_diff)

    p_pat = sub.add_parser("patterns", help="list or validate the pattern catalog")
    p_pat.add_argument("--patterns", help="pattern catalog dir (default: bundled)")
    p_pat.add_argument(
        "--validate", action="store_true",
        help="validate every pattern and run its fixtures (non-zero exit on failure)",
    )
    p_pat.set_defaults(func=_cmd_patterns)

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
