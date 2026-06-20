"""Query the archive — raw SQL, canned reports, and full-text source search.

Everything here is read-only. The CLI opens the DB in SQLite read-only mode so
an ad-hoc ``query`` can never mutate the archive.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

# Canned queries. ``:scan`` binds to a chosen scan id (default: latest).
CANNED: dict[str, str] = {
    "summary": (
        "SELECT s.id AS scan, s.finished_at, s.contracts_scanned, "
        "COUNT(f.id) AS findings "
        "FROM scans s LEFT JOIN findings f ON f.scan_id = s.id "
        "GROUP BY s.id ORDER BY s.id DESC"
    ),
    "by-severity": (
        "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = :scan "
        "GROUP BY severity ORDER BY n DESC"
    ),
    "top-patterns": (
        "SELECT f.pattern_id, p.name, p.severity, COUNT(*) AS n "
        "FROM findings f LEFT JOIN patterns p ON p.id = f.pattern_id "
        "WHERE f.scan_id = :scan GROUP BY f.pattern_id ORDER BY n DESC LIMIT 25"
    ),
    "by-chain": (
        "SELECT COALESCE(c.chain_key, '(local)') AS chain, COUNT(*) AS findings "
        "FROM findings f JOIN contracts c ON c.id = f.contract_id "
        "WHERE f.scan_id = :scan GROUP BY chain ORDER BY findings DESC"
    ),
    "by-category": (
        "SELECT p.category, COUNT(*) AS n FROM findings f "
        "JOIN patterns p ON p.id = f.pattern_id "
        "WHERE f.scan_id = :scan GROUP BY p.category ORDER BY n DESC"
    ),
    "flagged-contracts": (
        "SELECT c.id, COALESCE(c.name, '?') AS name, "
        "COALESCE(c.chain_key, '(local)') AS chain, COUNT(*) AS findings "
        "FROM findings f JOIN contracts c ON c.id = f.contract_id "
        "WHERE f.scan_id = :scan GROUP BY c.id ORDER BY findings DESC LIMIT 25"
    ),
    "critical": (
        "SELECT f.pattern_id, c.name, f.line, f.snippet FROM findings f "
        "JOIN contracts c ON c.id = f.contract_id "
        "WHERE f.scan_id = :scan AND f.severity = 'critical' "
        "ORDER BY c.id, f.line LIMIT 200"
    ),
}


@dataclass
class SearchHit:
    contract_id: int
    name: str | None
    chain_key: str | None
    line: int
    text: str


def connect_ro(path: str | Path) -> sqlite3.Connection:
    """Open an existing archive read-only."""
    uri = f"file:{Path(path).as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
    return row[0] if row and row[0] is not None else None


def run_sql(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def run_canned(conn: sqlite3.Connection, name: str, scan: int | None = None) -> list[sqlite3.Row]:
    if name not in CANNED:
        raise KeyError(f"unknown canned query {name!r}; choose from {sorted(CANNED)}")
    sql = CANNED[name]
    params: dict = {}
    if ":scan" in sql:
        params["scan"] = scan if scan is not None else latest_scan_id(conn)
    return conn.execute(sql, params).fetchall()


def search_source(
    conn: sqlite3.Connection,
    term: str,
    *,
    regex: bool = False,
    kind: str = "normalized",
    limit: int = 100,
) -> list[SearchHit]:
    """Full-text search over stored source, returning per-line hits.

    ``kind`` is ``normalized`` (analyzed blob), ``raw``, or ``all``.
    """
    if regex:
        rx = re.compile(term)
        matcher = rx.search
        where, args = "1=1", []
    else:
        matcher = None
        where = "s.content LIKE ? ESCAPE '\\'"
        args = ["%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"]

    kind_sql = "" if kind == "all" else "AND s.kind = ?"
    args2 = [] if kind == "all" else [kind]

    sql = (
        "SELECT s.contract_id, s.content, c.name, c.chain_key "
        "FROM sources s JOIN contracts c ON c.id = s.contract_id "
        f"WHERE {where} {kind_sql}"
    )
    rows = conn.execute(sql, (args + args2)).fetchall()

    hits: list[SearchHit] = []
    needle = term if not regex else None
    for r in rows:
        content = r["content"] or ""
        for i, line in enumerate(content.split("\n"), start=1):
            ok = matcher(line) if regex else (needle in line)
            if ok:
                hits.append(SearchHit(
                    contract_id=r["contract_id"], name=r["name"],
                    chain_key=r["chain_key"], line=i, text=line.strip()[:160],
                ))
                if len(hits) >= limit:
                    return hits
    return hits
