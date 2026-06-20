"""Run the pattern engine over the archive and persist a scan + findings.

A scan snapshots the active pattern set (``pattern_set_hash``) so results stay
reproducible and explainable. Only **verified** normalized source is scanned;
bytecode-only contracts are skipped (regex over bytecode is meaningless).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .engine import scan_source
from .patterns import Pattern, pattern_set_hash


@dataclass
class ScanStats:
    scan_id: int
    contracts_scanned: int
    findings: int
    by_severity: dict[str, int]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _snapshot_patterns(conn: sqlite3.Connection, patterns: list[Pattern]) -> None:
    for p in patterns:
        conn.execute(
            "INSERT OR REPLACE INTO patterns "
            "(id, name, severity, category, confidence, swc, cwe, version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (p.id, p.name, p.severity, p.category, p.confidence, p.swc, p.cwe, p.version),
        )


def run_scan(
    conn: sqlite3.Connection,
    patterns: list[Pattern],
    *,
    min_confidence: float = 0.0,
) -> ScanStats:
    psh = pattern_set_hash(patterns)
    with conn:
        _snapshot_patterns(conn, patterns)
        cur = conn.execute(
            "INSERT INTO scans (started_at, pattern_set_hash, engine) VALUES (?, ?, ?)",
            (_now(), psh, "python"),
        )
        scan_id = int(cur.lastrowid)

        rows = conn.execute(
            "SELECT contract_id, content FROM sources WHERE kind = 'normalized'"
        ).fetchall()

        contracts = 0
        total = 0
        for contract_id, content in rows:
            contracts += 1
            for f in scan_source(content or "", patterns, min_confidence=min_confidence):
                conn.execute(
                    "INSERT OR IGNORE INTO findings "
                    "(scan_id, contract_id, pattern_id, severity, confidence, "
                    " line, snippet, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id, contract_id, f.pattern_id, f.severity,
                        f.confidence, f.line, f.snippet, f.description,
                    ),
                )
                total += 1

        conn.execute(
            "UPDATE scans SET finished_at = ?, contracts_scanned = ? WHERE id = ?",
            (_now(), contracts, scan_id),
        )

    by_sev = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        )
    }
    return ScanStats(
        scan_id=scan_id, contracts_scanned=contracts, findings=total, by_severity=by_sev
    )
