"""Run the pattern engine over the archive and persist a scan + findings.

A scan snapshots the active pattern set (``pattern_set_hash``) so results stay
reproducible and explainable. Only **verified** normalized source is scanned;
bytecode-only contracts are skipped (regex over bytecode is meaningless).

Incremental mode reuses results: a contract whose normalized source is unchanged
since the latest prior scan with the *same* pattern set is not re-run — its
findings are copied forward. If nothing changed, an incremental scan re-runs the
engine on **zero** contracts.
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
    rescanned: int = 0
    reused: int = 0


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


def _baseline_scan(conn: sqlite3.Connection, psh: str, before_id: int) -> int | None:
    row = conn.execute(
        "SELECT id FROM scans WHERE pattern_set_hash = ? AND id < ? "
        "ORDER BY id DESC LIMIT 1",
        (psh, before_id),
    ).fetchone()
    return row[0] if row else None


def _copy_findings(conn: sqlite3.Connection, src_scan: int, dst_scan: int, contract_id: int) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO findings "
        "(scan_id, contract_id, pattern_id, severity, confidence, line, snippet, evidence) "
        "SELECT ?, contract_id, pattern_id, severity, confidence, line, snippet, evidence "
        "FROM findings WHERE scan_id = ? AND contract_id = ?",
        (dst_scan, src_scan, contract_id),
    )
    return cur.rowcount


def run_scan(
    conn: sqlite3.Connection,
    patterns: list[Pattern],
    *,
    min_confidence: float = 0.0,
    incremental: bool = False,
) -> ScanStats:
    psh = pattern_set_hash(patterns)
    with conn:
        _snapshot_patterns(conn, patterns)
        cur = conn.execute(
            "INSERT INTO scans (started_at, pattern_set_hash, engine) VALUES (?, ?, ?)",
            (_now(), psh, "python"),
        )
        scan_id = int(cur.lastrowid)
        baseline = _baseline_scan(conn, psh, scan_id) if incremental else None

        rows = conn.execute(
            "SELECT c.id, c.source_hash, s.content "
            "FROM contracts c JOIN sources s "
            "  ON s.contract_id = c.id AND s.kind = 'normalized'"
        ).fetchall()

        contracts = rescanned = reused = total = 0
        for contract_id, source_hash, content in rows:
            contracts += 1
            unchanged = False
            if baseline is not None:
                prior = conn.execute(
                    "SELECT source_hash FROM scan_contracts "
                    "WHERE scan_id = ? AND contract_id = ?",
                    (baseline, contract_id),
                ).fetchone()
                unchanged = prior is not None and prior[0] == source_hash

            if unchanged:
                total += _copy_findings(conn, baseline, scan_id, contract_id)
                reused += 1
            else:
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
                rescanned += 1

            conn.execute(
                "INSERT OR REPLACE INTO scan_contracts "
                "(scan_id, contract_id, source_hash, rescanned) VALUES (?, ?, ?, ?)",
                (scan_id, contract_id, source_hash, 0 if unchanged else 1),
            )

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
        scan_id=scan_id, contracts_scanned=contracts, findings=total,
        by_severity=by_sev, rescanned=rescanned, reused=reused,
    )
