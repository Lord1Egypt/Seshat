"""Diff two scans into new / fixed / regressed findings.

A finding's identity is ``(contract_id, pattern_id, line)``. Given scans A→B:

- **new** — in B, not in A
- **fixed** — in A, not in B
- **regressed** — present in both A and B, but absent in at least one scan
  *between* them (it was fixed and came back)
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

FindingKey = tuple[int, str, int]


@dataclass
class DiffResult:
    scan_a: int
    scan_b: int
    new: list[FindingKey] = field(default_factory=list)
    fixed: list[FindingKey] = field(default_factory=list)
    regressed: list[FindingKey] = field(default_factory=list)


def _findings(conn: sqlite3.Connection, scan_id: int) -> set[FindingKey]:
    return {
        (r[0], r[1], r[2])
        for r in conn.execute(
            "SELECT contract_id, pattern_id, line FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
    }


def diff_scans(conn: sqlite3.Connection, scan_a: int, scan_b: int) -> DiffResult:
    a = _findings(conn, scan_a)
    b = _findings(conn, scan_b)

    lo, hi = (scan_a, scan_b) if scan_a < scan_b else (scan_b, scan_a)
    intermediates = [
        r[0] for r in conn.execute(
            "SELECT id FROM scans WHERE id > ? AND id < ? ORDER BY id", (lo, hi)
        )
    ]
    inter_sets = [_findings(conn, sid) for sid in intermediates]

    persistent = a & b
    regressed = {
        key for key in persistent
        if any(key not in s for s in inter_sets)
    }

    return DiffResult(
        scan_a=scan_a,
        scan_b=scan_b,
        new=sorted(b - a),
        fixed=sorted(a - b),
        regressed=sorted(regressed),
    )
