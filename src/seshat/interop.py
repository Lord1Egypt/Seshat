"""Interoperability — import findings from external tools into the archive.

Seshat already *exports* SARIF/JSON (see :mod:`seshat.report`). This adds the
other direction: pull results from SARIF (the IDE/CI standard) or Slither's JSON
into a scan, so an archive can hold and diff findings from multiple tools — and
so a Seshat → SARIF → Seshat round-trip preserves findings.

Imported contracts are keyed by their artifact URI (origin ``imported``) so the
same external file maps to the same contract row on re-import.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .normalize import source_hash

# SARIF level → our severity (export collapses critical/high → error, so import
# cannot recover the split; high is the safe choice).
_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_SLITHER_SEV = {
    "High": "high", "Medium": "medium", "Low": "low",
    "Informational": "info", "Optimization": "info",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _imported_contract(conn: sqlite3.Connection, uri: str) -> int:
    h = source_hash(uri)
    row = conn.execute(
        "SELECT id FROM contracts WHERE source_hash = ? AND origin = 'imported'",
        (h,),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO contracts (name, source_hash, has_verified_source, first_seen, origin) "
        "VALUES (?, ?, 0, ?, 'imported')",
        (uri[-80:], h, _now()),
    )
    return int(cur.lastrowid)


def _ensure_pattern(conn: sqlite3.Connection, pid: str, name: str, severity: str,
                    category: str = "IMPORTED") -> None:
    conn.execute(
        "INSERT OR IGNORE INTO patterns (id, name, severity, category, confidence, version) "
        "VALUES (?, ?, ?, ?, 0.0, 'imported')",
        (pid, name, severity, category),
    )


def _new_scan(conn: sqlite3.Connection, engine: str) -> int:
    cur = conn.execute(
        "INSERT INTO scans (started_at, finished_at, engine, pattern_set_hash) "
        "VALUES (?, ?, ?, 'imported')",
        (_now(), _now(), engine),
    )
    return int(cur.lastrowid)


def import_sarif(conn: sqlite3.Connection, path: str | Path) -> int:
    """Import a SARIF 2.1.0 file into a new scan. Returns the scan id."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    with conn:
        scan_id = _new_scan(conn, "imported-sarif")
        count = 0
        for run in data.get("runs", []):
            rules = {
                r.get("id"): r
                for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for res in run.get("results", []):
                rule_id = res.get("ruleId") or "UNKNOWN"
                level = res.get("level", "warning")
                severity = _LEVEL_SEV.get(level, "medium")
                rule = rules.get(rule_id, {})
                name = rule.get("shortDescription", {}).get("text", rule_id)
                category = rule.get("properties", {}).get("category") or "IMPORTED"
                _ensure_pattern(conn, rule_id, name, severity, category or "IMPORTED")

                msg = res.get("message", {}).get("text", "")
                for loc in res.get("locations", []) or [{}]:
                    phys = loc.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "unknown")
                    line = phys.get("region", {}).get("startLine", 0) or 0
                    cid = _imported_contract(conn, uri)
                    conn.execute(
                        "INSERT OR IGNORE INTO findings (scan_id, contract_id, pattern_id, "
                        "severity, confidence, line, snippet, evidence) "
                        "VALUES (?, ?, ?, ?, 0.0, ?, '', ?)",
                        (scan_id, cid, rule_id, severity, line, msg),
                    )
                    count += 1
        conn.execute(
            "UPDATE scans SET contracts_scanned = "
            "(SELECT COUNT(DISTINCT contract_id) FROM findings WHERE scan_id = ?) "
            "WHERE id = ?", (scan_id, scan_id),
        )
    return scan_id


def import_slither(conn: sqlite3.Connection, path: str | Path) -> int:
    """Import a Slither ``--json`` report into a new scan. Returns the scan id."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    detectors = (data.get("results") or {}).get("detectors", [])
    with conn:
        scan_id = _new_scan(conn, "imported-slither")
        for det in detectors:
            check = det.get("check", "unknown")
            pid = "SL-" + check
            severity = _SLITHER_SEV.get(det.get("impact", ""), "medium")
            _ensure_pattern(conn, pid, check, severity, "SLITHER")
            msg = (det.get("description") or check).strip().splitlines()[0][:200]
            for el in det.get("elements", []) or []:
                sm = el.get("source_mapping", {}) or {}
                uri = sm.get("filename_relative") or sm.get("filename_short") or "unknown"
                lines = sm.get("lines") or [0]
                cid = _imported_contract(conn, uri)
                conn.execute(
                    "INSERT OR IGNORE INTO findings (scan_id, contract_id, pattern_id, "
                    "severity, confidence, line, snippet, evidence) "
                    "VALUES (?, ?, ?, ?, 0.0, ?, '', ?)",
                    (scan_id, cid, pid, severity, lines[0], msg),
                )
        conn.execute(
            "UPDATE scans SET contracts_scanned = "
            "(SELECT COUNT(DISTINCT contract_id) FROM findings WHERE scan_id = ?) "
            "WHERE id = ?", (scan_id, scan_id),
        )
    return scan_id


IMPORTERS = {"sarif": import_sarif, "slither": import_slither}
