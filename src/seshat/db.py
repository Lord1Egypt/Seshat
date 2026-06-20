"""Thin SQLite access layer + migration runner for the Seshat archive.

Everything here is standard-library only (``sqlite3``). A connection always has
foreign keys enforced and rows accessible by column name.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .migrations import MIGRATIONS


def connect(path: str | Path = "seshat.db") -> sqlite3.Connection:
    """Open (creating if needed) a Seshat DB with sane pragmas.

    ``:memory:`` is accepted for tests.
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
    )
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (0)")


def current_version(conn: sqlite3.Connection) -> int:
    """Return the applied schema version (0 if none / uninitialized)."""
    try:
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row[0]) if row is not None else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply any pending migrations in order. Idempotent.

    Returns the schema version after migrating.
    """
    _ensure_version_table(conn)
    applied = current_version(conn)
    for mig in MIGRATIONS:
        if mig.version <= applied:
            continue
        with conn:  # one transaction per migration; rolls back on error
            conn.executescript(mig.sql)
            conn.execute("UPDATE schema_version SET version = ?", (mig.version,))
        applied = mig.version
    return applied


def init_db(path: str | Path = "seshat.db") -> tuple[sqlite3.Connection, int, bool]:
    """Create (if needed) and migrate a DB at ``path``.

    Returns ``(connection, version, created)`` where ``created`` is True only
    when the file did not exist beforehand. Re-running is a no-op (idempotent).
    """
    created = False
    if str(path) != ":memory:":
        p = Path(path)
        created = not p.exists()
        p.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    version = migrate(conn)
    return conn, version, created
