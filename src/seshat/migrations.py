"""Schema migrations for the Seshat local archive.

Each migration is a ``(version, name, sql)`` triple, applied in strictly
increasing order. The applied level is tracked in the ``schema_version`` table.
Migrations must be **append-only**: never edit a shipped migration, add a new one.

The SQL here is the *finalized* Phase 0 schema. See docs/DATABASE_SCHEMA.md.
"""

from __future__ import annotations

from typing import NamedTuple


class Migration(NamedTuple):
    version: int
    name: str
    sql: str


_M0001_INITIAL = """
CREATE TABLE chains (
    key      TEXT PRIMARY KEY,
    name     TEXT,
    chain_id INTEGER
);

CREATE TABLE contracts (
    id                  INTEGER PRIMARY KEY,
    chain_key           TEXT    REFERENCES chains(key),
    address             TEXT,
    name                TEXT,
    source_hash         TEXT,
    has_verified_source INTEGER NOT NULL DEFAULT 0,
    first_seen          TEXT,
    origin              TEXT
);
-- Hard dedup key for on-chain contracts. NULLs are distinct in SQLite, so any
-- number of local-only files (chain_key/address NULL) may coexist.
CREATE UNIQUE INDEX ux_contracts_chain_address ON contracts(chain_key, address);
-- source_hash is a NON-unique lookup index, NOT a global constraint: the same
-- source legitimately deploys to many chains (e.g. USDC on Ethereum + Polygon).
CREATE INDEX ix_contracts_source_hash ON contracts(source_hash);

CREATE TABLE sources (
    id          INTEGER PRIMARY KEY,
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    kind        TEXT    NOT NULL,
    path        TEXT,
    content     TEXT,
    lines       INTEGER
);
CREATE INDEX ix_sources_contract ON sources(contract_id);

CREATE TABLE patterns (
    id         TEXT PRIMARY KEY,
    name       TEXT,
    severity   TEXT,
    category   TEXT,
    confidence REAL,
    swc        TEXT,
    cwe        TEXT,
    version    TEXT
);

CREATE TABLE scans (
    id                INTEGER PRIMARY KEY,
    started_at        TEXT,
    finished_at       TEXT,
    pattern_set_hash  TEXT,
    engine            TEXT,
    contracts_scanned INTEGER
);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    pattern_id  TEXT    NOT NULL REFERENCES patterns(id),
    severity    TEXT,
    confidence  REAL,
    line        INTEGER,
    snippet     TEXT,
    evidence    TEXT
);
-- Per-(scan, contract, pattern, line) dedup: never count one line twice.
CREATE UNIQUE INDEX ux_findings_dedup ON findings(scan_id, contract_id, pattern_id, line);
CREATE INDEX ix_findings_scan     ON findings(scan_id);
CREATE INDEX ix_findings_contract ON findings(contract_id);
CREATE INDEX ix_findings_pattern  ON findings(pattern_id);
"""


# Append-only. Add new migrations below with the next version number.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "initial_schema", _M0001_INITIAL),
)


def latest_version() -> int:
    """Highest migration version defined."""
    return MIGRATIONS[-1].version if MIGRATIONS else 0
