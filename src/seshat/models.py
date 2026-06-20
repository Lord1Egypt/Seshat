"""Core data model — dataclasses mirroring the SQLite schema.

These are plain value objects. They carry no DB logic; the access layer in
``db.py`` (and ingestion/scan stages in later phases) maps rows to/from them.
Field names and order match docs/DATABASE_SCHEMA.md and migration 0001.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(slots=True)
class Chain:
    key: str
    name: str | None = None
    chain_id: int | None = None


@dataclass(slots=True)
class Contract:
    id: int | None = None
    chain_key: str | None = None
    address: str | None = None
    name: str | None = None
    source_hash: str | None = None
    has_verified_source: int = 0
    first_seen: str | None = None
    origin: str | None = None


@dataclass(slots=True)
class Source:
    id: int | None = None
    contract_id: int | None = None
    kind: str = "raw"  # raw | standard_json | normalized | bytecode
    path: str | None = None
    content: str | None = None
    lines: int | None = None


@dataclass(slots=True)
class Pattern:
    id: str  # "P001", ...
    name: str | None = None
    severity: str | None = None  # critical | high | medium | low | info
    category: str | None = None
    confidence: float | None = None
    swc: str | None = None
    cwe: str | None = None
    version: str | None = None


@dataclass(slots=True)
class Scan:
    id: int | None = None
    started_at: str | None = None
    finished_at: str | None = None
    pattern_set_hash: str | None = None
    engine: str | None = None  # python | rust
    contracts_scanned: int | None = None


@dataclass(slots=True)
class Finding:
    id: int | None = None
    scan_id: int | None = None
    contract_id: int | None = None
    pattern_id: str | None = None
    severity: str | None = None
    confidence: float | None = None
    line: int | None = None
    snippet: str | None = None
    evidence: str | None = None


def _from_row(cls, row: sqlite3.Row):
    """Build a dataclass from a sqlite3.Row, ignoring unknown columns."""
    fields = {f for f in cls.__dataclass_fields__}
    data = {k: row[k] for k in row.keys() if k in fields}
    return cls(**data)
