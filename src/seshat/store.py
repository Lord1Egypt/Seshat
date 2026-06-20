"""Persistence helpers for ingestion — contract dedup + source storage.

Dedup contract:
- If ``(chain_key, address)`` are both known, that pair is the identity (a
  contract is one deployment on one chain). Enforced by a UNIQUE index too.
- Otherwise (local files, bytecode without an address) identity is the
  ``source_hash`` (content-addressed). Re-ingesting identical content is a no-op.

Either way, re-ingesting the same input adds **zero** duplicate rows.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .chains import ensure_chain
from .models import Contract, Source


@dataclass
class IngestResult:
    contract_id: int
    created: bool
    name: str | None
    chain_key: str | None
    address: str | None
    has_verified_source: int
    origin: str | None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _find_existing(conn: sqlite3.Connection, c: Contract) -> int | None:
    if c.chain_key and c.address:
        row = conn.execute(
            "SELECT id FROM contracts WHERE chain_key = ? AND address = ?",
            (c.chain_key, c.address),
        ).fetchone()
        return row[0] if row else None
    if c.source_hash:
        row = conn.execute(
            "SELECT id FROM contracts WHERE source_hash = ? "
            "AND chain_key IS NULL AND address IS NULL",
            (c.source_hash,),
        ).fetchone()
        return row[0] if row else None
    return None


def store_contract(
    conn: sqlite3.Connection,
    contract: Contract,
    *,
    raw: str | None = None,
    normalized: str | None = None,
    normalized_lines: int | None = None,
    source_kind: str = "normalized",
    source_path: str | None = None,
) -> IngestResult:
    """Insert a contract + its analyzed source, or return the existing row.

    Idempotent: a second call with the same identity makes no changes.
    """
    address = contract.address.lower() if contract.address else None
    contract.address = address
    if contract.chain_key:
        contract.chain_key = ensure_chain(conn, contract.chain_key)

    with conn:
        existing = _find_existing(conn, contract)
        if existing is not None:
            return IngestResult(
                contract_id=existing,
                created=False,
                name=contract.name,
                chain_key=contract.chain_key,
                address=address,
                has_verified_source=contract.has_verified_source,
                origin=contract.origin,
            )

        cur = conn.execute(
            "INSERT INTO contracts "
            "(chain_key, address, name, source_hash, has_verified_source, "
            " first_seen, origin) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                contract.chain_key,
                address,
                contract.name,
                contract.source_hash,
                contract.has_verified_source,
                contract.first_seen or _now(),
                contract.origin,
            ),
        )
        contract_id = int(cur.lastrowid)

        if normalized is not None:
            _add_source(
                conn,
                Source(
                    contract_id=contract_id,
                    kind=source_kind,
                    path=source_path,
                    content=normalized,
                    lines=normalized_lines,
                ),
            )
        if raw is not None:
            _add_source(
                conn,
                Source(
                    contract_id=contract_id,
                    kind="raw",
                    path=source_path,
                    content=raw,
                    lines=(raw.count("\n") + 1) if raw else 0,
                ),
            )

    return IngestResult(
        contract_id=contract_id,
        created=True,
        name=contract.name,
        chain_key=contract.chain_key,
        address=address,
        has_verified_source=contract.has_verified_source,
        origin=contract.origin,
    )


def _add_source(conn: sqlite3.Connection, source: Source) -> int:
    cur = conn.execute(
        "INSERT INTO sources (contract_id, kind, path, content, lines) "
        "VALUES (?, ?, ?, ?, ?)",
        (source.contract_id, source.kind, source.path, source.content, source.lines),
    )
    return int(cur.lastrowid)
