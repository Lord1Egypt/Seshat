"""Source adapters — get contracts into the archive, cleanly.

Each importer flattens/normalizes its input and stores one contract per
deployment (or per local file), excluding vendored dependencies. All importers
are deterministic and idempotent (re-ingesting adds no duplicate rows).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import explorer, normalize
from .models import Contract
from .store import IngestResult, store_contract

# Directories never walked for project ingestion (deps + build artifacts).
_SKIP_DIRS = {
    "node_modules",
    "lib",
    "out",
    "cache",
    "artifacts",
    "build",
    ".git",
    "typechain",
    "typechain-types",
    "coverage",
}


def ingest_solidity_text(
    conn: sqlite3.Connection,
    text: str,
    *,
    chain: str | None = None,
    address: str | None = None,
    name: str | None = None,
    origin: str = "local",
    path: str | None = None,
) -> IngestResult:
    """Ingest one source payload (flat Solidity or Standard-JSON)."""
    raw, norm = normalize.normalize_input(text)
    contract = Contract(
        chain_key=chain,
        address=address,
        name=(name or normalize.guess_contract_name(raw))[: normalize.MAX_IDENT],
        source_hash=normalize.source_hash(norm.content),
        has_verified_source=1,
        origin=origin,
    )
    return store_contract(
        conn,
        contract,
        raw=raw,
        normalized=norm.content,
        normalized_lines=norm.lines,
        source_path=path,
    )


def ingest_solidity_file(
    conn: sqlite3.Connection,
    path: str | Path,
    *,
    chain: str | None = None,
    address: str | None = None,
    name: str | None = None,
    origin: str = "local",
) -> IngestResult:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return ingest_solidity_text(
        conn, text, chain=chain, address=address, name=name, origin=origin,
        path=str(p),
    )


def ingest_standard_json(
    conn: sqlite3.Connection,
    path_or_text: str | Path,
    *,
    chain: str | None = None,
    address: str | None = None,
    name: str | None = None,
    origin: str = "standard_json",
) -> IngestResult:
    """Ingest a Standard-JSON file path or raw JSON/Solidity text."""
    p = Path(path_or_text) if not _looks_like_json(str(path_or_text)) else None
    text = p.read_text(encoding="utf-8", errors="replace") if p and p.exists() \
        else str(path_or_text)
    return ingest_solidity_text(
        conn, text, chain=chain, address=address, name=name, origin=origin,
        path=str(p) if p else None,
    )


def ingest_project(
    conn: sqlite3.Connection,
    root: str | Path,
    *,
    chain: str | None = None,
    origin: str | None = None,
) -> list[IngestResult]:
    """Ingest a Foundry/Hardhat project tree.

    Walks the tree, skipping dependency/build dirs, and ingests every project
    ``.sol`` as its own contract. Dependency files are excluded from scope.
    """
    root = Path(root)
    detected = origin or _detect_project_kind(root)
    results: list[IngestResult] = []
    for sol in _iter_project_sol(root):
        rel = sol.relative_to(root).as_posix()
        if normalize.is_dependency_path(rel):
            continue
        results.append(
            ingest_solidity_file(conn, sol, chain=chain, origin=detected)
        )
    return results


def ingest_bytecode(
    conn: sqlite3.Connection,
    bytecode: str,
    *,
    chain: str | None = None,
    address: str | None = None,
    name: str | None = None,
    origin: str = "bytecode",
) -> IngestResult:
    """Ingest raw bytecode — marked unverified (``has_verified_source = 0``)."""
    code = bytecode.strip()
    contract = Contract(
        chain_key=chain,
        address=address,
        name=name[: normalize.MAX_IDENT] if name else None,
        source_hash=normalize.source_hash(code),
        has_verified_source=0,
        origin=origin,
    )
    return store_contract(
        conn, contract, normalized=code, normalized_lines=1, source_kind="bytecode",
    )


def ingest_address(
    conn: sqlite3.Connection,
    chain: str,
    address: str,
    *,
    online: bool = False,
    api_key: str | None = None,
    cache_dir: str | Path = explorer.DEFAULT_CACHE_DIR,
    force: bool = False,
) -> IngestResult:
    """Fetch verified source for an address (cached) and ingest it.

    Falls back to an unverified placeholder if the explorer has no source.
    """
    result = explorer.fetch_sourcecode(
        chain, address, api_key=api_key, cache_dir=cache_dir,
        online=online, force=force,
    )
    if not explorer.is_verified(result):
        return ingest_bytecode(
            conn, result.get("Bytecode", "") or "0x", chain=chain,
            address=address, origin="explorer",
        )
    source, name = explorer.extract_source_payload(result)
    return ingest_solidity_text(
        conn, source, chain=chain, address=address, name=name, origin="explorer",
    )


def ingest_maateye_registry(
    conn: sqlite3.Connection, path: str | Path
) -> list[IngestResult]:
    """Import a MaatEye-style registry: a JSON array or JSONL of records.

    Each record is lenient about key casing and carries at least an address and
    one of: ``source``/``source_code``/``sourceCode``/``standard_json`` (verified
    source) or ``bytecode`` (unverified).
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    records = _parse_registry(text)
    results: list[IngestResult] = []
    for rec in records:
        chain = _first(rec, "chain", "chain_key", "chainKey", "network")
        address = _first(rec, "address", "contract", "contract_address")
        name = _first(rec, "name", "contract_name", "contractName", "ContractName")
        source = _first(
            rec, "source", "source_code", "sourceCode", "SourceCode",
            "standard_json", "standardJson",
        )
        if source:
            results.append(
                ingest_solidity_text(
                    conn, source if isinstance(source, str) else json.dumps(source),
                    chain=chain, address=address, name=name, origin="maateye",
                )
            )
        else:
            bytecode = _first(rec, "bytecode", "Bytecode", "code")
            if bytecode:
                results.append(
                    ingest_bytecode(
                        conn, str(bytecode), chain=chain, address=address,
                        name=name, origin="maateye",
                    )
                )
    return results


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _looks_like_json(s: str) -> bool:
    s = s.lstrip()
    return s.startswith("{") or s.startswith("[")


def _detect_project_kind(root: Path) -> str:
    if (root / "foundry.toml").exists():
        return "foundry"
    if any((root / f).exists() for f in (
        "hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs"
    )):
        return "hardhat"
    return "project"


def _iter_project_sol(root: Path):
    for path in sorted(root.rglob("*.sol")):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        yield path


def _parse_registry(text: str) -> list[dict]:
    s = text.strip()
    if not s:
        return []
    try:
        obj = json.loads(s)
        if isinstance(obj, list):
            return [r for r in obj if isinstance(r, dict)]
        if isinstance(obj, dict):
            # {"contracts": [...]} or a single record
            inner = obj.get("contracts") or obj.get("records")
            if isinstance(inner, list):
                return [r for r in inner if isinstance(r, dict)]
            return [obj]
    except (json.JSONDecodeError, ValueError):
        pass
    # JSONL fallback
    out: list[dict] = []
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if isinstance(rec, dict):
                out.append(rec)
        except (json.JSONDecodeError, ValueError):
            continue
    return out


def _first(rec: dict, *keys: str):
    for k in keys:
        if k in rec and rec[k]:
            return rec[k]
    return None
