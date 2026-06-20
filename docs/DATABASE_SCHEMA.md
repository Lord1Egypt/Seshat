# 🗄️ Seshat — Database Schema (draft v1)

The local archive is a single SQLite file, `seshat.db`. This schema was **finalized in Phase 0** (migration `0001_initial_schema`) and is evolved via migrations (every change ships with a migration + test).

## Overview

```
chains ──< contracts ──< sources
                │
                └──< findings >── patterns
                          │
                          └── scans
```

- A **contract** belongs to a **chain** and has one or more **sources** (verified source, bytecode, or a normalized blob).
- A **scan** is one run of the engine (with a pattern-set hash).
- A **finding** links a **contract**, a **pattern**, and the **scan** that produced it.

## Tables

### `chains`
| column | type | notes |
|---|---|---|
| `key` | TEXT PK | `ethereum`, `base`, … |
| `name` | TEXT | display name |
| `chain_id` | INTEGER | EVM chain id |

### `contracts`
| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | |
| `chain_key` | TEXT FK→chains | nullable for local-only contracts |
| `address` | TEXT | lowercased; nullable for local files |
| `name` | TEXT | contract name if known |
| `source_hash` | TEXT | hash of normalized source (dedup key) |
| `has_verified_source` | INTEGER | 1 = real source analyzed, 0 = bytecode/placeholder |
| `first_seen` | TEXT | ISO timestamp |
| `origin` | TEXT | `local` / `foundry` / `explorer` / `maateye` / … |

*Unique:* `(chain_key, address)` — the hard dedup key for on-chain contracts. NULLs are distinct in SQLite, so any number of local-only files (`chain_key`/`address` NULL) coexist.

> **Phase 0 finalize note:** `source_hash` is a **non-unique index**, *not* a global unique constraint. The same source legitimately deploys to many chains (e.g. USDC on Ethereum and Polygon); a global `UNIQUE(source_hash)` would reject the second one. Re-ingest dedup uses `source_hash` for lookup *within* `(chain, address)` scope (Phase 1).

### `sources`
| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | |
| `contract_id` | INTEGER FK→contracts | |
| `kind` | TEXT | `raw` / `standard_json` / `normalized` / `bytecode` |
| `path` | TEXT | original file path, if any |
| `content` | TEXT | source text (normalized for the analyzed blob) |
| `lines` | INTEGER | line count (for location math) |

### `patterns`
| column | type | notes |
|---|---|---|
| `id` | TEXT PK | `P001`, … |
| `name` | TEXT | |
| `severity` | TEXT | `critical`/`high`/`medium`/`low`/`info` |
| `category` | TEXT | taxonomy bucket |
| `confidence` | REAL | default detector confidence 0–1 |
| `swc` | TEXT | SWC id(s) |
| `cwe` | TEXT | CWE id(s) |
| `version` | TEXT | pattern revision |

### `scans`
| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | the `scan_id` |
| `started_at` | TEXT | ISO timestamp |
| `finished_at` | TEXT | |
| `pattern_set_hash` | TEXT | hash of the active pattern set (reproducibility) |
| `engine` | TEXT | `python` / `rust` |
| `contracts_scanned` | INTEGER | |

### `findings`
| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | |
| `scan_id` | INTEGER FK→scans | |
| `contract_id` | INTEGER FK→contracts | |
| `pattern_id` | TEXT FK→patterns | |
| `severity` | TEXT | snapshot at scan time |
| `confidence` | REAL | detector confidence for this hit |
| `line` | INTEGER | 1-based line in normalized source |
| `snippet` | TEXT | short context |
| `evidence` | TEXT | e.g. "matched at line N" |

*Unique (dedup):* `(scan_id, contract_id, pattern_id, line)`.

### `scan_contracts` (migration 0002)
Per-scan provenance — which contracts a scan covered and the source hash at that time. Powers **incremental re-scan** (skip unchanged contracts) and the "touched zero contracts" guarantee.

| column | type | notes |
|---|---|---|
| `scan_id` | INTEGER FK→scans | |
| `contract_id` | INTEGER FK→contracts | |
| `source_hash` | TEXT | normalized source hash at scan time |
| `rescanned` | INTEGER | 1 = engine re-ran, 0 = findings copied forward |

*Primary key:* `(scan_id, contract_id)`.

### `schema_version`
| column | type | notes |
|---|---|---|
| `version` | INTEGER | current migration level |

## Example queries (offline)

```sql
-- Severity breakdown for the latest scan
SELECT severity, COUNT(*) AS n
FROM findings
WHERE scan_id = (SELECT MAX(id) FROM scans)
GROUP BY severity ORDER BY n DESC;

-- Contracts flagged by a specific pattern
SELECT c.chain_key, c.address, f.line
FROM findings f JOIN contracts c ON c.id = f.contract_id
WHERE f.pattern_id = 'P017';

-- How many contracts actually had verified source?
SELECT COUNT(*) FROM contracts WHERE has_verified_source = 1;
```

## Diffing (Phase 3)

`seshat diff A B` computes, over the `findings` of two `scan_id`s keyed by `(contract_id, pattern_id, line)`:
- **new** — in B, not in A
- **fixed** — in A, not in B
- **regressed** — re-appeared after being fixed in an intermediate scan

> Schema is intentionally small and boring — boring schemas age well. Every future change is a migration with a test.
