# 🏗️ Seshat — Architecture

A design document. Code follows the roadmap; this is the blueprint it builds to.

## Design goals

1. **Offline-first** — the scan path never needs the network.
2. **Local source of truth** — one SQLite file (`seshat.db`) holds everything.
3. **Reproducible** — deterministic ingestion + matching.
4. **Composable** — ingest, scan, query, and report are independent stages over the DB.
5. **Honest** — confidence and review-flag semantics are first-class, not cosmetic.

## The pipeline

```
                 ┌──────────────┐
   sources ────▶ │  INGEST      │ normalize → dedup → store source
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │  seshat.db   │ ◀── single local SQLite file
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │  SCAN        │ patterns → matchers → threshold → dedup
                 └──────┬───────┘ writes findings (linked to a scan_id)
                        ▼
        ┌───────────────┴───────────────┐
        ▼                               ▼
  ┌──────────┐                   ┌──────────────┐
  │  QUERY   │ SQL · diff        │  REPORT      │ JSON/CSV/SARIF/MD/HTML
  └──────────┘                   └──────────────┘
```

Each stage reads/writes the DB and nothing else, so any stage can run alone (`ingest` today, `scan` tomorrow, `report` next week) and results are stable.

## Components

### 1. Ingestion (`seshat ingest`)
- **Source adapters** for: local `.sol`, Standard-JSON, Foundry/Hardhat trees, address+explorer (cached), bytecode, MaatEye registry.
- **Normalizer** (ported from MaatEye, hardened): flatten Standard-JSON incl. Etherscan `{{…}}`, drop dependency files, strip comments/strings while preserving line numbers.
- **Dedup** by `(chain, address)` and source content hash. Re-ingesting is a no-op.

### 2. Pattern engine (`seshat scan`)
- Loads YAML patterns into memory; each has detectors of kind `regex | function_signature | ast | semantic`.
- Applies matchers to **normalized** source.
- **Confidence threshold** filters weak/informational detectors.
- **Dedup per `(pattern, line)`**.
- Writes a `scan` row (timestamp + pattern-set hash) and one `finding` per surviving match.

### 3. Query & diff (`seshat query` / `seshat diff`)
- Raw SQL over the DB, plus canned queries and full-text source search.
- Diff compares two `scan_id`s into **new / fixed / regressed** sets.
- Incremental re-scan skips contracts whose source hash and pattern-set are unchanged.

### 4. Reporting (`seshat report`)
- Exporters render a scan into JSON, CSV, **SARIF**, Markdown, or a single self-contained **HTML** file.
- All outputs carry review-flag framing, confidence, and a severity legend.

### 5. Optional Rust core (Phase 5)
- A drop-in scanning engine reading the **same** pattern YAML, behind a stable boundary. Must produce **identical findings** to the Python engine on the baseline corpus; it only adds speed.

## Determinism & honesty contracts
- **Determinism:** ingestion normalization and matcher iteration order are fixed; a scan records the exact pattern-set hash so results are explainable and reproducible.
- **Honesty:** a "finding" is a *review flag*. The schema stores `confidence` and `severity` separately; reports never imply confirmed exploitability. Only verified source is marked `analyzed`.

## Why SQLite
- Zero-config, single-file, in the Python stdlib (`sqlite3`) — perfectly offline.
- Real SQL for ad-hoc analysis; trivial to back up, share, or delete.
- Scales comfortably to hundreds of thousands of contracts on a laptop.

See **[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)** for tables and **[PATTERNS.md](PATTERNS.md)** for the detection taxonomy.
