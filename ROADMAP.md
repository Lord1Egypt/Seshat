# 🗺️ Seshat — Roadmap

Seshat is built in **eight focused phases**. Each phase has a clear theme, concrete deliverables, and **acceptance criteria** (a "definition of done") so progress is unambiguous. Task-level checklists live in **[CHECKLIST.md](CHECKLIST.md)**.

> **Principle:** every phase ends *green* — tests pass, docs updated, demo works — before the next begins. No phase depends on the cloud.

---

## 🧭 Guiding constraints (apply to every phase)

- **Offline-first** — nothing in the core path requires network. Address-fetching is the only optional, explicit online step.
- **Low/zero dependency** — Python **standard library + `sqlite3`** for the core. Every added dependency must justify itself.
- **Reproducible** — same inputs + same pattern set ⇒ byte-identical findings.
- **Honest** — findings are *review flags* with confidence; severities are triage priority.
- **Tested** — every pattern has labeled fixtures; every module has unit tests; CI runs offline.
- **Filesystem-safe** — identifiers capped at 80 chars; large directories partitioned by first char (no `OSError 36`).

---

## Phase 0 — 🏛️ Foundation & Schema
*Lay the cornerstone.*

**Deliverables**
- Repo scaffold, `MIT` license, `CLAUDE.md`, offline CI (lint + unit tests).
- Final **SQLite schema** (`contracts`, `sources`, `chains`, `patterns`, `scans`, `findings`) + a tiny **migration** system.
- Core data model (dataclasses) and a thin DB access layer.
- `seshat init` — create an empty, versioned `seshat.db`.

**Acceptance criteria**
- `seshat init` creates a schema-versioned DB; re-running is idempotent.
- Schema documented in [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) and enforced by a migration test.

---

## Phase 1 — 📥 Ingestion Engine
*Get contracts into the archive, cleanly.*

**Deliverables**
- Importers: **local `.sol`**, **Solidity Standard-JSON**, **Foundry/Hardhat** project trees, **address + explorer fetch** (cached), **raw bytecode**, **MaatEye registry import**.
- **Normalization** (ported & hardened from MaatEye): flatten Standard-JSON incl. `{{…}}`, drop dependency files, strip comments/strings (preserving line numbers).
- **Content-addressed dedup** — a contract is keyed by `(chain, address)` and/or source hash; re-ingesting is a no-op.

**Acceptance criteria**
- A Foundry project ingests into the DB with one command; dependency files are excluded from analysis scope.
- Re-ingesting the same input adds zero duplicate rows.
- An offline address fetch is cached and never re-hits the network unless forced.

---

## Phase 2 — 🎯 Pattern Engine (100+)
*The heart: detect, honestly.*

**Deliverables**
- **Matcher kinds:** regex, function-signature, lightweight AST/structural, and semantic heuristics.
- **Pattern format** (YAML): id, name, severity, category, **confidence**, **SWC/CWE mapping**, detectors, recommendation.
- **Pattern SDK** + validator + **labeled fixture harness** (each pattern: ≥1 true-positive, ≥1 clean fixture).
- **Confidence threshold** and **per-(pattern,line) dedup** in the core.
- Grow the catalog to **100+ patterns** (migrate MaatEye's 50, expand to full SWC coverage + DeFi-specific classes).

**Acceptance criteria**
- 100+ patterns load and validate; each has passing TP + FP fixtures.
- A clean OpenZeppelin ERC-20 produces **zero critical** flags (false-positive guard).
- Findings are deduped and confidence-thresholded; a documented baseline corpus is reproducible.

---

## Phase 3 — 🗄️ Local Database & Query
*Make the archive answer questions.*

**Deliverables**
- Persist scans + findings with full history (`scan_id`, timestamps, pattern-set version).
- `seshat query` — raw SQL **and** a set of canned queries (top patterns, by severity, by chain).
- **Full-text search** over stored source.
- **Scan diff** — `seshat diff A B`: new / fixed / regressed findings.
- **Incremental re-scan** — only re-scan contracts whose source or pattern-set changed.

**Acceptance criteria**
- Two scans of the same corpus can be diffed into new/fixed/regressed sets.
- Re-scan after a no-op change touches zero contracts.

---

## Phase 4 — 📤 Reporting & UX
*Make it a joy to read.*

**Deliverables**
- Exporters: **JSON**, **CSV**, **SARIF** (VS Code / CI annotations), **Markdown**, self-contained **HTML report**.
- A pretty CLI (and optional TUI) with a triage view.
- Honest framing surfaced everywhere (review-flag language, confidence, severity legend).

**Acceptance criteria**
- SARIF validates against the schema and renders in VS Code's Problems panel.
- The HTML report is a single offline file that opens with no server.

---

## Phase 5 — ⚡ Rust Performance Core
*Scale to large corpora.*

**Deliverables**
- A Rust scanning engine (parallel, same pattern format) behind a stable interface; Python stays the ergonomic front-end.
- Benchmarks vs the pure-Python engine; large-DB handling; directory partitioning for big imports.

**Acceptance criteria**
- Rust core produces **identical findings** to the Python engine on the baseline corpus.
- Measurable speedup on a 10k-contract corpus, documented.

---

## Phase 6 — 📦 Distribution
*Make it trivially downloadable.*

**Deliverables**
- Packaging: **PyPI** (`pipx install seshat`), **crates.io**, and **standalone binaries** (no runtime).
- Offline pattern bundle shipped with the package (scan local files with zero network).
- **Animated VHS terminal demo GIF** in the README (house standard).
- Docs site.

**Acceptance criteria**
- `pipx install seshat && seshat scan ./project` works on a clean machine **with networking disabled**.
- README shows a real terminal demo.

---

## Phase 7 — 🧠 Ecosystem & Polish
*Open it up.*

**Deliverables**
- **Plugin system** for custom/community patterns.
- IDE integration via SARIF (and a possible LSP).
- Interop: import/export with MaatEye, Slither, and standard formats.
- A curated community pattern pack.

**Acceptance criteria**
- A third-party pattern can be dropped in and runs without touching core code.
- Round-trip import/export with at least one external tool.

---

## 📌 Versioning

- `v0.x` — pre-release; schema may change between minors (with migrations).
- `v1.0` — stable schema, 100+ validated patterns, all five exporters, distributable binaries, demo GIF. **This is "100% perfection."**

---

<div align="center">
<i>📜 Build the foundation true, and the house stands. — Seshat stretched the cord. 📜</i>
</div>
