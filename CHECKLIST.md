# ✅ Seshat — Build Checklist

Per-phase, task-level tracking. Check items off as they land. Each phase must be **fully green** (tests + docs + demo) before the next starts. See **[ROADMAP.md](ROADMAP.md)** for themes and acceptance criteria.

> Legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## Phase 0 — 🏛️ Foundation & Schema ✅
- [x] Repo scaffold (`src/`, `tests/`, `patterns/`, `docs/`)
- [x] `LICENSE` (MIT), `CLAUDE.md`, `.gitignore`, `pyproject.toml`
- [x] Offline CI workflow (lint + unit tests, no network)
- [x] SQLite schema v1 (`chains`, `contracts`, `sources`, `patterns`, `scans`, `findings`)
- [x] Migration system + schema-version table
- [x] Core dataclasses + thin DB access layer
- [x] `seshat init` command (idempotent)
- [x] Schema test enforces migrations apply cleanly

## Phase 1 — 📥 Ingestion Engine ✅
- [x] Importer: local `.sol` files
- [x] Importer: Solidity Standard-JSON
- [x] Importer: Foundry / Hardhat project trees
- [x] Importer: address + explorer fetch (cached, opt-in online)
- [x] Importer: raw bytecode (mark unverified)
- [x] Importer: MaatEye registry
- [x] Normalizer: flatten Standard-JSON incl. `{{…}}`
- [x] Normalizer: drop dependency files (OZ, node_modules, lib/, …)
- [x] Normalizer: strip comments/strings, preserve line numbers
- [x] Content-addressed dedup (no duplicate rows on re-ingest)
- [x] Tests for every importer + normalizer

## Phase 2 — 🎯 Pattern Engine (100+) ✅
- [x] Pattern YAML schema (id/name/severity/category/confidence/SWC/CWE/detectors)
- [x] Matcher: regex
- [x] Matcher: function-signature (brace-balanced function scope)
- [x] Matcher: lightweight AST / structural (scope + requires/forbids)
- [x] Matcher: semantic heuristic (requires/forbids composition)
- [x] Confidence threshold in core
- [x] Dedup per `(pattern, line)`
- [x] Pattern SDK + validator (`seshat patterns --validate`)
- [x] Labeled fixture harness (inline TP + FP per pattern)
- [x] Migrate MaatEye's 50 patterns (with their fixes baked in)
- [x] Expand to 100+ (103 patterns across all 12 categories)
- [x] Precision baseline: clean ERC-20 ⇒ 0 critical

## Phase 3 — 🗄️ Local Database & Query ✅
- [x] Persist scans + findings with history
- [x] `seshat query` (raw SQL, read-only)
- [x] Canned queries (top patterns, by severity, by chain, by category, flagged, critical)
- [x] Full-text search over source (`seshat search`, substring + regex)
- [x] `seshat diff A B` (new / fixed / regressed)
- [x] Incremental re-scan (only changed contracts; no-op touches zero)
- [x] Tests for query, diff, incremental

## Phase 4 — 📤 Reporting & UX ✅
- [x] Exporter: JSON
- [x] Exporter: CSV
- [x] Exporter: SARIF 2.1.0 (valid shape; security-severity for code scanning)
- [x] Exporter: Markdown
- [x] Exporter: self-contained offline HTML report
- [x] Pretty CLI triage view (`report --format table`; full curses TUI deferred — optional)
- [x] Review-flag framing surfaced in every output

## Phase 5 — ⚡ Rust Performance Core
- [ ] Rust engine reading the same pattern format
- [ ] Parity test: identical findings vs Python on baseline corpus
- [ ] Parallel scanning + large-DB handling
- [ ] Directory partitioning for big imports (80-char safety)
- [ ] Benchmarks documented

## Phase 6 — 📦 Distribution
- [x] PyPI package (`pipx install seshat-scanner`) — buildable wheel/sdist (publish = maintainer step)
- [ ] crates.io package (depends on Phase 5 Rust core — deferred)
- [x] Standalone binaries (Linux/macOS/Windows) — release workflow builds on tag
- [x] Offline pattern bundle shipped in package (103 patterns as package-data)
- [x] Clean-machine, network-disabled smoke test (offline wheel install + scan verified)
- [x] Terminal demo in README (animated SVG; VHS `.tape` committed for GIF)
- [ ] Docs site (docs/ markdown present; hosted site optional)

## Phase 7 — 🧠 Ecosystem & Polish
- [ ] Plugin system for custom patterns
- [ ] IDE integration (SARIF / LSP)
- [ ] Interop: MaatEye / Slither import-export
- [ ] Community pattern pack
- [ ] `v1.0` release — "100% perfection"

---

<div align="center"><i>📜 One checkbox at a time, the archive is written. 📜</i></div>
