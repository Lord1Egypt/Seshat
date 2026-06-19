# Seshat — Project Instructions for AI Assistants

This file orients any AI coding assistant (Claude, Antigravity, etc.) working on **Seshat**. Follow it exactly.

## What Seshat is
An **offline-first, downloadable** smart-contract vulnerability **scanner + local SQLite archive**. 100+ heuristic detection patterns. Runs 100% locally — **no GitHub Actions / cloud / API gatekeeping** in the core path. Sibling to [MaatEye](https://github.com/Lord1Egypt/MaatEye) (the cloud scanner); Seshat is the local scribe/record-keeper.

**Status:** design phase — see `ROADMAP.md` / `CHECKLIST.md`. Build phase by phase; each phase ends green before the next.

## Non-negotiable principles
1. **Offline-first.** Nothing in the core path needs network. Address-fetching is the only optional, explicit online step, and it caches.
2. **Low/zero dependency.** Python **stdlib + `sqlite3`** for the core. Justify every new dependency in the PR.
3. **Reproducible.** Same inputs + same pattern set ⇒ identical findings. No nondeterminism.
4. **Honest output.** Findings are **review flags** (heuristic), never "confirmed vulnerabilities." Every finding carries a confidence; severity = triage priority. Never inflate counts.
5. **Filesystem safety.** Cap identifiers/dir names at **80 chars**; partition large directories by first char (avoid `OSError 36`). Never dump thousands of files in one folder.
6. **Test before done.** Every pattern needs labeled fixtures (≥1 true-positive, ≥1 clean). Every module needs unit tests. CI runs offline and must be green.

## Lessons inherited from MaatEye (bake in, don't rediscover)
- **Normalize source before matching:** flatten Standard-JSON (incl. Etherscan `{{…}}`), **drop dependency files** (`@openzeppelin`, `node_modules/`, `lib/`, `solmate`, …), **strip comments + string literals** (preserve line numbers). Scanning bundled deps/comments inflated findings ~10×.
- **Confidence threshold:** detectors carry a confidence; skip sub-threshold ones. A "good-practice detected" note must never become a critical finding.
- **Dedup per `(pattern, line)`** — never count the same line many times.
- **Verified source only** counts as "analyzed"; bytecode placeholders do not.
- **`ast`/structural detectors that match on mere keyword co-occurrence over-fire** — require real structure, and add a clean fixture to prove they stay quiet.

## Workflow
- **branch → PR → merge.** Never push straight to `main`.
- End commit messages with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Keep `CHECKLIST.md` current — check items as they land.
- At `v1.0` (100+ validated patterns, all exporters, binaries, demo GIF), Seshat is "100% perfection."

## Layout (target)
```
seshat/
  src/seshat/        # Python core (stdlib + sqlite3)
  patterns/          # 100+ YAML patterns (+ fixtures)
  tests/             # unit tests + pattern fixtures
  docs/              # ARCHITECTURE, DATABASE_SCHEMA, PATTERNS, COMPARISON
  rust/              # optional Rust perf core (Phase 5)
```
