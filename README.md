<div align="center">

# 📜 Seshat

### The Divine Scribe of Smart Contracts

*She who measures, records, and remembers — an **offline-first** smart-contract vulnerability **archive & scanner** that builds a local database you own.*

<p align="center">
  <img src="https://img.shields.io/badge/status-design%20phase-blueviolet?style=for-the-badge&labelColor=1a1a2e" alt="Status"/>
  <img src="https://img.shields.io/badge/runs-100%25%20local-00d4aa?style=for-the-badge&labelColor=1a1a2e" alt="Local"/>
  <img src="https://img.shields.io/badge/patterns-100%2B%20planned-gold?style=for-the-badge&labelColor=1a1a2e" alt="Patterns"/>
  <img src="https://img.shields.io/badge/database-SQLite-003B57?style=for-the-badge&labelColor=1a1a2e&logo=sqlite" alt="SQLite"/>
  <img src="https://img.shields.io/badge/cloud-none-ff4444?style=for-the-badge&labelColor=1a1a2e" alt="No Cloud"/>
  <img src="https://img.shields.io/badge/license-MIT-44cc44?style=for-the-badge&labelColor=1a1a2e" alt="MIT"/>
</p>

<p align="center">
  <b>🏛️ Named after Seshat (𓋇)</b> — ancient Egyptian goddess of writing, wisdom, measurement,<br>
  and the divine record-keeper: <i>"Mistress of the House of Books."</i><br>
  <i>Where <a href="https://github.com/Lord1Egypt/MaatEye">MaatEye</a> is the all-seeing eye that judges in the cloud,<br>Seshat is the scribe who records every contract and verdict into an archive that is yours.</i>
</p>

</div>

---

> ### 📐 This repository is in its **design phase**.
> The architecture, roadmap, and pattern taxonomy below are the **blueprint**. Code lands phase by phase (see the [Roadmap](#-roadmap)). Documentation first, so the foundation is right before a single line is written.

---

## 🌍 Vision

**Seshat is a smart-contract vulnerability scanner you download and run on your own machine.** No GitHub Actions. No cloud. No API gatekeeping. It ingests contracts from anywhere, scans them with **100+ detection patterns**, and writes everything — source, scans, findings, history — into a **local SQLite database** you can query, diff, and export, fully offline.

It is built for people who want to **own their data and their analysis**: auditors triaging a portfolio, researchers building a corpus, teams gating CI without sending source to a third party, and anyone who believes a security tool should work on a plane with the Wi-Fi off.

> 🔎 **Honest by design.** Like its sibling MaatEye, Seshat reports **review flags** — heuristic pattern matches that point a human to code worth inspecting — **not confirmed vulnerabilities**. A flag means *"look here,"* not *"this is exploitable."* That honesty is baked into the schema, the severities, and every report.

---

## ✨ What makes Seshat different

| | 📜 **Seshat** | 👁️⚖️ MaatEye | 🔬 Typical scanners |
|---|:---:|:---:|:---:|
| **Runs locally / offline** | ✅ download & run | ❌ cloud (GitHub Actions) | ⚠️ varies |
| **Owns a local database** | ✅ SQLite, queryable | ❌ JSON registry | ❌ stateless |
| **Detection patterns** | ✅ **100+** | 50 | 30–90 |
| **Ingests local projects** | ✅ foundry/hardhat/.sol | ❌ tokens only | ✅ |
| **Scan history & diffing** | ✅ compare runs | ❌ | ⚠️ rare |
| **SARIF / IDE export** | ✅ planned | ❌ | ⚠️ some |
| **Zero-/low-dependency** | ✅ stdlib + sqlite3 | ✅ | ❌ heavy deps |
| **Sends your source anywhere** | ❌ never | ⚠️ explorer fetch | ⚠️ varies |

---

## 🧩 Core features (planned)

- 🗄️ **Local vulnerability database** — every contract, its source, every scan, and every finding live in `seshat.db`. Re-openable, queryable with plain SQL, and 100% offline.
- 🎯 **100+ detection patterns** — a SWC/CWE-mapped taxonomy across access control, reentrancy, arithmetic, proxies, oracles, governance, token economics, signatures, and more — each with a confidence score and labeled test fixtures.
- 📥 **Ingest from anywhere** — local `.sol` files, Solidity Standard-JSON, Foundry/Hardhat projects, a list of addresses (fetched once, cached forever), raw bytecode, or import an existing MaatEye registry.
- 🧪 **Honest, deduplicated findings** — flatten Standard-JSON (and Etherscan's `{{…}}`), drop bundled dependencies, strip comments/strings, dedup per `(pattern, line)`, and threshold by confidence — so the numbers mean something.
- 🔁 **Scan diffing** — compare two scans of the same corpus: what's new, what's fixed, what regressed.
- 📤 **Export everywhere** — JSON, CSV, **SARIF** (for VS Code / CI annotations), Markdown, and a self-contained offline **HTML report** you can open in any browser.
- ⚡ **Optional Rust core** — a later phase adds a parallel Rust scanning engine for large corpora, keeping the Python front-end ergonomic.

---

## 🏗️ Architecture at a glance

```mermaid
flowchart TB
    subgraph IN["📥 Ingestion"]
        A1[Local .sol files]
        A2[Foundry / Hardhat project]
        A3[Address list + explorer fetch]
        A4[Standard-JSON / bytecode]
        A5[MaatEye registry import]
    end

    A1 & A2 & A3 & A4 & A5 --> NORM[🧹 Normalize<br/>flatten JSON · drop deps · strip comments]

    NORM --> DB[(🗄️ seshat.db<br/>SQLite)]

    DB --> ENG[🎯 Pattern Engine<br/>100+ patterns · regex · sig · AST<br/>confidence threshold · dedup]
    ENG --> DB

    DB --> Q[🔍 Query & Diff<br/>SQL · canned queries · scan compare]
    DB --> REP[📤 Reporters<br/>JSON · CSV · SARIF · MD · HTML]

    style DB fill:#0d1225,stroke:#ffd700,color:#ffd700
    style ENG fill:#131a30,stroke:#00d4aa,color:#e0e0e0
    style NORM fill:#131a30,stroke:#4a7fc7,color:#e0e0e0
```

Detailed design lives in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**, the schema in **[docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md)**, and the pattern taxonomy in **[docs/PATTERNS.md](docs/PATTERNS.md)**.

---

## 🚀 Quick start *(target experience — not yet implemented)*

```bash
# Install (planned distribution channels)
pipx install seshat          # Python
# or:  cargo install seshat  # Rust core
# or:  download a standalone binary — no runtime required

# Build a database from a local project
seshat ingest ./my-foundry-project
seshat scan                       # runs all 100+ patterns into seshat.db

# Ask the archive questions — offline
seshat query "SELECT name, severity, COUNT(*) FROM findings GROUP BY 1,2"
seshat report --html out.html     # self-contained offline report
seshat diff --since last-week     # what changed?

# Ingest by address (fetched once, then cached locally forever)
seshat ingest --chain ethereum 0xA0b8...  --scan
```

> The commands above describe the **intended** UX. They are the contract the build will fulfill — see the [Roadmap](#-roadmap).

---

## 🗺️ Roadmap

Seshat ships in eight focused phases. Full detail + acceptance criteria in **[ROADMAP.md](ROADMAP.md)**; per-phase task lists in **[CHECKLIST.md](CHECKLIST.md)**.

| Phase | Theme | Outcome |
|:---:|---|---|
| **0** | 🏛️ Foundation & schema | Repo, CI, SQLite schema + migrations |
| **1** | 📥 Ingestion engine | Import & normalize from every source |
| **2** | 🎯 Pattern engine (100+) | Matchers, pattern SDK, labeled fixtures |
| **3** | 🗄️ Local DB & query | Persist, SQL/canned queries, scan diff |
| **4** | 📤 Reporting & UX | JSON/CSV/SARIF/MD/HTML, pretty CLI/TUI |
| **5** | ⚡ Rust performance core | Parallel engine for large corpora |
| **6** | 📦 Distribution | PyPI · crates.io · binaries · demo GIF |
| **7** | 🧠 Ecosystem | Plugins · IDE/SARIF · interop |

**Current status:** 📐 *Phase 0 — design & documentation.*

---

## 📜 Philosophy

> *Seshat recorded the deeds; Ma'at weighed them against the feather.*

Truth over flattery. A flag is an invitation to look, not a verdict. The archive is yours, it works offline, and it tells you exactly how confident it is. Read more in **[ABOUT.md](ABOUT.md)**.

---

## 🤝 Contributing & License

This is an early-stage, design-first project by **[Lord1Egypt](https://github.com/Lord1Egypt)**. Issues, pattern ideas, and architecture feedback are welcome while the foundation is being laid. Licensed under **[MIT](LICENSE)** — free for everyone, forever.

<div align="center">
<br>
<i>📜 May every contract be measured, recorded, and remembered. 📜</i>
</div>
