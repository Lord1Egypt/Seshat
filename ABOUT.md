<div align="center">

# 📜 About Seshat

*Mistress of the House of Books · Lady of Measurement · Scribe of the Gods*

</div>

---

## Who was Seshat?

In ancient Egyptian belief, **Seshat (𓋇)** was the goddess of writing, wisdom, measurement, and record-keeping — the divine librarian who inscribed the deeds of kings on the leaves of the sacred *ished* tree, and who "stretched the cord" to measure the foundations of every temple before it was built. She was the keeper of the archive, the one who **measured, recorded, and remembered**.

A scanner that builds and keeps a **local archive of contracts and their findings** could have no better patron. **MaatEye** is the all-seeing *eye* — it watches the chains and weighs them in public. **Seshat** is the *scribe* — she takes what is found and writes it, precisely and permanently, into a book of records that belongs to **you**.

---

## Why Seshat exists

Most contract scanners ask you to make a trade you shouldn't have to make:

- **Send us your source code** (and trust where it goes), **or**
- **Run a heavyweight toolchain** with a forest of dependencies, **or**
- **Live inside someone's cloud** with rate limits and an account.

Seshat refuses the trade. It is **downloadable, offline-first, and yours**:

1. **Your machine, your data.** Source never leaves your computer unless *you* ask it to fetch a public address. Findings live in a local SQLite file you can back up, inspect, or delete.
2. **Reproducible.** The same inputs and the same pattern set produce the same database. No moving cloud, no "results changed because the backend did."
3. **Queryable.** Your findings are not a static report — they're a **database**. Ask it anything in SQL. Slice by chain, by severity, by pattern, by date.
4. **Honest.** Seshat reports **review flags**, not verdicts. Every finding carries a confidence score and a severity that means *triage priority*, not *confirmed impact*. It will tell you when it is guessing.

---

## What Seshat is — and is not

**Seshat *is*:**
- An **offline vulnerability archive** — a growing, queryable local database of contracts and their analysis.
- A **heuristic static scanner** with 100+ patterns spanning the major smart-contract weakness classes (SWC/CWE-mapped).
- A **triage and corpus tool** — for auditors, researchers, CI gates, and the curious.

**Seshat is *not*:**
- A formal verifier or a symbolic-execution engine. It does not prove safety.
- A guarantee. A flagged contract is **not necessarily exploitable**; an unflagged one is **not necessarily safe**.
- A replacement for a manual audit. It points the flashlight; a human still has to look.

---

## The lessons it was born with

Seshat is not starting from zero. It inherits hard-won lessons from its sibling **[MaatEye](https://github.com/Lord1Egypt/MaatEye)**, baked into the foundation rather than discovered later:

- **Honest framing from day one** — "review flags," never inflated "vulnerability" counts.
- **Confidence thresholding** — low-confidence heuristics and "good-practice" notes never masquerade as critical findings.
- **Source normalization** — flatten Solidity Standard-JSON (including Etherscan's `{{…}}` quirk), **drop bundled dependencies**, and **strip comments and string literals** before matching, so patterns hit real logic, not OpenZeppelin boilerplate or revert messages.
- **Deduplication** — one finding per `(pattern, line)`, so a contract is never inflated to dozens of phantom issues.
- **Verified-source discipline** — only real, published source is analyzed; bytecode placeholders are never counted as "scanned."
- **Labeled precision baselines** — every pattern ships with fixtures proving it catches the real thing *and* stays quiet on clean code.

---

## The family

Seshat is part of a small pantheon of tools by **Lord1Egypt (Mohamed Mounir)**:

| Tool | Domain | Deity |
|---|---|---|
| **[MaatEye](https://github.com/Lord1Egypt/MaatEye)** | cloud multi-chain scanner + public dashboard | Ma'at — truth & judgment |
| **📜 Seshat** | offline local-DB scanner & archive | Seshat — the scribe & record-keeper |
| **ethsmith** | Solidity security audit tooling | the forge |
| **ThothTerm** | GPU terminal emulator | Thoth — knowledge |

Together: the **eye** that watches, the **scribe** that records.

---

<div align="center">
<i>📜 What is measured can be improved. What is recorded is not forgotten. 📜</i>
</div>
