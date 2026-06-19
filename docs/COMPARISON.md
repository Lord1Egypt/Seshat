# ⚖️ Seshat vs the field

How Seshat positions itself next to its sibling MaatEye and common static analyzers. This is about **fit**, not "winning" — each tool is good at a different job.

## Seshat vs MaatEye (the family split)

| | 📜 **Seshat** | 👁️⚖️ **MaatEye** |
|---|---|---|
| **Where it runs** | your machine, offline | GitHub Actions, cloud |
| **Data home** | local SQLite database (yours) | JSON registry + public Pages dashboard |
| **What it scans** | anything you ingest (local projects, addresses, JSON) | tokens discovered from feeds |
| **Patterns** | 100+ (target) | 50 |
| **History / diff** | full scan history, diffing | latest snapshot |
| **Audience** | auditors, researchers, CI, the privacy-minded | public watchers, dashboards |
| **Output** | JSON/CSV/SARIF/MD/HTML, SQL queries | hosted dashboard |

**The mythology mirrors the design:** MaatEye is the *eye* that judges in the open; Seshat is the *scribe* that records into a private archive. They interoperate — Seshat can import a MaatEye registry, and either can export to the other's formats.

## Seshat vs typical static analyzers

| Trait | Seshat | Slither-class tools | Cloud SaaS scanners |
|---|---|---|---|
| Offline | ✅ core needs no network | ✅ usually | ❌ |
| Dependency weight | stdlib + sqlite3 | moderate–heavy | n/a |
| Persists a queryable DB | ✅ first-class | ⚠️ rare | ⚠️ proprietary |
| Scan diffing | ✅ | ⚠️ some | ✅ |
| SARIF / IDE | ✅ planned | ✅ some | ✅ |
| Honest "review flag" framing | ✅ explicit | ⚠️ varies | ⚠️ marketing-driven |
| Formal/symbolic depth | ❌ heuristic only | ⚠️ some | ⚠️ some |

## When to reach for Seshat

- You want to **triage a portfolio** of contracts and keep the results in a database you can query later.
- You need to scan **without sending source anywhere**.
- You want **reproducible** results and the ability to **diff** scans over time.
- You're **building a corpus** for research and want structured, deduplicated findings.

## When *not* to

- You need **proofs**, not heuristics — use a formal verifier or symbolic execution tool.
- You want a **zero-setup hosted dashboard** for public token watching — that's **MaatEye**.
- You need a manual audit — Seshat triages; it does not replace a human auditor.

> Honest by design: a flag is *"look here,"* never *"this is exploitable."*
