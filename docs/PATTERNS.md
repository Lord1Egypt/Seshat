# 🎯 Seshat — Pattern Taxonomy (100+)

Seshat targets **100+ detection patterns**, organized into a clear taxonomy and mapped to the **SWC Registry** and **CWE** where applicable. This document is the plan; patterns are implemented in Phase 2, each with labeled fixtures.

## Pattern anatomy (YAML)

```yaml
id: "P017"
name: "Arbitrary External Call"
severity: "critical"          # critical | high | medium | low | info
category: "EXTERNAL_CALLS"
confidence: 0.75              # 0–1; below the engine threshold ⇒ skipped
swc: "SWC-112"
cwe: "CWE-749"
detectors:
  - type: "regex"            # regex | function_signature | ast | semantic
    pattern: "\\.call\\{[^}]*\\}\\s*\\([^)]*\\)"
    confidence: 0.75
    description: "Low-level call to a caller-controlled destination"
    recommendation: "Restrict the call target; prefer pull-payment patterns."
fixtures:
  positive: ["fixtures/P017_vuln.sol"]   # must be flagged
  negative: ["fixtures/P017_clean.sol"]  # must stay quiet
```

**Rules every pattern obeys** (inherited from MaatEye's hard lessons):
- Runs against **normalized** source (deps dropped, comments/strings stripped).
- Carries a **confidence**; the engine drops sub-threshold detectors.
- Findings are **deduped per line**.
- Ships with **≥1 positive and ≥1 negative fixture**; CI fails if either breaks.

## Categories & target coverage

| Category | Focus | ~Target |
|---|---|---|
| 🔐 **Access Control** | unprotected mint/init, missing modifiers, role hijack, tx.origin, ownership | 14 |
| 🔄 **Reentrancy** | classic, cross-function, cross-contract, read-only, ERC-721/1155 callbacks, fallback | 12 |
| 📞 **External Calls** | unchecked returns, arbitrary/delegatecall targets, gas stipend, existence checks | 12 |
| 🧩 **Proxy / Upgradeable** | uninitialized proxy, storage collision, constructor-in-impl, UUPS guards, metamorphic | 12 |
| 📐 **Arithmetic** | overflow/underflow, precision loss, rounding direction, fee math, EIP-4626 share math | 10 |
| 🪙 **Token Economics** | honeypots, fee-on-transfer, deflationary accounting, oracle manipulation, flash-loan vectors | 12 |
| 🗳️ **Governance** | low quorum, flash-loan takeover, timelock gaps, vote manipulation | 8 |
| ✍️ **Signatures / Crypto** | replay, missing nonce/chainId, malleability, ecrecover(0) | 8 |
| ⏱️ **Time / Randomness** | block.timestamp dependence, blockhash randomness, deadline checks | 6 |
| 🧠 **Business Logic** | input validation, visibility, unchecked state machines, dangerous defaults | 8 |
| 🛡️ **Standards / Hygiene** | SafeERC20, ERC-20 return values, deprecated opcodes, floating pragma | 8 |
| 🔬 **Bytecode / Low-level** | selfdestruct, delegatecall in assembly, create2 collisions, dangerous opcodes | 8 |

**Total target: ~128 patterns** (comfortably over the 100+ goal, with room to prune weak ones).

## Severity ≠ confidence

These are **independent** axes and both are stored:
- **Severity** = *if real, how bad?* (triage priority)
- **Confidence** = *how sure is the heuristic this is real?*

A `critical` pattern with `0.4` confidence is a "look here urgently *if* it's real" — surfaced, but never presented as a confirmed exploit.

## Matcher kinds

| Kind | Good for | Caveats |
|---|---|---|
| `regex` | syntactic smells, opcode/keyword use | precise patterns only; no DOTALL/IGNORECASE traps |
| `function_signature` | "function X with/without modifier Y" | scoped to a function block |
| `ast` / structural | call-after-state-change, inheritance shape | lightweight, not a full compiler |
| `semantic` | cross-pattern heuristics, taint hints | highest effort, gated by confidence |

## Anti-false-positive discipline

Hard rules, learned the hard way on MaatEye:
- ❌ Never match across **bundled dependency** code (it's dropped before scanning).
- ❌ Never match inside **comments or string literals** (stripped first).
- ❌ Never let a detector require a trivially-true token (e.g. the word `function`) — it must require *real structure*.
- ❌ Never count the same line twice.
- ✅ Every pattern proves itself against a **clean fixture** (e.g. a vanilla OpenZeppelin ERC-20 must raise **zero** critical flags).

## Provenance

The first 50 patterns are migrated from **MaatEye** *with their corrections already applied* (e.g. ETH-only gas-stipend matching, 2-arg ERC-20 transfer detection, proxy-scoped constructor checks, no keyword-co-occurrence AST rules). The remaining ~78 expand coverage toward the full SWC registry and modern DeFi weakness classes.

## Implementation status (Phase 2 — shipped)

- **103 patterns** ship in `patterns/catalog/` across all 12 categories; each is a self-contained YAML file with **inline** TP/FP fixtures.
- **Zero dependencies.** YAML is parsed by a stdlib `miniyaml` subset loader (regex lives in single-quoted scalars so backslashes stay literal). No PyYAML.
- **One unified matcher** backs the four declared kinds: `scope: file` (per-line) or `scope: function` (brace-balanced body, including `receive`/`fallback`), optional `multiline`, and `requires`/`forbids` lists that compose detectors into `function_signature`/`ast`/`semantic` checks without a real compiler.
- **Engine contracts:** sub-threshold detectors are dropped; findings are deduped per `(pattern, line)`, highest confidence wins.
- **Gates (CI):** `seshat patterns --validate` proves every pattern's fixtures; a clean OZ-style ERC-20 raises **zero critical** flags; the catalog count is asserted ≥ 100.
- Regenerate the catalog with `python tools/gen_catalog.py` (the YAML files are the source of truth; the generator is committed for provenance).
- Run a scan with `seshat scan`; results persist to the archive with a reproducible `pattern_set_hash`.
