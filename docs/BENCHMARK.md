# ⚡ Seshat — Rust Core Benchmark

The optional Rust core (`rust/`) reads the **same** YAML pattern catalog as the
Python engine and produces **identical findings** — it only adds speed.

## Parity (identical findings)

Verified three ways:

1. **Rust fixture parity** (`cargo test`) — every one of the 103 patterns flags
   its positive fixture and stays quiet on its negative, exactly like the Python
   harness; a clean ERC-20 raises zero critical flags.
2. **Cross-engine parity** (`tests/test_rust_parity.py`) — the Rust binary and
   the Python engine return identical `(pattern_id, line)` findings on the same
   Solidity files (normalizer + matcher, end-to-end).
3. **At scale** — on the 10k-contract corpus below, both engines report the
   **same total finding count**.

## Speed

Measured with `python tools/bench_rust.py 10000` on a WSL2 laptop:

| Engine | 10,000 contracts · 103 patterns | Findings |
|---|---|---|
| 🐍 Python | **16.39 s** | 140,000 |
| 🦀 Rust   | **2.55 s** | 140,000 |
| **Speedup** | **≈ 6.4×** | identical |

The Rust core scans files in parallel (rayon) with compiled regex; the Python
engine stays the ergonomic, zero-dependency default front-end.

## Reproduce

```bash
cd rust && cargo build --release && cargo test    # build + parity tests
cd .. && python tools/bench_rust.py 10000         # benchmark
# scan a tree directly with the fast core:
rust/target/release/seshat-rs scan ./contracts --patterns src/seshat/catalog
```
