#!/usr/bin/env python3
"""Benchmark: Python engine vs the Rust core on a synthetic corpus.

    python tools/bench_rust.py [N]      # default N=5000 contracts

Generates N small Solidity files (a mix of flagged + clean), then times a full
scan with each engine over the same corpus and reports the speedup.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from seshat import engine, normalize
from seshat.patterns import default_catalog_dir, load_patterns

REPO = Path(__file__).resolve().parent.parent
RUST_BIN = REPO / "rust" / "target" / "release" / "seshat-rs"

TEMPLATE = """pragma solidity 0.7.{v};
contract C{i} {{
  mapping(address=>uint) bal;
  address owner;
  // a comment with selfdestruct that must be ignored
  function mint(address to, uint a) public {{ bal[to] += a; }}
  function setOwner(address o) external {{ owner = o; }}
  function withdraw() public {{
    (bool ok,) = msg.sender.call{{value: bal[msg.sender]}}("");
    bal[msg.sender] = 0;
  }}
  function ts() public view returns (bool) {{ return block.timestamp > 1; }}
}}
"""


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    pats = load_patterns(default_catalog_dir())
    catalog = str(default_catalog_dir())

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        srcs = []
        for i in range(n):
            p = tmp / f"C{i}.sol"
            p.write_text(TEMPLATE.format(i=i, v=i % 8), encoding="utf-8")
            srcs.append(p)
        print(f"corpus: {n} contracts, {len(pats)} patterns")

        # Python engine
        t0 = time.perf_counter()
        py_findings = 0
        for p in srcs:
            text = normalize.normalize_text(p.read_text(encoding="utf-8")).content
            py_findings += len(engine.scan_source(text, pats))
        py = time.perf_counter() - t0
        print(f"  python : {py:7.2f}s   ({py_findings} findings)")

        if not RUST_BIN.exists():
            print("  rust   : (binary not built — run `cargo build --release` in rust/)")
            return

        t0 = time.perf_counter()
        out = subprocess.run(
            [str(RUST_BIN), "scan", str(tmp), "--patterns", catalog, "--json"],
            capture_output=True, text=True, check=True,
        )
        rs = time.perf_counter() - t0
        import json
        rs_findings = len(json.loads(out.stdout))
        print(f"  rust   : {rs:7.2f}s   ({rs_findings} findings)")
        if rs > 0:
            print(f"  speedup: {py / rs:.1f}x")


if __name__ == "__main__":
    main()
