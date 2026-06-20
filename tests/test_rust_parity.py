"""Cross-engine parity: the Rust binary and the Python engine must produce
identical findings on the same Solidity files (normalizer + matcher end-to-end).

Skips automatically if the Rust release binary isn't built — so the pure-Python
CI job stays green; a dedicated Rust CI job builds the binary and runs this.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from seshat import engine, normalize
from seshat.patterns import default_catalog_dir, load_patterns

REPO = Path(__file__).resolve().parent.parent
RUST_BIN = REPO / "rust" / "target" / "release" / "seshat-rs"

SAMPLES = {
    "Vault.sol": (
        "pragma solidity 0.7.0;\n"
        "contract Vault {\n"
        "  mapping(address=>uint) bal;\n"
        "  function mint(address to, uint a) public { bal[to]+=a; }\n"
        "  function withdraw() public {\n"
        '    (bool ok,) = msg.sender.call{value: bal[msg.sender]}("");\n'
        "    bal[msg.sender] = 0;\n"
        "  }\n"
        "  function kill() public { selfdestruct(payable(msg.sender)); }\n"
        "}\n"
    ),
    "Token.sol": (
        "pragma solidity ^0.8.20;\n"
        "contract Token {\n"
        "  address owner;\n"
        "  function setOwner(address o) external { owner = o; }\n"
        "  function f(address t) public { t.delegatecall(abi.encode(1)); }\n"
        "  function g() public view returns (bool) { return block.timestamp > 0; }\n"
        "}\n"
    ),
    "Clean.sol": (
        "pragma solidity 0.8.20;\n"
        "contract Clean {\n"
        "  uint256 private x;\n"
        "  function get() external view returns (uint256) { return x; }\n"
        "}\n"
    ),
}


@unittest.skipUnless(RUST_BIN.exists(), "rust binary not built (cargo build --release)")
class RustParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())
        cls.catalog = str(default_catalog_dir())

    def _python_findings(self, src: str) -> set[tuple[str, int]]:
        text = normalize.normalize_text(src).content
        return {(f.pattern_id, f.line) for f in engine.scan_source(text, self.patterns)}

    def _rust_findings(self, path: Path) -> dict[str, set[tuple[str, int]]]:
        out = subprocess.run(
            [str(RUST_BIN), "scan", str(path), "--patterns", self.catalog, "--json"],
            capture_output=True, text=True, check=True,
        )
        result: dict[str, set] = {}
        for r in json.loads(out.stdout):
            result.setdefault(Path(r["file"]).name, set()).add((r["pattern_id"], r["line"]))
        return result

    def test_identical_findings_per_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for name, src in SAMPLES.items():
                (tmp / name).write_text(src, encoding="utf-8")
            for name, src in SAMPLES.items():
                py = self._python_findings(src)
                rs = self._rust_findings(tmp / name).get(name, set())
                self.assertEqual(
                    py, rs,
                    f"{name}: parity mismatch\n  py-only={sorted(py - rs)}\n"
                    f"  rs-only={sorted(rs - py)}",
                )
                # the vulnerable samples must actually produce findings
                if name != "Clean.sol":
                    self.assertTrue(py, f"{name} produced no findings")


if __name__ == "__main__":
    unittest.main()
