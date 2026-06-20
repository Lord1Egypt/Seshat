"""Catalog integrity: every pattern validates and proves itself via fixtures.

This is the Phase 2 acceptance gate. It also enforces the precision baseline
(a clean OpenZeppelin-style ERC-20 raises zero *critical* flags) and the 100+
pattern count.
"""

import unittest

from seshat import engine
from seshat.patterns import (
    default_catalog_dir,
    load_patterns,
    validate_pattern,
)

# A vanilla, safe ERC-20 (OZ-shaped). Must not raise any CRITICAL review flag.
CLEAN_ERC20 = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20, Ownable {
    constructor() ERC20("MyToken", "MTK") Ownable(msg.sender) {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
"""


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def test_catalog_not_empty(self):
        self.assertGreater(len(self.patterns), 0)

    def test_at_least_100_patterns(self):
        self.assertGreaterEqual(
            len(self.patterns), 100,
            f"only {len(self.patterns)} patterns; Phase 2 target is 100+",
        )

    def test_ids_unique(self):
        ids = [p.id for p in self.patterns]
        self.assertEqual(len(ids), len(set(ids)), "duplicate pattern ids")

    def test_all_patterns_valid(self):
        problems = []
        for p in self.patterns:
            problems.extend(validate_pattern(p))
        self.assertEqual(problems, [], "\n".join(problems))

    def test_all_fixtures_pass(self):
        problems = []
        for p in self.patterns:
            problems.extend(engine.check_pattern_fixtures(p))
        self.assertEqual(problems, [], "\n".join(problems))

    def test_clean_erc20_zero_critical(self):
        from seshat import normalize
        norm = normalize.normalize_input(CLEAN_ERC20)[1]
        finds = engine.scan_source(norm.content, self.patterns)
        criticals = [f for f in finds if f.severity == "critical"]
        self.assertEqual(
            criticals, [],
            "clean ERC-20 raised critical flags: "
            + ", ".join(f"{f.pattern_id}@L{f.line}" for f in criticals),
        )


if __name__ == "__main__":
    unittest.main()
