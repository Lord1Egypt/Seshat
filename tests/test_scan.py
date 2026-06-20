"""Scan persistence + reproducibility tests."""

import unittest

from seshat import db, ingest
from seshat.patterns import default_catalog_dir, load_patterns, pattern_set_hash
from seshat.scan import run_scan

VULN = (
    "contract Vuln {\n"
    "  mapping(address=>uint) bal;\n"
    "  function mint(address to, uint a) public { bal[to]+=a; }\n"
    "  function withdraw() public {\n"
    "    uint a = bal[msg.sender];\n"
    '    (bool ok,) = msg.sender.call{value: a}("");\n'
    "    bal[msg.sender] = 0;\n"
    "  }\n"
    "}\n"
)


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        ingest.ingest_solidity_text(self.conn, VULN)

    def test_scan_persists_findings(self):
        stats = run_scan(self.conn, self.patterns)
        self.assertEqual(stats.contracts_scanned, 1)
        self.assertGreater(stats.findings, 0)
        # the unprotected mint and the unguarded value-call should both flag
        ids = {
            r[0] for r in self.conn.execute(
                "SELECT DISTINCT pattern_id FROM findings WHERE scan_id = ?",
                (stats.scan_id,),
            )
        }
        self.assertIn("P001", ids)  # unprotected mint
        self.assertIn("P003", ids)  # reentrancy

    def test_scan_row_and_hash_recorded(self):
        stats = run_scan(self.conn, self.patterns)
        row = self.conn.execute(
            "SELECT pattern_set_hash, engine, finished_at, contracts_scanned "
            "FROM scans WHERE id = ?", (stats.scan_id,)
        ).fetchone()
        self.assertEqual(row["pattern_set_hash"], pattern_set_hash(self.patterns))
        self.assertEqual(row["engine"], "python")
        self.assertIsNotNone(row["finished_at"])
        self.assertEqual(row["contracts_scanned"], 1)

    def test_findings_deduped_by_constraint(self):
        # running the same scan logic twice into the same scan_id would collide;
        # here two separate scans each store their own findings.
        s1 = run_scan(self.conn, self.patterns)
        s2 = run_scan(self.conn, self.patterns)
        self.assertNotEqual(s1.scan_id, s2.scan_id)
        self.assertEqual(s1.findings, s2.findings)  # reproducible counts

    def test_pattern_set_hash_stable(self):
        a = pattern_set_hash(self.patterns)
        b = pattern_set_hash(load_patterns(default_catalog_dir()))
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
