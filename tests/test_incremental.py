"""Incremental re-scan: unchanged contracts are not re-run."""

import unittest

from seshat import db, ingest
from seshat.patterns import default_catalog_dir, load_patterns
from seshat.scan import run_scan

A = "contract A { function mint(address t, uint a) public { } }"
B = "contract B { function withdraw() public { payable(msg.sender).transfer(1); } }"


class IncrementalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        ingest.ingest_solidity_text(self.conn, A, chain="ethereum", address="0xa")

    def test_noop_incremental_touches_zero(self):
        run_scan(self.conn, self.patterns)  # full baseline
        stats = run_scan(self.conn, self.patterns, incremental=True)
        self.assertEqual(stats.rescanned, 0)
        self.assertEqual(stats.reused, 1)
        # findings preserved by copy-forward
        self.assertGreater(stats.findings, 0)

    def test_new_contract_is_rescanned(self):
        run_scan(self.conn, self.patterns)
        ingest.ingest_solidity_text(self.conn, B, chain="ethereum", address="0xb")
        stats = run_scan(self.conn, self.patterns, incremental=True)
        self.assertEqual(stats.rescanned, 1)  # only the new contract
        self.assertEqual(stats.reused, 1)     # the unchanged one

    def test_different_pattern_set_forces_full_rescan(self):
        run_scan(self.conn, self.patterns)
        subset = self.patterns[:5]  # different pattern_set_hash → no baseline match
        stats = run_scan(self.conn, subset, incremental=True)
        self.assertEqual(stats.reused, 0)
        self.assertEqual(stats.rescanned, 1)

    def test_copy_forward_preserves_findings(self):
        s1 = run_scan(self.conn, self.patterns)
        s2 = run_scan(self.conn, self.patterns, incremental=True)
        f1 = self.conn.execute(
            "SELECT pattern_id, line FROM findings WHERE scan_id = ? ORDER BY line, pattern_id",
            (s1.scan_id,)).fetchall()
        f2 = self.conn.execute(
            "SELECT pattern_id, line FROM findings WHERE scan_id = ? ORDER BY line, pattern_id",
            (s2.scan_id,)).fetchall()
        self.assertEqual([tuple(r) for r in f1], [tuple(r) for r in f2])


if __name__ == "__main__":
    unittest.main()
