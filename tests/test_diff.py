"""Scan diff tests — new / fixed / regressed."""

import unittest

from seshat import db
from seshat.diff import diff_scans


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO contracts (id) VALUES (1)")
        for pid in ("P001", "P002", "P003"):
            self.conn.execute("INSERT INTO patterns (id) VALUES (?)", (pid,))

    def _scan(self, *findings):
        cur = self.conn.execute("INSERT INTO scans (engine) VALUES ('python')")
        sid = cur.lastrowid
        for pid, line in findings:
            self.conn.execute(
                "INSERT INTO findings (scan_id, contract_id, pattern_id, line) "
                "VALUES (?, 1, ?, ?)", (sid, pid, line)
            )
        return sid

    def test_new_and_fixed(self):
        a = self._scan(("P001", 10), ("P002", 20))
        b = self._scan(("P001", 10), ("P003", 30))
        d = diff_scans(self.conn, a, b)
        self.assertEqual(d.new, [(1, "P003", 30)])
        self.assertEqual(d.fixed, [(1, "P002", 20)])
        self.assertEqual(d.regressed, [])

    def test_regressed_via_intermediate(self):
        a = self._scan(("P001", 10))          # present
        self._scan()                           # intermediate: P001 gone (fixed)
        c = self._scan(("P001", 10))          # came back
        d = diff_scans(self.conn, a, c)
        self.assertEqual(d.regressed, [(1, "P001", 10)])
        self.assertEqual(d.new, [])
        self.assertEqual(d.fixed, [])

    def test_no_regression_without_gap(self):
        a = self._scan(("P001", 10))
        b = self._scan(("P001", 10))  # adjacent, never disappeared
        d = diff_scans(self.conn, a, b)
        self.assertEqual(d.regressed, [])

    def test_diff_is_order_independent_for_intermediates(self):
        a = self._scan(("P001", 1))
        self._scan()  # gap
        b = self._scan(("P001", 1))
        # passing the ids reversed still finds the gap between them
        d = diff_scans(self.conn, b, a)
        self.assertEqual(d.regressed, [(1, "P001", 1)])


if __name__ == "__main__":
    unittest.main()
