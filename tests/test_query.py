"""Query + search tests."""

import tempfile
import unittest
from pathlib import Path

from seshat import db, ingest, query
from seshat.patterns import default_catalog_dir, load_patterns
from seshat.scan import run_scan

VULN = (
    "contract Vuln {\n"
    "  mapping(address=>uint) bal;\n"
    "  function mint(address to, uint a) public { bal[to]+=a; }\n"
    "}\n"
)


class QueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "s.db")
        conn, _, _ = db.init_db(self.path)
        ingest.ingest_solidity_text(conn, VULN, chain="ethereum", address="0xabc")
        run_scan(conn, self.patterns)
        conn.close()
        self.ro = query.connect_ro(self.path)
        self.addCleanup(self.ro.close)

    def test_read_only_blocks_writes(self):
        import sqlite3
        with self.assertRaises(sqlite3.OperationalError):
            self.ro.execute("DELETE FROM findings")

    def test_canned_summary(self):
        rows = query.run_canned(self.ro, "summary")
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["findings"], 1)

    def test_canned_by_severity_and_top_patterns(self):
        sev = query.run_canned(self.ro, "by-severity")
        self.assertTrue(any(r["severity"] == "critical" for r in sev))
        top = query.run_canned(self.ro, "top-patterns")
        self.assertTrue(any(r["pattern_id"] == "P001" for r in top))

    def test_canned_by_chain(self):
        rows = query.run_canned(self.ro, "by-chain")
        self.assertTrue(any(r["chain"] == "ethereum" for r in rows))

    def test_unknown_canned(self):
        with self.assertRaises(KeyError):
            query.run_canned(self.ro, "nope")

    def test_raw_sql(self):
        rows = query.run_sql(self.ro, "SELECT COUNT(*) AS n FROM contracts")
        self.assertEqual(rows[0]["n"], 1)


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "s.db")
        conn, _, _ = db.init_db(self.path)
        ingest.ingest_solidity_text(conn, VULN)
        conn.close()
        self.ro = query.connect_ro(self.path)
        self.addCleanup(self.ro.close)

    def test_substring_search_with_line(self):
        hits = query.search_source(self.ro, "function mint")
        self.assertTrue(hits)
        self.assertEqual(hits[0].line, 3)

    def test_regex_search(self):
        hits = query.search_source(self.ro, r"mapping\(", regex=True)
        self.assertTrue(hits)

    def test_no_match(self):
        self.assertEqual(query.search_source(self.ro, "selfdestruct"), [])

    def test_like_wildcard_is_escaped(self):
        # "%" should be treated literally, not as a wildcard
        self.assertEqual(query.search_source(self.ro, "%zzz%"), [])


if __name__ == "__main__":
    unittest.main()
