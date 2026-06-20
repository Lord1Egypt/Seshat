"""CLI `seshat init` tests — creation, idempotency, schema version."""

import tempfile
import unittest
from pathlib import Path

from seshat import db
from seshat.cli import main
from seshat.migrations import latest_version


class InitCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / "seshat.db")

    def test_init_creates_versioned_db(self):
        rc = main(["init", "--db", self.db_path])
        self.assertEqual(rc, 0)
        self.assertTrue(Path(self.db_path).exists())
        conn = db.connect(self.db_path)
        self.addCleanup(conn.close)
        self.assertEqual(db.current_version(conn), latest_version())

    def test_init_is_idempotent(self):
        self.assertEqual(main(["init", "--db", self.db_path]), 0)
        first_mtime = Path(self.db_path).stat().st_mtime_ns
        # second run must succeed and not error
        self.assertEqual(main(["init", "--db", self.db_path]), 0)
        conn = db.connect(self.db_path)
        self.addCleanup(conn.close)
        self.assertEqual(db.current_version(conn), latest_version())
        # still exactly one schema_version row
        n = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        self.assertEqual(n, 1)
        self.assertIsInstance(first_mtime, int)

    def test_init_in_nested_dir(self):
        nested = str(Path(self.tmp.name) / "a" / "b" / "seshat.db")
        self.assertEqual(main(["init", "--db", nested]), 0)
        self.assertTrue(Path(nested).exists())

    def test_no_command_prints_help(self):
        # Must not hang or raise; returns 0.
        self.assertEqual(main([]), 0)


if __name__ == "__main__":
    unittest.main()
