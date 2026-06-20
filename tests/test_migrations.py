"""Migration + schema tests. Stdlib unittest only — runs fully offline."""

import sqlite3
import unittest

from seshat import db
from seshat.migrations import MIGRATIONS, latest_version

EXPECTED_TABLES = {
    "schema_version",
    "chains",
    "contracts",
    "sources",
    "patterns",
    "scans",
    "findings",
}


def _table_names(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r[0] for r in rows}


class MigrationSanityTests(unittest.TestCase):
    def test_versions_are_contiguous_and_increasing(self):
        versions = [m.version for m in MIGRATIONS]
        self.assertEqual(versions, sorted(versions))
        self.assertEqual(versions, list(range(1, len(versions) + 1)))
        self.assertEqual(len(versions), len(set(versions)))

    def test_latest_version_matches_last_migration(self):
        self.assertEqual(latest_version(), MIGRATIONS[-1].version)


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        self.addCleanup(self.conn.close)

    def test_fresh_migrate_reaches_latest(self):
        version = db.migrate(self.conn)
        self.assertEqual(version, latest_version())
        self.assertEqual(db.current_version(self.conn), latest_version())

    def test_all_expected_tables_created(self):
        db.migrate(self.conn)
        self.assertTrue(EXPECTED_TABLES.issubset(_table_names(self.conn)))

    def test_migrate_is_idempotent(self):
        v1 = db.migrate(self.conn)
        tables_after_first = _table_names(self.conn)
        v2 = db.migrate(self.conn)  # must not raise (tables already exist)
        self.assertEqual(v1, v2)
        self.assertEqual(_table_names(self.conn), tables_after_first)
        # exactly one schema_version row
        count = self.conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        self.assertEqual(count, 1)

    def test_foreign_keys_enforced(self):
        db.migrate(self.conn)
        with self.assertRaises(sqlite3.IntegrityError):
            # finding references a non-existent scan/contract/pattern
            self.conn.execute(
                "INSERT INTO findings (scan_id, contract_id, pattern_id) "
                "VALUES (999, 999, 'P999')"
            )
            self.conn.commit()

    def test_findings_dedup_constraint(self):
        db.migrate(self.conn)
        c = self.conn
        c.execute("INSERT INTO scans (id) VALUES (1)")
        c.execute("INSERT INTO contracts (id) VALUES (1)")
        c.execute("INSERT INTO patterns (id) VALUES ('P001')")
        c.execute(
            "INSERT INTO findings (scan_id, contract_id, pattern_id, line) "
            "VALUES (1, 1, 'P001', 42)"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO findings (scan_id, contract_id, pattern_id, line) "
                "VALUES (1, 1, 'P001', 42)"
            )

    def test_same_source_hash_allowed_across_chains(self):
        # USDC-style: identical source deployed on two chains must both store.
        db.migrate(self.conn)
        c = self.conn
        c.execute("INSERT INTO chains (key) VALUES ('ethereum')")
        c.execute("INSERT INTO chains (key) VALUES ('polygon')")
        c.execute(
            "INSERT INTO contracts (chain_key, address, source_hash) "
            "VALUES ('ethereum', '0xaaa', 'deadbeef')"
        )
        c.execute(
            "INSERT INTO contracts (chain_key, address, source_hash) "
            "VALUES ('polygon', '0xbbb', 'deadbeef')"
        )
        n = c.execute(
            "SELECT COUNT(*) FROM contracts WHERE source_hash='deadbeef'"
        ).fetchone()[0]
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
