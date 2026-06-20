"""Explorer cache tests — offline-first, never hits the network in CI."""

import json
import tempfile
import unittest
from pathlib import Path

from seshat import db, explorer, ingest


class ExplorerCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name)

    def _seed(self, chain, address, result):
        p = explorer._cache_path(self.cache, chain, address)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result), encoding="utf-8")
        return p

    def test_offline_miss_raises(self):
        with self.assertRaises(explorer.ExplorerError):
            explorer.fetch_sourcecode(
                "ethereum", "0xabc", cache_dir=self.cache, online=False
            )

    def test_unknown_chain_raises(self):
        with self.assertRaises(explorer.ExplorerError):
            explorer.fetch_sourcecode(
                "notachain", "0xabc", cache_dir=self.cache, online=False
            )

    def test_cache_hit_served_offline_case_insensitive(self):
        result = {"SourceCode": "contract A {}", "ContractName": "A"}
        self._seed("ethereum", "0xabc", result)
        got = explorer.fetch_sourcecode(
            "ethereum", "0xABC", cache_dir=self.cache, online=False
        )
        self.assertEqual(got, result)

    def test_extract_and_verified(self):
        result = {"SourceCode": "contract A {}", "ContractName": "A"}
        src, name = explorer.extract_source_payload(result)
        self.assertEqual(src, "contract A {}")
        self.assertEqual(name, "A")
        self.assertTrue(explorer.is_verified(result))
        self.assertFalse(explorer.is_verified({"SourceCode": ""}))


class IngestAddressOfflineTests(unittest.TestCase):
    """Full offline address-ingest path using a pre-seeded cache (no network)."""

    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name)

    def test_ingest_address_from_cache(self):
        result = {"SourceCode": "contract Vault { uint x; }", "ContractName": "Vault"}
        p = explorer._cache_path(self.cache, "ethereum", "0xdead")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result), encoding="utf-8")

        r = ingest.ingest_address(
            self.conn, "ethereum", "0xDEAD", online=False, cache_dir=self.cache
        )
        self.assertTrue(r.created)
        self.assertEqual(r.name, "Vault")
        self.assertEqual(r.has_verified_source, 1)
        self.assertEqual(r.origin, "explorer")
        # second call is idempotent (still cached, still one row)
        r2 = ingest.ingest_address(
            self.conn, "ethereum", "0xdead", online=False, cache_dir=self.cache
        )
        self.assertFalse(r2.created)
        n = self.conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        self.assertEqual(n, 1)

    def test_unverified_address_falls_back_to_bytecode(self):
        result = {"SourceCode": "", "Bytecode": "0x6080"}
        p = explorer._cache_path(self.cache, "base", "0xbeef")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result), encoding="utf-8")
        r = ingest.ingest_address(
            self.conn, "base", "0xbeef", online=False, cache_dir=self.cache
        )
        self.assertEqual(r.has_verified_source, 0)


if __name__ == "__main__":
    unittest.main()
