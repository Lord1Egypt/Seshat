"""Ingestion adapter tests — importers, dedup, dependency exclusion."""

import json
import tempfile
import unittest
from pathlib import Path

from seshat import db, ingest


def _count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class IngestBase(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)


class LocalAndDedupTests(IngestBase):
    def test_ingest_solidity_text(self):
        r = ingest.ingest_solidity_text(self.conn, "contract Token { uint x; }")
        self.assertTrue(r.created)
        self.assertEqual(r.name, "Token")
        self.assertEqual(r.has_verified_source, 1)
        self.assertEqual(_count(self.conn, "contracts"), 1)
        # a normalized source row exists
        self.assertGreaterEqual(_count(self.conn, "sources"), 1)

    def test_reingest_same_content_is_noop(self):
        ingest.ingest_solidity_text(self.conn, "contract A { uint x; }")
        r2 = ingest.ingest_solidity_text(self.conn, "contract A { uint x; }")
        self.assertFalse(r2.created)
        self.assertEqual(_count(self.conn, "contracts"), 1)

    def test_dedup_by_chain_address(self):
        ingest.ingest_solidity_text(
            self.conn, "contract A {}", chain="ethereum", address="0xAbC"
        )
        # different source, same (chain, address) → still one contract
        r2 = ingest.ingest_solidity_text(
            self.conn, "contract DIFFERENT {}", chain="ethereum", address="0xabc"
        )
        self.assertFalse(r2.created)
        self.assertEqual(_count(self.conn, "contracts"), 1)
        # address stored lowercased
        addr = self.conn.execute("SELECT address FROM contracts").fetchone()[0]
        self.assertEqual(addr, "0xabc")

    def test_same_source_two_chains_both_stored(self):
        ingest.ingest_solidity_text(self.conn, "contract A {}", chain="ethereum", address="0x1")
        ingest.ingest_solidity_text(self.conn, "contract A {}", chain="polygon", address="0x2")
        self.assertEqual(_count(self.conn, "contracts"), 2)
        # chains table seeded for both
        self.assertEqual(_count(self.conn, "chains"), 2)


class FileAndProjectTests(IngestBase):
    def _write(self, rel, content):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_ingest_solidity_file(self):
        p = self._write("Vault.sol", "contract Vault { uint x; }")
        r = ingest.ingest_solidity_file(self.conn, p)
        self.assertTrue(r.created)
        self.assertEqual(r.name, "Vault")

    def test_foundry_project_excludes_deps(self):
        self._write("foundry.toml", "[profile.default]\nsrc = 'src'\n")
        self._write("src/Token.sol", "contract Token { uint x; }")
        self._write("src/Vault.sol", "contract Vault { uint y; }")
        self._write("lib/openzeppelin-contracts/ERC20.sol", "contract ERC20 {}")
        self._write("lib/forge-std/Test.sol", "contract Test {}")
        results = ingest.ingest_project(self.conn, self.root)
        names = sorted(r.name for r in results)
        self.assertEqual(names, ["Token", "Vault"])  # deps excluded
        self.assertEqual(_count(self.conn, "contracts"), 2)
        origins = {
            r[0] for r in self.conn.execute("SELECT DISTINCT origin FROM contracts")
        }
        self.assertEqual(origins, {"foundry"})

    def test_project_reingest_noop(self):
        self._write("foundry.toml", "x")
        self._write("src/A.sol", "contract A { uint x; }")
        ingest.ingest_project(self.conn, self.root)
        ingest.ingest_project(self.conn, self.root)
        self.assertEqual(_count(self.conn, "contracts"), 1)


class BytecodeAndRegistryTests(IngestBase):
    def test_bytecode_marked_unverified(self):
        r = ingest.ingest_bytecode(
            self.conn, "0x6080604052", chain="base", address="0xfeed"
        )
        self.assertEqual(r.has_verified_source, 0)
        row = self.conn.execute(
            "SELECT kind FROM sources WHERE contract_id = ?", (r.contract_id,)
        ).fetchone()
        self.assertEqual(row[0], "bytecode")

    def test_registry_array(self):
        reg = [
            {"chain": "ethereum", "address": "0xaaa", "name": "Foo",
             "source": "contract Foo { uint x; }"},
            {"chain": "base", "address": "0xbbb", "bytecode": "0x6080"},
        ]
        p = self.root / "registry.json"
        p.write_text(json.dumps(reg), encoding="utf-8")
        results = ingest.ingest_maateye_registry(self.conn, p)
        self.assertEqual(len(results), 2)
        self.assertEqual(_count(self.conn, "contracts"), 2)
        verified = self.conn.execute(
            "SELECT COUNT(*) FROM contracts WHERE has_verified_source = 1"
        ).fetchone()[0]
        self.assertEqual(verified, 1)

    def test_registry_jsonl(self):
        lines = "\n".join(
            json.dumps(r) for r in [
                {"chain": "polygon", "address": "0x1", "source": "contract A {}"},
                {"chain": "polygon", "address": "0x2", "source": "contract B {}"},
            ]
        )
        p = self.root / "registry.jsonl"
        p.write_text(lines, encoding="utf-8")
        results = ingest.ingest_maateye_registry(self.conn, p)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
