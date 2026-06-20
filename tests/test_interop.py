"""Interop tests — SARIF round-trip and Slither import."""

import json
import tempfile
import unittest
from pathlib import Path

from seshat import db, ingest, interop, report
from seshat.patterns import default_catalog_dir, load_patterns
from seshat.scan import run_scan

VULN = (
    "contract Vuln {\n"
    "  function mint(address to, uint a) public { }\n"
    "  function kill() public { selfdestruct(payable(msg.sender)); }\n"
    "}\n"
)

SLITHER = {
    "success": True,
    "results": {"detectors": [
        {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
         "description": "Reentrancy in withdraw()\n",
         "elements": [{"source_mapping": {"lines": [12, 13], "filename_relative": "V.sol"}}]},
        {"check": "naming-convention", "impact": "Informational", "confidence": "High",
         "description": "Constant not in UPPER_CASE",
         "elements": [{"source_mapping": {"lines": [4], "filename_relative": "V.sol"}}]},
    ]},
}


class SarifRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_export_then_import_preserves_findings(self):
        # produce a scan + SARIF
        src = db.connect(":memory:")
        db.migrate(src)
        self.addCleanup(src.close)
        ingest.ingest_solidity_text(src, VULN, chain="ethereum", address="0xabc")
        run_scan(src, self.patterns)
        rep = report.build_report(src)
        sarif_path = self.dir / "out.sarif"
        sarif_path.write_text(report.to_sarif(rep), encoding="utf-8")

        original = {(f.pattern_id, f.line) for f in rep.findings}
        self.assertTrue(original)

        # import into a fresh archive
        dst = db.connect(":memory:")
        db.migrate(dst)
        self.addCleanup(dst.close)
        scan_id = interop.import_sarif(dst, sarif_path)

        imported = {
            (r[0], r[1]) for r in dst.execute(
                "SELECT pattern_id, line FROM findings WHERE scan_id = ?", (scan_id,)
            )
        }
        self.assertEqual(imported, original)

    def test_sarif_import_is_valid_json_scan(self):
        sarif_path = self.dir / "x.sarif"
        sarif_path.write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "X", "rules": [
                {"id": "R1", "shortDescription": {"text": "Rule one"}}]}},
                "results": [{"ruleId": "R1", "level": "error",
                             "message": {"text": "boom"},
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "A.sol"},
                                 "region": {"startLine": 7}}}]}]}],
        }), encoding="utf-8")
        conn = db.connect(":memory:")
        db.migrate(conn)
        self.addCleanup(conn.close)
        scan_id = interop.import_sarif(conn, sarif_path)
        row = conn.execute(
            "SELECT pattern_id, line, severity FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        self.assertEqual((row[0], row[1], row[2]), ("R1", 7, "high"))


class SlitherImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "slither.json"
        self.path.write_text(json.dumps(SLITHER), encoding="utf-8")
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)

    def test_import_slither(self):
        scan_id = interop.import_slither(self.conn, self.path)
        rows = self.conn.execute(
            "SELECT pattern_id, severity, line FROM findings WHERE scan_id = ? ORDER BY line",
            (scan_id,)
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "SL-naming-convention")
        self.assertEqual(rows[0][1], "info")
        self.assertEqual(rows[1][0], "SL-reentrancy-eth")
        self.assertEqual(rows[1][1], "high")
        # patterns were registered
        n = self.conn.execute(
            "SELECT COUNT(*) FROM patterns WHERE category = 'SLITHER'"
        ).fetchone()[0]
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
