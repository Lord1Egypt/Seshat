"""Reporting tests — builder + all exporters."""

import csv
import io
import json
import unittest

from seshat import db, ingest, report
from seshat.patterns import default_catalog_dir, load_patterns
from seshat.scan import run_scan

VULN = (
    "contract Vuln {\n"
    "  mapping(address=>uint) bal;\n"
    "  function mint(address to, uint a) public { bal[to]+=a; }\n"
    "  function kill() public { selfdestruct(payable(msg.sender)); }\n"
    "}\n"
)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns(default_catalog_dir())

    def setUp(self):
        self.conn = db.connect(":memory:")
        db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        ingest.ingest_solidity_text(self.conn, VULN, chain="ethereum", address="0xfeed")
        self.scan_id = run_scan(self.conn, self.patterns).scan_id
        self.report = report.build_report(self.conn)

    def test_build_report_basics(self):
        self.assertEqual(self.report.scan_id, self.scan_id)
        self.assertGreater(self.report.total_findings, 0)
        self.assertGreater(self.report.by_severity.get("critical", 0), 0)
        # sorted critical-first
        self.assertEqual(self.report.findings[0].severity, "critical")

    def test_min_severity_filter(self):
        crit = report.build_report(self.conn, min_severity="critical")
        self.assertTrue(all(f.severity == "critical" for f in crit.findings))
        self.assertLessEqual(crit.total_findings, self.report.total_findings)

    def test_json_valid_and_framed(self):
        payload = json.loads(report.to_json(self.report))
        self.assertEqual(payload["tool"], "seshat")
        self.assertIn("review flags", payload["disclaimer"].lower())
        self.assertEqual(len(payload["findings"]), self.report.total_findings)

    def test_csv_roundtrips(self):
        rows = list(csv.reader(io.StringIO(report.to_csv(self.report))))
        self.assertEqual(rows[0][0], "severity")
        self.assertEqual(len(rows) - 1, self.report.total_findings)

    def test_markdown_has_disclaimer_and_table(self):
        md = report.to_markdown(self.report)
        self.assertIn("REVIEW FLAGS", md)
        self.assertIn("| Severity |", md)
        self.assertIn("P001", md)

    def test_sarif_shape_valid(self):
        s = json.loads(report.to_sarif(self.report))
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("$schema", s)
        run = s["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Seshat")
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertEqual(len(run["results"]), self.report.total_findings)
        r0 = run["results"][0]
        self.assertIn(r0["level"], ("error", "warning", "note"))
        self.assertTrue(r0["ruleId"])
        self.assertGreaterEqual(
            r0["locations"][0]["physicalLocation"]["region"]["startLine"], 1
        )
        # rule ids referenced by results must exist in the driver rules
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)

    def test_html_self_contained_offline(self):
        h = report.to_html(self.report)
        self.assertTrue(h.lstrip().startswith("<!doctype html>"))
        # no external resources — fully offline
        self.assertNotIn("http://", h)
        self.assertNotIn("src=", h)
        self.assertNotIn("<link", h)
        self.assertIn("review flags", h.lower())
        self.assertIn("P001", h)

    def test_table_view(self):
        t = report.to_table(self.report)
        self.assertIn("Seshat", t)
        self.assertIn("CRITICAL", t)
        # no ANSI codes when color is off
        self.assertNotIn("\033[", t)

    def test_empty_scan_report(self):
        clean = db.connect(":memory:")
        db.migrate(clean)
        self.addCleanup(clean.close)
        ingest.ingest_solidity_text(clean, "contract Ok { uint x; }")
        run_scan(clean, self.patterns)
        rep = report.build_report(clean)
        # exporters must not crash on zero findings
        self.assertIn("No review flags", report.to_markdown(rep))
        json.loads(report.to_json(rep))
        json.loads(report.to_sarif(rep))
        self.assertIn("<!doctype html>", report.to_html(rep))


if __name__ == "__main__":
    unittest.main()
