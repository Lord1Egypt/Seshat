"""Plugin system tests — drop-in patterns load without touching core."""

import tempfile
import unittest
from pathlib import Path

from seshat import engine, patterns

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "plugins"

PLUGIN = """
id: P950
name: Test Plugin Pattern
severity: medium
category: BUSINESS_LOGIC
confidence: 0.7
detectors:
  - type: regex
    pattern: 'dangerousThing\\s*\\('
    confidence: 0.7
    description: 'a test smell'
tests:
  positive:
    - 'contract C { function f() public { dangerousThing(); } }'
  negative:
    - 'contract C { uint x; }'
"""


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        (self.dir / "P950_test.yaml").write_text(PLUGIN, encoding="utf-8")

    def test_plugin_loaded_alongside_bundled(self):
        base = patterns.load_catalog()
        merged = patterns.load_catalog(extra_dirs=[self.dir])
        self.assertEqual(len(merged), len(base) + 1)
        self.assertIn("P950", {p.id for p in merged})

    def test_dropped_in_pattern_fires_without_core_changes(self):
        merged = patterns.load_catalog(extra_dirs=[self.dir])
        pat = next(p for p in merged if p.id == "P950")
        finds = engine.scan_snippet("contract C { function f() public { dangerousThing(); } }", pat)
        self.assertTrue(any(f.pattern_id == "P950" for f in finds))

    def test_duplicate_id_is_rejected(self):
        dup = self.dir / "dup.yaml"
        dup.write_text(PLUGIN.replace("P950", "P001"), encoding="utf-8")  # collides with bundled
        with self.assertRaises(patterns.PatternError):
            patterns.load_catalog(extra_dirs=[self.dir])

    def test_shipped_example_plugin_is_valid(self):
        self.assertTrue(EXAMPLES.is_dir())
        pats = patterns.load_patterns(EXAMPLES)
        self.assertTrue(pats)
        for p in pats:
            self.assertEqual(patterns.validate_pattern(p), [])
            self.assertEqual(engine.check_pattern_fixtures(p), [])


if __name__ == "__main__":
    unittest.main()
