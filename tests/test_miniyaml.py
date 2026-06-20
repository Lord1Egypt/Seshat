"""Tests for the zero-dep YAML subset loader."""

import unittest

from seshat import miniyaml


class ScalarTests(unittest.TestCase):
    def test_types(self):
        d = miniyaml.loads(
            "a: 1\nb: 1.5\nc: true\nd: false\ne: null\nf: hello\ng: ~\n"
        )
        self.assertEqual(d, {
            "a": 1, "b": 1.5, "c": True, "d": False,
            "e": None, "f": "hello", "g": None,
        })

    def test_single_quoted_keeps_backslashes(self):
        d = miniyaml.loads(r"pattern: '\.call\{[^}]*\}\s*\('")
        self.assertEqual(d["pattern"], r"\.call\{[^}]*\}\s*\(")

    def test_single_quote_escape(self):
        d = miniyaml.loads("msg: 'it''s fine'")
        self.assertEqual(d["msg"], "it's fine")

    def test_double_quoted_escapes(self):
        d = miniyaml.loads(r'msg: "line1\nline2\ttab"')
        self.assertEqual(d["msg"], "line1\nline2\ttab")

    def test_trailing_comment_on_plain(self):
        d = miniyaml.loads("severity: critical   # the worst\nx: 5 # five")
        self.assertEqual(d, {"severity": "critical", "x": 5})

    def test_trailing_comment_after_quote(self):
        d = miniyaml.loads("pattern: '\\.call'   # a comment")
        self.assertEqual(d["pattern"], "\\.call")

    def test_colon_in_quoted_value(self):
        d = miniyaml.loads("swc: 'SWC-107: reentrancy'")
        self.assertEqual(d["swc"], "SWC-107: reentrancy")


class StructureTests(unittest.TestCase):
    def test_nested_map(self):
        d = miniyaml.loads("fixtures:\n  positive:\n    - 'a'\n    - 'b'\n")
        self.assertEqual(d, {"fixtures": {"positive": ["a", "b"]}})

    def test_list_of_maps(self):
        text = (
            "detectors:\n"
            "  - type: regex\n"
            "    pattern: '\\.call'\n"
            "    confidence: 0.75\n"
            "  - type: semantic\n"
            "    pattern: 'mint'\n"
        )
        d = miniyaml.loads(text)
        self.assertEqual(len(d["detectors"]), 2)
        self.assertEqual(d["detectors"][0], {
            "type": "regex", "pattern": "\\.call", "confidence": 0.75,
        })
        self.assertEqual(d["detectors"][1]["type"], "semantic")

    def test_list_of_maps_with_nested_list(self):
        text = (
            "detectors:\n"
            "  - type: regex\n"
            "    pattern: 'p'\n"
            "    forbids:\n"
            "      - 'onlyOwner'\n"
            "      - 'onlyRole'\n"
            "    confidence: 0.8\n"
        )
        d = miniyaml.loads(text)
        det = d["detectors"][0]
        self.assertEqual(det["forbids"], ["onlyOwner", "onlyRole"])
        self.assertEqual(det["confidence"], 0.8)
        self.assertEqual(det["pattern"], "p")

    def test_full_pattern_shape(self):
        text = (
            "id: P017\n"
            "name: Arbitrary External Call\n"
            "severity: critical\n"
            "category: EXTERNAL_CALLS\n"
            "confidence: 0.75\n"
            "swc: SWC-112\n"
            "detectors:\n"
            "  - type: regex\n"
            "    pattern: '\\.call\\{[^}]*\\}'\n"
            "    confidence: 0.75\n"
            "    description: 'low-level call'\n"
            "tests:\n"
            "  positive:\n"
            "    - 'contract C { function f() { x.call{value: 1}(\"\"); } }'\n"
            "  negative:\n"
            "    - 'contract C {}'\n"
        )
        d = miniyaml.loads(text)
        self.assertEqual(d["id"], "P017")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["detectors"][0]["pattern"], "\\.call\\{[^}]*\\}")
        self.assertEqual(len(d["tests"]["positive"]), 1)
        self.assertEqual(d["tests"]["negative"], ["contract C {}"])

    def test_tabs_rejected(self):
        with self.assertRaises(miniyaml.MiniYAMLError):
            miniyaml.loads("a:\n\t- 1\n")

    def test_empty(self):
        self.assertIsNone(miniyaml.loads("\n# only a comment\n"))


if __name__ == "__main__":
    unittest.main()
