"""Engine mechanics: scope, requires/forbids, threshold, dedup, line numbers."""

import unittest

from seshat import engine
from seshat.patterns import Detector, Pattern


def _pat(pid, detectors, severity="high", category="EXTERNAL_CALLS"):
    return Pattern(
        id=pid, name=pid, severity=severity, category=category,
        confidence=0.5, detectors=detectors,
        positive=["x"], negative=["y"],
    )


def _det(pattern, **kw):
    d = Detector(type=kw.pop("type", "regex"), pattern=pattern,
                 confidence=kw.pop("confidence", 0.7), **kw)
    d.compile()
    return d


class FunctionRegionTests(unittest.TestCase):
    def test_extracts_bodies_and_skips_declarations(self):
        text = (
            "interface I { function decl() external; }\n"
            "contract C {\n"
            "  function a() public { uint x; }\n"
            "  function b() public { uint y; }\n"
            "}\n"
        )
        regions = engine.iter_function_regions(text)
        # only the two real bodies, not the interface declaration
        self.assertEqual(len(regions), 2)
        self.assertIn("uint x", regions[0][0])
        self.assertEqual(regions[0][1], 3)  # base line of function a

    def test_nested_braces_balanced(self):
        text = "contract C {\n function f() public { if (true) { while(false){} } }\n}\n"
        regions = engine.iter_function_regions(text)
        self.assertEqual(len(regions), 1)
        self.assertTrue(regions[0][0].count("{") == regions[0][0].count("}"))


class ScopeTests(unittest.TestCase):
    def test_function_scope_forbids_guard(self):
        pat = _pat("P900", [_det(r"\.call\{", scope="function", forbids=["nonReentrant"])])
        vuln = "contract C { function f() public { a.call{value:1}(\"\"); } }"
        safe = "contract C { function f() public nonReentrant { a.call{value:1}(\"\"); } }"
        self.assertEqual(len(engine.scan_source(vuln, [pat])), 1)
        self.assertEqual(len(engine.scan_source(safe, [pat])), 0)

    def test_function_scope_requires(self):
        pat = _pat("P901", [_det(r"function\s+f", scope="function", requires=["selfdestruct"])])
        with_sd = "contract C { function f() public { selfdestruct(payable(msg.sender)); } }"
        without = "contract C { function f() public { uint x; } }"
        self.assertEqual(len(engine.scan_source(with_sd, [pat])), 1)
        self.assertEqual(len(engine.scan_source(without, [pat])), 0)

    def test_function_flagged_once(self):
        # pattern could match twice in one function, but scope=function flags once
        pat = _pat("P902", [_det(r"\.call", scope="function")])
        src = "contract C { function f() public { a.call(); b.call(); } }"
        self.assertEqual(len(engine.scan_source(src, [pat])), 1)


class FileScopeTests(unittest.TestCase):
    def test_per_line_line_numbers(self):
        pat = _pat("P903", [_det(r"selfdestruct")])
        src = "contract C {\n  function f() public {\n    selfdestruct(payable(0));\n  }\n}\n"
        finds = engine.scan_source(src, [pat])
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].line, 3)

    def test_multiline_match(self):
        pat = _pat("P904", [_det(r"a\s*=\s*b", multiline=True)])
        src = "contract C {\n uint a =\n   b;\n}\n"
        finds = engine.scan_source(src, [pat])
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].line, 2)  # match starts on line 2


class ThresholdAndDedupTests(unittest.TestCase):
    def test_confidence_threshold_drops_detector(self):
        pat = _pat("P905", [_det(r"selfdestruct", confidence=0.3)])
        src = "contract C { function f() public { selfdestruct(payable(0)); } }"
        self.assertEqual(len(engine.scan_source(src, [pat], min_confidence=0.5)), 0)
        self.assertEqual(len(engine.scan_source(src, [pat], min_confidence=0.2)), 1)

    def test_dedup_per_pattern_line_keeps_highest_confidence(self):
        pat = _pat("P906", [
            _det(r"selfdestruct", confidence=0.4),
            _det(r"self\w+", confidence=0.9),
        ])
        src = "contract C { function f() public { selfdestruct(payable(0)); } }"
        finds = engine.scan_source(src, [pat])
        self.assertEqual(len(finds), 1)  # same (pattern, line) deduped
        self.assertEqual(finds[0].confidence, 0.9)

    def test_two_patterns_same_line_not_deduped(self):
        p1 = _pat("P907", [_det(r"selfdestruct")])
        p2 = _pat("P908", [_det(r"payable")])
        src = "contract C { function f() public { selfdestruct(payable(0)); } }"
        finds = engine.scan_source(src, [p1, p2])
        self.assertEqual(len(finds), 2)


if __name__ == "__main__":
    unittest.main()
