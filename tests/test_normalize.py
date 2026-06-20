"""Normalizer unit tests — the anti-inflation core (ported from MaatEye)."""

import unittest

from seshat import normalize


class StripTests(unittest.TestCase):
    def test_line_numbers_preserved(self):
        src = (
            "contract A {\n"
            "    // a line comment\n"
            "    uint x = 1; /* trailing */\n"
            "    /* multi\n"
            "       line */\n"
            "    function f() public {}\n"
            "}\n"
        )
        out = normalize.strip_comments_and_strings(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertNotIn("line comment", out)
        self.assertNotIn("multi", out)
        self.assertIn("contract A", out)
        self.assertIn("function f", out)

    def test_string_literals_blanked(self):
        src = 'string s = "hello // not a comment /* nor this */";'
        out = normalize.strip_comments_and_strings(src)
        self.assertNotIn("hello", out)
        self.assertIn("string s", out)
        # the // inside the string must NOT have started a comment
        self.assertIn(";", out)

    def test_escaped_quote_in_string(self):
        src = r'string s = "a\"b"; uint y = 2;'
        out = normalize.strip_comments_and_strings(src)
        self.assertIn("uint y", out)  # parser didn't get stuck inside the string

    def test_normalize_text_line_count(self):
        src = "a\nb\nc"
        ns = normalize.normalize_text(src)
        self.assertEqual(ns.lines, 3)


class FlattenTests(unittest.TestCase):
    def test_plain_solidity(self):
        files = normalize.flatten_standard_json("contract X {}")
        self.assertEqual(files, {"Contract.sol": "contract X {}"})

    def test_standard_json(self):
        data = {
            "language": "Solidity",
            "sources": {"A.sol": {"content": "contract A {}"}},
        }
        self.assertEqual(normalize.flatten_standard_json(data), {"A.sol": "contract A {}"})

    def test_etherscan_double_brace(self):
        text = '{{"language":"Solidity","sources":{"B.sol":{"content":"contract B {}"}}}}'
        self.assertEqual(normalize.flatten_standard_json(text), {"B.sol": "contract B {}"})

    def test_bare_multifile_map(self):
        text = '{"A.sol":{"content":"contract A {}"},"B.sol":{"content":"contract B {}"}}'
        files = normalize.flatten_standard_json(text)
        self.assertEqual(set(files), {"A.sol", "B.sol"})


class DependencyTests(unittest.TestCase):
    def test_dependency_paths(self):
        for p in (
            "lib/openzeppelin-contracts/ERC20.sol",
            "@openzeppelin/contracts/token/ERC20.sol",
            "node_modules/@uniswap/v3/Pool.sol",
            "lib/solmate/src/tokens/ERC20.sol",
            "lib/forge-std/Test.sol",
        ):
            self.assertTrue(normalize.is_dependency_path(p), p)

    def test_project_paths_kept(self):
        for p in ("src/Token.sol", "contracts/Vault.sol", "MyContract.sol"):
            self.assertFalse(normalize.is_dependency_path(p), p)

    def test_select_drops_deps_but_never_everything(self):
        files = {
            "src/Token.sol": "contract Token {}",
            "lib/openzeppelin/ERC20.sol": "contract ERC20 {}",
        }
        kept = normalize.select_analyzed_files(files)
        self.assertEqual(set(kept), {"src/Token.sol"})
        # all-deps input keeps everything rather than analyzing nothing
        all_deps = {"lib/oz/A.sol": "x", "node_modules/b.sol": "y"}
        self.assertEqual(normalize.select_analyzed_files(all_deps), all_deps)


class HashAndPipelineTests(unittest.TestCase):
    def test_combine_is_deterministic(self):
        files = {"b.sol": "B", "a.sol": "A"}
        self.assertEqual(normalize.combine_sources(files), "A\nB")

    def test_source_hash_stable(self):
        self.assertEqual(
            normalize.source_hash("contract A {}"),
            normalize.source_hash("contract A {}"),
        )
        self.assertNotEqual(
            normalize.source_hash("contract A {}"),
            normalize.source_hash("contract B {}"),
        )

    def test_normalize_input_drops_deps(self):
        data = {
            "sources": {
                "src/Token.sol": {"content": "contract Token { uint x; }"},
                "lib/oz/ERC20.sol": {"content": "contract ERC20 { uint y; }"},
            }
        }
        raw, norm = normalize.normalize_input(data)
        self.assertIn("Token", raw)
        self.assertNotIn("ERC20", raw)
        self.assertGreater(norm.lines, 0)

    def test_guess_contract_name_capped(self):
        long_name = "C" * 200
        name = normalize.guess_contract_name(f"contract {long_name} {{}}")
        self.assertEqual(len(name), normalize.MAX_IDENT)


if __name__ == "__main__":
    unittest.main()
