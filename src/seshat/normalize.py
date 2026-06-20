"""Source normalization — ported & hardened from MaatEye.

Why this exists: scanning bundled dependencies, comments, and string literals
inflated MaatEye's findings ~10×. Before any pattern runs, source must be:

1. **Flattened** — Standard-JSON (incl. Etherscan's ``{{…}}`` wrapper) and
   multi-file inputs collapse to a deterministic, sorted set of files.
2. **Dependency-dropped** — vendored libraries (OpenZeppelin, solmate, …) are
   excluded from analysis scope.
3. **Comment/string-stripped** — comments and string/char literals are blanked
   **while preserving line numbers**, so a finding's line still points at the
   real source line.

All functions here are pure: no DB, no network.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import NamedTuple

MAX_IDENT = 80  # filesystem-safety cap (CLAUDE.md): identifiers/names ≤ 80 chars

# Vendor name fragments that mark a vendored dependency anywhere in the path.
# Matched case-insensitively. Kept broad — MaatEye's lesson is that
# *under*-dropping inflates findings far more than over-dropping costs.
_DEPENDENCY_VENDORS: tuple[str, ...] = (
    "@openzeppelin",
    "openzeppelin-contracts",
    "openzeppelin/",
    "@uniswap",
    "uniswap/",
    "@chainlink",
    "chainlink/",
    "@aave",
    "aave-",
    "@layerzero",
    "layerzerolabs",
    "solmate",
    "solady",
    "forge-std",
    "ds-test",
    "@arbitrum",
    "@eth-optimism",
    "@gnosis",
    "@safe-global",
    "prb-math",
    "@prb",
    "erc4626",
)

# Directory names that, as the FIRST path segment, mark a dependency tree:
# Foundry vendors deps under top-level ``lib/``. (Not matched mid-path, so a
# project's own ``contracts/lib/Math.sol`` is still analyzed.)
_DEPENDENCY_ROOT_DIRS: frozenset[str] = frozenset({"lib"})

# Directory names that mark a dependency anywhere in the path.
_DEPENDENCY_ANY_DIRS: frozenset[str] = frozenset({"node_modules"})


class NormalizedSource(NamedTuple):
    content: str  # comment/string-stripped, line-numbers preserved
    lines: int  # 1-based line count of `content`


def _slash(path: str) -> str:
    return path.replace("\\", "/")


def is_dependency_path(path: str) -> bool:
    """True if ``path`` looks like a vendored dependency to exclude from scope."""
    p = _slash(path).lower().lstrip("./")
    segments = p.split("/")
    if segments and segments[0] in _DEPENDENCY_ROOT_DIRS:
        return True
    if any(seg in _DEPENDENCY_ANY_DIRS for seg in segments):
        return True
    return any(vendor in p for vendor in _DEPENDENCY_VENDORS)


def flatten_standard_json(data: str | dict) -> dict[str, str]:
    """Collapse any supported source representation to ``{path: content}``.

    Handles: a plain Solidity string, Etherscan's double-brace ``{{…}}`` wrapper,
    Solidity Standard-JSON (``{"sources": {path: {"content": …}}}``), and the
    bare multi-file ``{path: {"content": …}}`` / ``{path: "…"}`` forms.
    """
    obj: object
    if isinstance(data, str):
        s = data.strip()
        # Etherscan wraps Standard-JSON input in an extra pair of braces.
        if s.startswith("{{") and s.endswith("}}"):
            s = s[1:-1]
        try:
            obj = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            # Not JSON → a single flat Solidity file.
            return {"Contract.sol": data}
    else:
        obj = data

    if not isinstance(obj, dict):
        return {"Contract.sol": data if isinstance(data, str) else json.dumps(data)}

    sources = obj.get("sources", obj) if isinstance(obj, dict) else obj
    files: dict[str, str] = {}
    if isinstance(sources, dict):
        for path, entry in sources.items():
            if isinstance(entry, dict) and "content" in entry:
                files[path] = entry["content"]
            elif isinstance(entry, str):
                files[path] = entry

    if not files:
        # Looked like JSON but carried no source files; treat original as text.
        return {"Contract.sol": data if isinstance(data, str) else json.dumps(data)}
    return files


def select_analyzed_files(files: dict[str, str]) -> dict[str, str]:
    """Drop dependency files. If *everything* is a dependency, keep all (so we
    never silently analyze nothing)."""
    kept = {p: c for p, c in files.items() if not is_dependency_path(p)}
    return kept or dict(files)


def combine_sources(files: dict[str, str]) -> str:
    """Concatenate kept files in **sorted path order** (deterministic)."""
    return "\n".join(files[p] for p in sorted(files))


def strip_comments_and_strings(src: str) -> str:
    """Blank out comments and string/char literals, preserving every newline so
    line numbers are stable. A tiny state machine (no regex — Solidity strings
    can contain ``//`` and comments can contain quotes)."""
    out: list[str] = []
    i, n = 0, len(src)
    state = "code"  # code | line_comment | block_comment | string
    quote = ""
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
            elif c == "/" and nxt == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
            elif c in ('"', "'"):
                state = "string"
                quote = c
                out.append(" ")
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        else:  # string
            if c == "\\" and nxt:
                out.append("  ")
                i += 2
            elif c == quote:
                state = "code"
                out.append(" ")
                i += 1
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
    return "".join(out)


def normalize_text(raw: str) -> NormalizedSource:
    """Strip comments/strings from already-combined source and count lines."""
    content = strip_comments_and_strings(raw)
    lines = content.count("\n") + 1 if content else 0
    return NormalizedSource(content=content, lines=lines)


def normalize_input(data: str | dict) -> tuple[str, NormalizedSource]:
    """Full pipeline: flatten → drop deps → combine → strip.

    Returns ``(raw_combined, normalized)`` where ``raw_combined`` is the kept
    files concatenated (un-stripped) and ``normalized`` is the analyzed blob.
    """
    files = flatten_standard_json(data)
    kept = select_analyzed_files(files)
    raw_combined = combine_sources(kept)
    return raw_combined, normalize_text(raw_combined)


def source_hash(content: str) -> str:
    """Stable content hash (sha256 hex) used as the dedup key."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


_CONTRACT_RE = re.compile(
    r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)", re.MULTILINE
)


def guess_contract_name(raw: str, fallback: str = "Contract") -> str:
    """Best-effort top contract/library/interface name, capped at 80 chars."""
    m = _CONTRACT_RE.search(raw)
    name = m.group(1) if m else fallback
    return name[:MAX_IDENT]
