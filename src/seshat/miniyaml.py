"""A tiny, dependency-free YAML *subset* loader.

Seshat's core is stdlib-only (CLAUDE.md), so we don't pull in PyYAML. Pattern
files use a deliberately small YAML subset that this module parses:

- nested **maps** and **lists**, by 2-space indentation;
- scalars: plain, ``'single-quoted'`` (backslashes literal — ideal for regex),
  and ``"double-quoted"`` (with ``\\n \\t \\\\ \\"`` escapes);
- ``true``/``false`` → bool, ``null``/``~`` → None, ints and floats;
- ``#`` comments (whole-line, and trailing on plain/closed-quote scalars).

It does **not** support: block scalars (``|`` / ``>``), anchors/aliases, flow
collections (``[a, b]`` / ``{a: b}``), or multi-document streams. Pattern files
stay within the subset; the validator rejects anything that doesn't round-trip
into the expected shape.
"""

from __future__ import annotations

import re
from typing import Any

_KV_RE = re.compile(r"^[\w.-]+:(\s|$)")


class MiniYAMLError(ValueError):
    pass


def load(path) -> Any:
    from pathlib import Path

    return loads(Path(path).read_text(encoding="utf-8"))


def loads(text: str) -> Any:
    items: list[tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise MiniYAMLError("tabs are not allowed for indentation")
        indent = len(raw) - len(raw.lstrip(" "))
        items.append((indent, stripped))
    if not items:
        return None
    value, _ = _parse_block(items, 0, items[0][0])
    return value


def _parse_block(items, i, indent):
    if items[i][1].startswith("-"):
        return _parse_list(items, i, indent)
    return _parse_map(items, i, indent)


def _parse_map(items, i, indent):
    result: dict[str, Any] = {}
    while i < len(items):
        ind, content = items[i]
        if ind != indent or content.startswith("- ") or content == "-":
            break
        key, val = _split_kv(content)
        if val == "":
            if i + 1 < len(items) and items[i + 1][0] > indent:
                child, i = _parse_block(items, i + 1, items[i + 1][0])
                result[key] = child
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _parse_scalar(val)
            i += 1
    return result, i


def _parse_list(items, i, indent):
    result: list[Any] = []
    while i < len(items):
        ind, content = items[i]
        if ind != indent or not (content == "-" or content.startswith("- ")):
            break
        after = content[1:].lstrip()
        # column where `after` begins: dash indent + 1 (the '-') + spaces stripped
        after_indent = ind + 1 + (len(content[1:]) - len(after))
        if after == "":
            if i + 1 < len(items) and items[i + 1][0] > indent:
                child, i = _parse_block(items, i + 1, items[i + 1][0])
                result.append(child)
            else:
                result.append(None)
                i += 1
        elif _KV_RE.match(after):
            synthetic = [(after_indent, after)] + items[i + 1 :]
            node, consumed = _parse_map(synthetic, 0, after_indent)
            i = i + consumed
            result.append(node)
        else:
            result.append(_parse_scalar(after))
            i += 1
    return result, i


def _split_kv(content: str) -> tuple[str, str]:
    idx = content.find(":")
    if idx == -1:
        raise MiniYAMLError(f"expected 'key: value', got: {content!r}")
    return content[:idx].strip(), content[idx + 1 :].strip()


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if not s:
        return None
    if s[0] == "'":
        return _read_single_quoted(s)
    if s[0] == '"':
        return _read_double_quoted(s)
    # plain scalar — strip a trailing comment
    hash_pos = s.find(" #")
    if hash_pos != -1:
        s = s[:hash_pos].rstrip()
    low = s.lower()
    if low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _read_single_quoted(s: str) -> str:
    out: list[str] = []
    i = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "'":
            if i + 1 < n and s[i + 1] == "'":  # '' → literal '
                out.append("'")
                i += 2
                continue
            return "".join(out)  # closing quote; ignore trailing comment
        out.append(c)
        i += 1
    raise MiniYAMLError(f"unterminated single-quoted scalar: {s!r}")


def _read_double_quoted(s: str) -> str:
    out: list[str] = []
    i = 1
    n = len(s)
    escapes = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "r": "\r", "0": "\0"}
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            out.append(escapes.get(s[i + 1], s[i + 1]))
            i += 2
            continue
        if c == '"':
            return "".join(out)
        out.append(c)
        i += 1
    raise MiniYAMLError(f"unterminated double-quoted scalar: {s!r}")
