"""The pattern engine — runs detectors over normalized source, honestly.

Input is **normalized** source (comments/strings stripped, deps dropped — see
:mod:`seshat.normalize`), so brace-balancing and line numbers are reliable.

Matcher mechanics (one unified evaluator behind the four declared kinds):
- ``scope: file`` — match per line over the whole source (default).
- ``scope: function`` — match within each brace-balanced function body, with
  ``requires``/``forbids`` evaluated in that function's text. Used for
  "function with/without modifier" (``function_signature`` / ``ast``) rules.
- ``multiline: true`` — match across the whole source (line taken from the match
  start), for cross-line shapes.
- ``requires`` (all must appear in scope) / ``forbids`` (none may) compose
  detectors into semantic checks without a real parser.

Two honesty contracts: a detector below the **confidence threshold** is skipped,
and findings are **deduped per (pattern, line)**.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import normalize
from .patterns import Detector, Pattern

# `receive`/`fallback` are functions too, but carry no `function` keyword.
_FUNCTION_RE = re.compile(r"\b(?:function|receive|fallback)\b")


@dataclass
class EngineFinding:
    pattern_id: str
    pattern_name: str
    severity: str
    confidence: float
    category: str
    line: int
    snippet: str
    description: str
    recommendation: str
    swc: str = ""
    cwe: str = ""


def iter_function_regions(text: str) -> list[tuple[str, int]]:
    """Yield ``(function_text, base_line)`` for each function body in ``text``.

    Relies on normalized source (no comments/strings) so brace counting is safe.
    Function *declarations* (no body, terminated by ``;``) are skipped.
    """
    regions: list[tuple[str, int]] = []
    n = len(text)
    for m in _FUNCTION_RE.finditer(text):
        j = m.end()
        depth_paren = 0
        brace = -1
        while j < n:
            ch = text[j]
            if ch == "(":
                depth_paren += 1
            elif ch == ")":
                depth_paren -= 1
            elif ch == ";" and depth_paren <= 0:
                break  # declaration only, no body
            elif ch == "{" and depth_paren <= 0:
                brace = j
                break
            j += 1
        if brace == -1:
            continue
        depth = 0
        k = brace
        while k < n:
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        end = min(k + 1, n)
        region = text[m.start():end]
        base_line = text[: m.start()].count("\n") + 1
        regions.append((region, base_line))
    return regions


def _all_present(regexes, text) -> bool:
    return all(rx.search(text) for rx in regexes)


def _any_present(regexes, text) -> bool:
    return any(rx.search(text) for rx in regexes)


def _detector_hits(det: Detector, text: str) -> list[int]:
    """Return the line numbers (1-based) where ``det`` fires in ``text``."""
    if det._rx is None:
        det.compile()

    if det.scope == "function":
        hits: list[int] = []
        for region, base_line in iter_function_regions(text):
            if det._req and not _all_present(det._req, region):
                continue
            if det._forb and _any_present(det._forb, region):
                continue
            # flag the function once, at the first matching line
            for idx, line in enumerate(region.split("\n")):
                if det._rx.search(line):
                    hits.append(base_line + idx)
                    break
        return hits

    # file scope: requires/forbids evaluated over the whole source
    if det._req and not _all_present(det._req, text):
        return []
    if det._forb and _any_present(det._forb, text):
        return []

    if det.multiline:
        return [text[: m.start()].count("\n") + 1 for m in det._rx.finditer(text)]

    hits = []
    for idx, line in enumerate(text.split("\n")):
        if det._rx.search(line):
            hits.append(idx + 1)
    return hits


def scan_source(
    text: str,
    patterns: list[Pattern],
    *,
    min_confidence: float = 0.0,
) -> list[EngineFinding]:
    """Scan one normalized source blob, returning deduped findings.

    Dedup is per ``(pattern_id, line)``; the highest-confidence detector wins.
    """
    lines = text.split("\n")
    best: dict[tuple[str, int], EngineFinding] = {}

    for pat in patterns:
        for det in pat.detectors:
            if det.confidence < min_confidence:
                continue
            for line_no in _detector_hits(det, text):
                key = (pat.id, line_no)
                snippet = lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else ""
                cand = EngineFinding(
                    pattern_id=pat.id,
                    pattern_name=pat.name,
                    severity=pat.severity,
                    confidence=det.confidence,
                    category=pat.category,
                    line=line_no,
                    snippet=snippet,
                    description=det.description,
                    recommendation=det.recommendation,
                    swc=pat.swc,
                    cwe=pat.cwe,
                )
                prev = best.get(key)
                if prev is None or cand.confidence > prev.confidence:
                    best[key] = cand

    return sorted(best.values(), key=lambda f: (f.line, f.pattern_id))


def scan_snippet(src: str, pattern: Pattern) -> list[EngineFinding]:
    """Normalize a raw Solidity snippet and scan it with a single pattern."""
    norm = normalize.normalize_text(src)
    return scan_source(norm.content, [pattern], min_confidence=0.0)


def check_pattern_fixtures(pattern: Pattern) -> list[str]:
    """Verify a pattern's inline fixtures: positives fire, negatives stay quiet.

    Returns a list of failure messages (empty ⇒ the pattern proves itself).
    """
    failures: list[str] = []
    for i, src in enumerate(pattern.positive):
        hits = [f for f in scan_snippet(src, pattern) if f.pattern_id == pattern.id]
        if not hits:
            failures.append(f"{pattern.id}: positive fixture #{i + 1} did not fire")
    for i, src in enumerate(pattern.negative):
        hits = [f for f in scan_snippet(src, pattern) if f.pattern_id == pattern.id]
        if hits:
            lines = sorted({h.line for h in hits})
            failures.append(
                f"{pattern.id}: negative fixture #{i + 1} false-positived at lines {lines}"
            )
    return failures
