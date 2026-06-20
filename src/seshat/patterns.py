"""Pattern model, loader, and validator.

A pattern is a small YAML file (loaded by :mod:`seshat.miniyaml`) describing one
detection rule plus its labeled fixtures. Patterns are self-contained: positive
and negative fixtures live **inline** under ``tests:`` so each pattern proves
itself (TP fires, FP stays quiet) without scattering .sol files.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import miniyaml

SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = (
    "ACCESS_CONTROL",
    "REENTRANCY",
    "EXTERNAL_CALLS",
    "PROXY_UPGRADEABLE",
    "ARITHMETIC",
    "TOKEN_ECONOMICS",
    "GOVERNANCE",
    "SIGNATURE_CRYPTO",
    "TIME_RANDOMNESS",
    "BUSINESS_LOGIC",
    "ERC_STANDARDS",
    "BYTECODE_LOWLEVEL",
)
DETECTOR_TYPES = ("regex", "function_signature", "ast", "semantic")


class PatternError(ValueError):
    pass


@dataclass
class Detector:
    type: str
    pattern: str
    confidence: float
    description: str = ""
    recommendation: str = ""
    scope: str = "file"  # file | function
    multiline: bool = False
    requires: list[str] = field(default_factory=list)
    forbids: list[str] = field(default_factory=list)
    _rx: re.Pattern | None = field(default=None, repr=False, compare=False)
    _req: list[re.Pattern] = field(default_factory=list, repr=False, compare=False)
    _forb: list[re.Pattern] = field(default_factory=list, repr=False, compare=False)

    def compile(self) -> None:
        self._rx = re.compile(self.pattern)
        self._req = [re.compile(r) for r in self.requires]
        self._forb = [re.compile(r) for r in self.forbids]


@dataclass
class Pattern:
    id: str
    name: str
    severity: str
    category: str
    confidence: float
    detectors: list[Detector]
    swc: str = ""
    cwe: str = ""
    version: str = "1"
    references: list[str] = field(default_factory=list)
    positive: list[str] = field(default_factory=list)
    negative: list[str] = field(default_factory=list)
    source_path: str | None = None


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def pattern_from_dict(data: dict, source_path: str | None = None) -> Pattern:
    if not isinstance(data, dict):
        raise PatternError(f"{source_path}: pattern must be a mapping")
    try:
        raw_detectors = data["detectors"]
    except KeyError as exc:
        raise PatternError(f"{source_path}: missing 'detectors'") from exc
    if not isinstance(raw_detectors, list) or not raw_detectors:
        raise PatternError(f"{source_path}: 'detectors' must be a non-empty list")

    default_conf = float(data.get("confidence", 0.5))
    detectors: list[Detector] = []
    for d in raw_detectors:
        if not isinstance(d, dict) or "pattern" not in d:
            raise PatternError(f"{source_path}: each detector needs a 'pattern'")
        det = Detector(
            type=str(d.get("type", "regex")),
            pattern=str(d["pattern"]),
            confidence=float(d.get("confidence", default_conf)),
            description=str(d.get("description", "")),
            recommendation=str(d.get("recommendation", "")),
            scope=str(d.get("scope", "file")),
            multiline=bool(d.get("multiline", False)),
            requires=_as_list(d.get("requires")),
            forbids=_as_list(d.get("forbids")),
        )
        detectors.append(det)

    tests = data.get("tests") or {}
    fixtures = data.get("fixtures") or {}
    return Pattern(
        id=str(data.get("id", "")),
        name=str(data.get("name", "")),
        severity=str(data.get("severity", "")).lower(),
        category=str(data.get("category", "")).upper(),
        confidence=default_conf,
        detectors=detectors,
        swc=str(data.get("swc", "") or ""),
        cwe=str(data.get("cwe", "") or ""),
        version=str(data.get("version", "1")),
        references=_as_list(data.get("references")),
        positive=_as_list(tests.get("positive")) + _as_list(fixtures.get("positive")),
        negative=_as_list(tests.get("negative")) + _as_list(fixtures.get("negative")),
        source_path=source_path,
    )


def load_pattern_file(path: str | Path) -> Pattern:
    path = Path(path)
    data = miniyaml.loads(path.read_text(encoding="utf-8"))
    pat = pattern_from_dict(data, source_path=str(path))
    for det in pat.detectors:
        det.compile()
    return pat


def load_patterns(directory: str | Path) -> list[Pattern]:
    """Load every ``*.yaml``/``*.yml`` pattern under ``directory`` (sorted by id)."""
    directory = Path(directory)
    files = sorted(
        p for p in directory.rglob("*.y*ml") if p.is_file()
    )
    patterns = [load_pattern_file(p) for p in files]
    patterns.sort(key=lambda p: p.id)
    return patterns


def validate_pattern(pat: Pattern) -> list[str]:
    """Return a list of human-readable problems (empty ⇒ valid)."""
    errs: list[str] = []
    where = pat.source_path or pat.id or "<pattern>"
    if not re.fullmatch(r"P\d{3}", pat.id):
        errs.append(f"{where}: id must look like 'P017', got {pat.id!r}")
    if not pat.name:
        errs.append(f"{where}: missing name")
    if pat.severity not in SEVERITIES:
        errs.append(f"{where}: severity {pat.severity!r} not in {SEVERITIES}")
    if pat.category not in CATEGORIES:
        errs.append(f"{where}: category {pat.category!r} not in taxonomy")
    if not (0.0 <= pat.confidence <= 1.0):
        errs.append(f"{where}: confidence {pat.confidence} out of [0,1]")
    for det in pat.detectors:
        if det.type not in DETECTOR_TYPES:
            errs.append(f"{where}: detector type {det.type!r} unknown")
        if det.scope not in ("file", "function"):
            errs.append(f"{where}: detector scope {det.scope!r} invalid")
        if not (0.0 <= det.confidence <= 1.0):
            errs.append(f"{where}: detector confidence {det.confidence} out of [0,1]")
        try:
            re.compile(det.pattern)
        except re.error as exc:
            errs.append(f"{where}: bad regex {det.pattern!r}: {exc}")
    if not pat.positive:
        errs.append(f"{where}: needs at least one positive (TP) fixture")
    if not pat.negative:
        errs.append(f"{where}: needs at least one negative (FP) fixture")
    return errs


def default_catalog_dir() -> Path:
    """Locate the bundled pattern catalog.

    Resolution order: ``$SESHAT_PATTERNS`` → a packaged ``catalog/`` beside this
    module → the repo's ``patterns/catalog`` (dev layout).
    """
    env = os.environ.get("SESHAT_PATTERNS")
    if env:
        return Path(env)
    packaged = Path(__file__).resolve().parent / "catalog"
    if packaged.is_dir():
        return packaged
    for parent in Path(__file__).resolve().parents:
        cand = parent / "patterns" / "catalog"
        if cand.is_dir():
            return cand
    return Path("patterns/catalog")


def pattern_set_hash(patterns: list[Pattern]) -> str:
    """Stable hash of the active pattern set (for reproducible scans)."""
    h = hashlib.sha256()
    for pat in sorted(patterns, key=lambda p: p.id):
        h.update(pat.id.encode())
        h.update(pat.version.encode())
        for det in pat.detectors:
            h.update(det.type.encode())
            h.update(det.pattern.encode())
            h.update(f"{det.confidence}{det.scope}{det.multiline}".encode())
            h.update("|".join(det.requires).encode())
            h.update("|".join(det.forbids).encode())
    return h.hexdigest()
