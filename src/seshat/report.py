"""Reporting — render a scan into JSON / CSV / SARIF / Markdown / HTML.

Every exporter carries Seshat's honesty framing: findings are **review flags**
(heuristic pattern matches that need human review), never confirmed
vulnerabilities. Severity is triage priority; confidence is how sure the
heuristic is. The two are independent and both are shown.

All exporters are pure functions of a :class:`Report` and use only the standard
library, so a report is reproducible and fully offline.
"""

from __future__ import annotations

import csv
import html
import io
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import __version__

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

DISCLAIMER = (
    "Seshat is a heuristic static scanner. These are REVIEW FLAGS — pattern "
    "matches that require manual review, not confirmed vulnerabilities. A flag "
    "means \"a human should look here,\" not \"this contract is exploitable.\" "
    "Severity is triage priority; confidence is how sure the heuristic is."
)

# severity -> (SARIF level, GitHub code-scanning security-severity)
_SARIF_LEVEL = {
    "critical": ("error", "9.0"),
    "high": ("error", "7.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "3.0"),
    "info": ("note", "1.0"),
}


@dataclass
class ReportFinding:
    contract_id: int
    contract_name: str | None
    chain: str | None
    address: str | None
    source_path: str | None
    pattern_id: str
    pattern_name: str | None
    category: str | None
    severity: str
    confidence: float
    line: int
    snippet: str
    evidence: str
    swc: str | None = None
    cwe: str | None = None
    recommendation: str = ""

    @property
    def artifact_uri(self) -> str:
        if self.source_path:
            return self.source_path
        loc = self.address or f"contract_{self.contract_id}"
        return f"{self.chain or 'local'}/{loc}.sol"


@dataclass
class Report:
    scan_id: int
    generated_at: str
    pattern_set_hash: str | None
    contracts_scanned: int
    total_findings: int
    by_severity: dict[str, int]
    findings: list[ReportFinding] = field(default_factory=list)
    tool_version: str = __version__


def build_report(
    conn: sqlite3.Connection,
    scan_id: int | None = None,
    *,
    recommendations: dict[str, str] | None = None,
    min_severity: str | None = None,
) -> Report:
    if scan_id is None:
        row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
        scan_id = row[0] if row else None
    if scan_id is None:
        raise ValueError("no scans in the archive — run `seshat scan` first")

    meta = conn.execute(
        "SELECT pattern_set_hash, contracts_scanned FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if meta is None:
        raise ValueError(f"scan #{scan_id} not found")

    rec = recommendations or {}
    max_rank = _SEV_RANK.get(min_severity, len(SEVERITY_ORDER)) if min_severity else len(SEVERITY_ORDER)

    rows = conn.execute(
        "SELECT f.pattern_id, f.severity, f.confidence, f.line, f.snippet, f.evidence, "
        "       c.id AS cid, c.name AS cname, c.chain_key, c.address, "
        "       p.name AS pname, p.category, p.swc, p.cwe, "
        "       (SELECT path FROM sources WHERE contract_id = c.id AND kind = 'normalized' "
        "        LIMIT 1) AS source_path "
        "FROM findings f "
        "JOIN contracts c ON c.id = f.contract_id "
        "LEFT JOIN patterns p ON p.id = f.pattern_id "
        "WHERE f.scan_id = ?",
        (scan_id,),
    ).fetchall()

    findings: list[ReportFinding] = []
    for r in rows:
        sev = r["severity"] or "info"
        if _SEV_RANK.get(sev, 99) > max_rank:
            continue
        findings.append(ReportFinding(
            contract_id=r["cid"], contract_name=r["cname"], chain=r["chain_key"],
            address=r["address"], source_path=r["source_path"],
            pattern_id=r["pattern_id"], pattern_name=r["pname"], category=r["category"],
            severity=sev, confidence=r["confidence"] or 0.0, line=r["line"] or 0,
            snippet=r["snippet"] or "", evidence=r["evidence"] or "",
            swc=r["swc"], cwe=r["cwe"], recommendation=rec.get(r["pattern_id"], ""),
        ))

    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 99), f.contract_id, f.line, f.pattern_id))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    return Report(
        scan_id=scan_id,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        pattern_set_hash=meta["pattern_set_hash"],
        contracts_scanned=meta["contracts_scanned"] or 0,
        total_findings=len(findings),
        by_severity=by_sev,
        findings=findings,
    )


# --------------------------------------------------------------------------- JSON
def to_json(report: Report) -> str:
    payload = {
        "tool": "seshat",
        "version": report.tool_version,
        "disclaimer": DISCLAIMER,
        "scan_id": report.scan_id,
        "generated_at": report.generated_at,
        "pattern_set_hash": report.pattern_set_hash,
        "contracts_scanned": report.contracts_scanned,
        "total_findings": report.total_findings,
        "by_severity": report.by_severity,
        "findings": [asdict(f) for f in report.findings],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------- CSV
def to_csv(report: Report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "severity", "confidence", "pattern_id", "pattern_name", "category",
        "chain", "address", "contract", "line", "swc", "cwe", "snippet",
    ])
    for f in report.findings:
        w.writerow([
            f.severity, f"{f.confidence:.2f}", f.pattern_id, f.pattern_name or "",
            f.category or "", f.chain or "", f.address or "",
            f.contract_name or f.contract_id, f.line, f.swc or "", f.cwe or "",
            f.snippet,
        ])
    return buf.getvalue()


# ----------------------------------------------------------------------- Markdown
def to_markdown(report: Report) -> str:
    out: list[str] = []
    out.append("# 👁️⚖️ Seshat — Review Flags")
    out.append("")
    out.append(f"> {DISCLAIMER}")
    out.append("")
    out.append(f"- **Scan:** #{report.scan_id} · generated {report.generated_at}")
    out.append(f"- **Contracts scanned:** {report.contracts_scanned}")
    out.append(f"- **Review flags:** {report.total_findings}")
    if report.pattern_set_hash:
        out.append(f"- **Pattern set:** `{report.pattern_set_hash[:12]}`")
    out.append("")
    out.append("## Severity breakdown")
    out.append("")
    out.append("| Severity | Flags |")
    out.append("|---|---|")
    for sev in SEVERITY_ORDER:
        if report.by_severity.get(sev):
            out.append(f"| {sev} | {report.by_severity[sev]} |")
    out.append("")
    out.append("## Findings")
    out.append("")
    if not report.findings:
        out.append("_No review flags._")
        return "\n".join(out) + "\n"
    out.append("| Severity | Conf | Pattern | Contract | Line | Note |")
    out.append("|---|---|---|---|---|---|")
    for f in report.findings:
        contract = f.contract_name or f"#{f.contract_id}"
        note = (f.evidence or f.pattern_name or "").replace("|", "\\|")
        out.append(
            f"| {f.severity} | {f.confidence:.2f} | {f.pattern_id} | "
            f"{contract} | {f.line} | {note} |"
        )
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- SARIF
def to_sarif(report: Report) -> str:
    rules: dict[str, dict] = {}
    for f in report.findings:
        if f.pattern_id in rules:
            continue
        level, sec = _SARIF_LEVEL.get(f.severity, ("note", "1.0"))
        tags = ["security", "review-flag"]
        if f.category:
            tags.append(f.category.lower())
        rules[f.pattern_id] = {
            "id": f.pattern_id,
            "name": (f.pattern_name or f.pattern_id).replace(" ", ""),
            "shortDescription": {"text": f.pattern_name or f.pattern_id},
            "fullDescription": {"text": f.evidence or f.pattern_name or f.pattern_id},
            "defaultConfiguration": {"level": level},
            "properties": {
                "category": f.category or "",
                "swc": f.swc or "",
                "cwe": f.cwe or "",
                "security-severity": sec,
                "tags": tags,
            },
        }

    results = []
    for f in report.findings:
        level, _ = _SARIF_LEVEL.get(f.severity, ("note", "1.0"))
        msg = f.evidence or f.pattern_name or f.pattern_id
        results.append({
            "ruleId": f.pattern_id,
            "level": level,
            "message": {"text": f"[review flag · confidence {f.confidence:.2f}] {msg}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.artifact_uri},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Seshat",
                "informationUri": "https://github.com/Lord1Egypt/Seshat",
                "version": report.tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# --------------------------------------------------------------------------- HTML
_SEV_COLOR = {
    "critical": "#d11", "high": "#e67e22", "medium": "#d4a700",
    "low": "#3498db", "info": "#7f8c8d",
}


def to_html(report: Report) -> str:
    e = html.escape
    cards = "".join(
        f'<div class="card" style="border-color:{_SEV_COLOR[s]}">'
        f'<div class="n" style="color:{_SEV_COLOR[s]}">{report.by_severity.get(s, 0)}</div>'
        f'<div class="l">{s}</div></div>'
        for s in SEVERITY_ORDER
    )
    rows = "".join(
        f"<tr>"
        f'<td><span class="pill" style="background:{_SEV_COLOR.get(f.severity, "#777")}">{e(f.severity)}</span></td>'
        f"<td>{f.confidence:.2f}</td><td>{e(f.pattern_id)}</td>"
        f"<td>{e(f.pattern_name or '')}</td>"
        f"<td>{e(f.contract_name or '#' + str(f.contract_id))}</td>"
        f"<td>{e(f.chain or 'local')}</td><td>{f.line}</td>"
        f"<td><code>{e(f.snippet)}</code></td></tr>"
        for f in report.findings
    ) or '<tr><td colspan="8">No review flags.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Seshat Review Flags — scan #{report.scan_id}</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 header{{padding:24px;background:#171a21;border-bottom:1px solid #2a2f3a}}
 h1{{margin:0 0 4px;font-size:20px}} .sub{{color:#9aa4b2;font-size:13px}}
 .disc{{margin:16px 24px;padding:12px 16px;background:#221c10;border:1px solid #6b5418;border-radius:8px;color:#e8d9a8;font-size:13px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;padding:16px 24px}}
 .card{{background:#171a21;border:2px solid #333;border-radius:10px;padding:12px 18px;min-width:90px;text-align:center}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:12px;color:#9aa4b2;text-transform:uppercase}}
 table{{width:calc(100% - 48px);margin:8px 24px 32px;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #232833;vertical-align:top}}
 th{{color:#9aa4b2;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
 code{{color:#9ad}} .pill{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;text-transform:uppercase}}
 .meta{{color:#9aa4b2;font-size:12px;padding:0 24px 24px}}
</style></head><body>
<header><h1>👁️⚖️ Seshat — Review Flags</h1>
<div class="sub">scan #{report.scan_id} · {e(report.generated_at)} · {report.contracts_scanned} contracts · {report.total_findings} flags · pattern set <code>{e((report.pattern_set_hash or '')[:12])}</code></div>
</header>
<div class="disc">⚠️ {e(DISCLAIMER)}</div>
<div class="cards">{cards}</div>
<table><thead><tr><th>Severity</th><th>Conf</th><th>Pattern</th><th>Name</th><th>Contract</th><th>Chain</th><th>Line</th><th>Snippet</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="meta">Generated by Seshat v{e(report.tool_version)} — offline, self-contained. Severity = triage priority; confidence = heuristic certainty.</div>
</body></html>
"""


# -------------------------------------------------------------- terminal triage view
def to_table(report: Report, *, color: bool = False) -> str:
    def c(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    sev_code = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}
    out: list[str] = []
    out.append(c(f"👁️⚖️  Seshat — scan #{report.scan_id}  ({report.total_findings} review flags, "
                 f"{report.contracts_scanned} contracts)", "1"))
    parts = [c(f"{report.by_severity.get(s, 0)} {s}", sev_code.get(s, "0"))
             for s in SEVERITY_ORDER if report.by_severity.get(s)]
    out.append("  " + " · ".join(parts) if parts else "  (no flags)")
    out.append("")
    cur = None
    for f in report.findings:
        if f.severity != cur:
            cur = f.severity
            out.append(c(f"── {f.severity.upper()} ──", sev_code.get(cur, "0")))
        loc = f.contract_name or f"#{f.contract_id}"
        out.append(f"  {f.pattern_id}  {loc}:{f.line}  {f.evidence or f.pattern_name or ''}")
    out.append("")
    out.append("⚠️  Review flags are heuristic, not confirmed vulnerabilities.")
    return "\n".join(out) + "\n"


EXPORTERS = {
    "json": to_json, "csv": to_csv, "sarif": to_sarif,
    "md": to_markdown, "markdown": to_markdown, "html": to_html,
}
