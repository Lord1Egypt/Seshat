#!/usr/bin/env python3
"""Generate an animated terminal demo as a self-contained SVG.

VHS is the house standard for demo GIFs, but it isn't always installed and a GIF
is an opaque binary. This produces a dependency-free, reproducible **animated
SVG** (`docs/demo.svg`) that renders inline in the GitHub README. A VHS tape
(`docs/demo.tape`) is also committed for when VHS is available.

    python tools/gen_demo.py
"""
from __future__ import annotations

from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "demo.svg"

# (text, css-class) — class drives colour. "" = default foreground.
LINES = [
    ("$ pipx install seshat-scanner", "cmd"),
    ("$ seshat ingest ./MyVault.sol", "cmd"),
    ("\U0001F4E5 ingested into seshat.db: 1 new (1 with verified source)", "ok"),
    ("$ seshat scan", "cmd"),
    ("\U0001F50D scan #1: 1 contracts, 103 patterns → 4 review flags", "ok"),
    ("$ seshat report", "cmd"),
    ("\U0001F441️⚖️  Seshat — scan #1  (4 review flags)", "hdr"),
    ("  ── CRITICAL ──", "crit"),
    ("    P001  MyVault:12  Public mint without an owner guard", "crit"),
    ("    P003  MyVault:20  Value call without a reentrancy guard", "crit"),
    ("  ── HIGH ──", "high"),
    ("    P006  MyVault:20  Unchecked low-level call", "high"),
    ("  ⚠️  Review flags are heuristic, not confirmed vulnerabilities.", "warn"),
]

ROW_H = 24
PAD_TOP = 56
WIDTH = 760
HEIGHT = PAD_TOP + ROW_H * len(LINES) + 20
STEP = 0.45  # seconds between lines appearing

COLORS = {
    "cmd": "#e6e6e6", "ok": "#7ee787", "hdr": "#d2a8ff",
    "crit": "#ff7b72", "high": "#ffa657", "warn": "#e3b341", "": "#c9d1d9",
}


def main() -> None:
    rows = []
    for i, (text, cls) in enumerate(LINES):
        y = PAD_TOP + i * ROW_H
        delay = round(0.3 + i * STEP, 2)
        color = COLORS.get(cls, COLORS[""])
        # the "$" prompt gets a green tint on command lines
        if text.startswith("$ "):
            content = (
                f'<tspan fill="#7ee787">$</tspan>'
                f'<tspan fill="{color}"> {escape(text[2:])}</tspan>'
            )
        else:
            content = f'<tspan fill="{color}">{escape(text)}</tspan>'
        rows.append(
            f'<text class="ln" x="20" y="{y}" style="--d:{delay}s">{content}</text>'
        )
    body = "\n  ".join(rows)
    total = round(0.3 + len(LINES) * STEP + 0.5, 2)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}"
     viewBox="0 0 {WIDTH} {HEIGHT}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14">
  <style>
    .ln {{ opacity: 0; animation: show .25s ease forwards; animation-delay: var(--d); }}
    @keyframes show {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    .cur {{ animation: blink 1s steps(1) infinite; animation-delay: {total}s; }}
    @keyframes blink {{ 50% {{ opacity: 0; }} }}
  </style>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="10" fill="#0d1117" stroke="#30363d"/>
  <rect width="{WIDTH}" height="36" rx="10" fill="#161b22"/>
  <rect y="26" width="{WIDTH}" height="10" fill="#161b22"/>
  <circle cx="22" cy="18" r="6" fill="#ff5f56"/>
  <circle cx="42" cy="18" r="6" fill="#ffbd2e"/>
  <circle cx="62" cy="18" r="6" fill="#27c93f"/>
  <text x="{WIDTH//2}" y="23" text-anchor="middle" fill="#8b949e" font-size="12">seshat — offline contract review</text>
  {body}
  <rect class="cur" x="20" y="{PAD_TOP + len(LINES) * ROW_H - 12}" width="8" height="15" fill="#7ee787"/>
</svg>
"""
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(svg, encoding="utf-8")
    print(f"wrote {OUT} ({HEIGHT}px tall, {len(LINES)} lines)")


if __name__ == "__main__":
    main()
