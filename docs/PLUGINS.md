# 🧩 Seshat — Plugins & Interop

Seshat is extensible without touching its core: drop in your own patterns, and
import findings from other tools.

## Custom patterns (plugins)

A pattern is a single self-contained YAML file (see [PATTERNS.md](PATTERNS.md)
for the full anatomy). To add your own:

1. Write a `*.yaml` pattern with inline `tests:` fixtures. Use an id outside the
   bundled range (P001–P178) — e.g. `P900`. See
   [`examples/plugins/P900_debug_console_log.yaml`](../examples/plugins/P900_debug_console_log.yaml).
2. Load it **alongside** the bundled catalog:

   ```bash
   seshat scan --plugins ./examples/plugins
   seshat patterns --plugins ./examples/plugins --validate
   ```

   …or drop it in `~/.config/seshat/patterns/` (or any dir in `$SESHAT_PLUGINS`)
   to auto-load it on every run.

3. Replace the catalog entirely with `--patterns DIR` if you want only your own.

Duplicate pattern ids across directories are rejected (no silent shadowing), and
every plugin pattern must pass its own TP/FP fixtures under `--validate`.

## Importing from other tools

Seshat can pull findings from external scanners into a scan, so one archive can
hold and **diff** results from multiple tools:

```bash
seshat import --format sarif  findings.sarif     # any SARIF 2.1.0 producer
seshat import --format slither slither.json      # slither --json slither.json
```

Imported contracts are keyed by their artifact URI (origin `imported`). Combined
with Seshat's own **SARIF export** (`seshat report -o out.sarif`), this gives a
clean round-trip: export → import → the same findings come back.

## IDE / CI integration

`seshat report -o findings.sarif` emits SARIF 2.1.0 that renders in VS Code's
Problems panel and powers GitHub code-scanning annotations (each result carries a
`security-severity`).
