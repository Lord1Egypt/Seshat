# patterns/

The canonical pattern catalog ships **inside the package** at
[`src/seshat/catalog/`](../src/seshat/catalog/) so it is bundled as package-data
and works fully offline after `pip install` / `pipx install` (no repo, no
network). There are **103 patterns**, each a self-contained YAML file with inline
TP/FP fixtures.

- Format & taxonomy: [../docs/PATTERNS.md](../docs/PATTERNS.md)
- Regenerate the catalog: `python tools/gen_catalog.py` (the YAML files are the
  source of truth; the generator is committed for provenance)
- Validate every pattern + fixture: `seshat patterns --validate`
- Point the engine at a different catalog: `--patterns DIR` or `$SESHAT_PATTERNS`
