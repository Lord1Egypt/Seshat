"""PyInstaller entry point — builds a single-file `seshat` binary.

Kept tiny and import-light so PyInstaller's analysis is clean. The catalog is
bundled via `--collect-data seshat` (see .github/workflows/release.yml).
"""
import sys

from seshat.cli import main

if __name__ == "__main__":
    sys.exit(main())
