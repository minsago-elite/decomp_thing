#!/usr/bin/env python3
"""Compatibility entry point for the GCC-owned archive verifier."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from oracle.gcc.verify_reconstruction_archive import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
