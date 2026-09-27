#!/usr/bin/env python3
"""Compatibility entry point for the GCC-owned accuracy coverage report."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from oracle.gcc.report_accuracy_coverage import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
