#!/usr/bin/env python3
"""Compatibility command for the benchmark-owned rebuild implementation."""

from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.rebuild_oracle import (  # noqa: E402, F401
    VerificationError,
    _safe_extract,
    main,
    rebuild,
)


if __name__ == "__main__":
    raise SystemExit(main())
