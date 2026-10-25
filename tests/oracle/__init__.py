"""Python oracle tests.

AGENTS.md forbids creating files outside the repository root, so every temporary file or directory a
test creates through ``tempfile`` defaults (and every Python subprocess it starts, via ``TMPDIR``)
lands under ``build/python-test-tmp`` instead of the system temporary directory.
"""
import os
import tempfile
from pathlib import Path

_TEMPORARY_ROOT = Path(__file__).resolve().parents[2] / "build" / "python-test-tmp"
_TEMPORARY_ROOT.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = os.fspath(_TEMPORARY_ROOT)
os.environ["TMPDIR"] = tempfile.tempdir
