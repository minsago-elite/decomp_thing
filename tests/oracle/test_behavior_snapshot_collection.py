"""Post-execution collection cannot wait for an adversarial special-file writer."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oracle.behavior_corpus import BehaviorCorpusError, _read_regular_snapshot

ROOT = Path(__file__).resolve().parents[2]


class SnapshotCollectionTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_fifo_replacing_declared_input_refuses_within_outer_deadline(self):
        workspace = self.root / "work"
        workspace.mkdir()
        os.mkfifo(workspace / "input", 0o600)
        script = r"""
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from oracle.behavior_corpus import BehaviorCorpusError
from oracle.behavior_corpus_bwrap import _collect_workspace, blob
case = {"inputs": [{"path": "input", **blob(b"original")}], "expected": {"artifacts": []}}
try:
    _collect_workspace(Path(sys.argv[2]), case, {"workspaceEntries": 1, "artifactBytes": 4096}, {}, "fifo-case")
except BehaviorCorpusError as error:
    assert "not a non-symlink regular file" in str(error), str(error)
    print("rejected FIFO before waiting for a writer")
else:
    raise AssertionError("FIFO input was accepted")
"""
        # This is outside the target execution timeout, exactly where the old
        # blocking open hung. The outer deadline makes that old behavior fail.
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT), str(workspace)],
            stdin=subprocess.DEVNULL, capture_output=True, env={}, cwd=ROOT, timeout=3, check=True,
        )
        self.assertEqual(result.stdout, b"rejected FIFO before waiting for a writer\n")
        self.assertEqual(result.stderr, b"")

    def test_regular_snapshot_still_reads_exact_bytes_and_enforces_length(self):
        path = self.root / "regular"
        path.write_bytes(b"regular payload")
        self.assertEqual(_read_regular_snapshot(path, "regular", 15), b"regular payload")
        with self.assertRaisesRegex(BehaviorCorpusError, "exceeds"):
            _read_regular_snapshot(path, "regular", 14)

    def test_symlink_substitution_cannot_redirect_the_snapshot(self):
        path = self.root / "regular"
        path.write_bytes(b"private")
        alias = self.root / "alias"
        alias.symlink_to(path)
        with self.assertRaises(BehaviorCorpusError):
            _read_regular_snapshot(alias, "alias", 4096)


if __name__ == "__main__":
    unittest.main()
