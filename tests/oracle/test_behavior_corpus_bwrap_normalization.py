"""Bounded normalization regressions for admitted generic corpus rules (#97)."""
from __future__ import annotations

import base64
import hashlib
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oracle import behavior_corpus_bwrap as backend
from oracle.behavior_corpus import BehaviorCorpusError

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_BYTES = 2 * 1024 * 1024
RULE_ID = "literal-normalization"


def accepted_corpus(pattern: str = "a", replacement: bytes = b"z" * 256) -> dict:
    """A program-neutral fixture whose normalization and artifact bounds pass real admission."""
    machine = {"x86_64": 62, "aarch64": 183}[platform.machine()]
    return backend.validate_corpus({
        "schemaVersion": 1,
        "scope": "fixture",
        "id": "bounded-normalization-control",
        "executable": {"bytes": 1, "sha256": hashlib.sha256(b"e").hexdigest()},
        "sandbox": {
            "backend": backend.BACKEND,
            "profile": "normalization-control",
            "baseArgv": list(backend.BASE_ARGV),
            "executablePath": "/oracle/exe",
            "workspacePath": "/work",
            "programPath": "/oracle/program",
            "executeElfMachine": machine,
            "hostTools": [],
            "storagePolicy": backend.STORAGE_POLICY_ID,
            "syscallPolicy": backend.storage_filter_identity(machine),
        },
        "environment": {},
        "limits": {
            "wallSeconds": 10, "cpuSeconds": 10, "streamBytes": 4096,
            "artifactBytes": ARTIFACT_BYTES, "compileAddressSpaceBytes": 1024 ** 3,
            "executeAddressSpaceBytes": 64 * 1024 * 1024, "openFiles": 64,
            "closureLibraries": 64, "workspaceEntries": 2, "processes": 32,
            "writableBytes": 4 * 1024 * 1024, "writableEntries": 8,
        },
        "artifactNormalizations": [{
            "id": RULE_ID, "pattern": pattern,
            "replacementBase64": base64.b64encode(replacement).decode("ascii"),
        }],
        "cases": [{
            "id": "normalization", "categories": ["normalization-control"], "repetitions": 1,
            "arguments": [], "inputs": [],
            "expected": {
                "exitCode": 0, "stdout": backend.blob(b""), "stderr": backend.blob(b""),
                "artifacts": [{
                    "path": "artifact", "mode": "0o644", "normalizations": [RULE_ID],
                    "normalizedSha256": hashlib.sha256(b"reviewed-output").hexdigest(),
                }],
            },
            "execute": None,
        }],
    })


def normalize(payload: bytes, pattern: str = "a", replacement: bytes = b"z" * 256) -> bytes:
    corpus = accepted_corpus(pattern, replacement)
    rules = backend._validate_normalizations(corpus["artifactNormalizations"], "corpus.artifactNormalizations")
    return backend.normalize_artifact(payload, [RULE_ID], rules, "admitted artifact")


_BOUNDED_REJECTION = r"""
import resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
sys.path.insert(0, sys.argv[1])
from tests.oracle.test_behavior_corpus_bwrap_normalization import (
    ARTIFACT_BYTES, RULE_ID, accepted_corpus,
)
from oracle import behavior_corpus_bwrap as backend
from oracle.behavior_corpus import BehaviorCorpusError
corpus = accepted_corpus()
rules = backend._validate_normalizations(corpus['artifactNormalizations'], 'corpus.artifactNormalizations')
payload = b'a' * ARTIFACT_BYTES
assert len(payload) == corpus['limits']['artifactBytes']
try:
    backend.normalize_artifact(payload, [RULE_ID], rules, 'admitted artifact')
except BehaviorCorpusError as error:
    assert 'matched' in str(error) and 'exactly once' in str(error), str(error)
    print('refused match count within memory limit')
else:
    raise AssertionError('multiply matching artifact was accepted')
"""


class BoundedArtifactNormalizationTests(unittest.TestCase):
    def test_admitted_repeated_artifact_refuses_before_expanding_every_match(self) -> None:
        # The 2 MiB input is admitted, but eagerly replacing every byte produces
        # 512 MiB. The historical implementation raises MemoryError under this
        # ceiling instead of delivering its promised match-count refusal.
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="normalization-limit-", dir=ROOT / "build") as directory:
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", _BOUNDED_REJECTION, os.fspath(ROOT)],
                cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=3, check=False,
                env={"TMPDIR": directory, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stdout, b"refused match count within memory limit\n")
        self.assertEqual(result.stderr, b"")

    def test_exactly_one_match_preserves_literal_backslashes_and_nul(self) -> None:
        replacement = b"\\1\\g<0>\\n\\x41\x00"
        self.assertEqual(normalize(b"prefix-a-suffix", replacement=replacement), b"prefix-" + replacement + b"-suffix")

    def test_exactly_one_match_may_use_the_maximum_replacement(self) -> None:
        self.assertEqual(normalize(b"XaY"), b"X" + b"z" * 256 + b"Y")

    def test_no_match_reports_a_match_count_refusal(self) -> None:
        with self.assertRaisesRegex(BehaviorCorpusError, "matched 0 times instead of exactly once"):
            normalize(b"no-hit")

    def test_overlapping_occurrences_keep_nonoverlapping_regex_semantics(self) -> None:
        # re.subn treats aaa with pattern aa as exactly one match, then keeps the
        # last a. Counting a second overlapping search would change that contract.
        self.assertEqual(normalize(b"aaa", pattern="aa", replacement=b"X"), b"Xa")
        with self.assertRaisesRegex(BehaviorCorpusError, "matched.*exactly once"):
            normalize(b"aaaa", pattern="aa", replacement=b"X")


if __name__ == "__main__":
    unittest.main()
