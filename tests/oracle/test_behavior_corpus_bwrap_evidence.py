"""Offline binding of the checked hosted capture; omitted from capture-generation controls."""
from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from oracle import behavior_corpus_bwrap as backend
from oracle.llvm import behavior_corpus_bwrap as adapter
from oracle.llvm.produced_program import PROFILE

ROOT = Path(__file__).resolve().parents[2]


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class CheckedExecutionEvidenceTests(unittest.TestCase):
    def test_checked_live_report_and_provenance_match_the_current_runtime_sources(self) -> None:
        report_path = PROFILE / "behavior-corpus-bwrap-v1-evidence.json"
        provenance_path = PROFILE / "behavior-corpus-bwrap-v1-provenance.json"
        report = adapter.verify_supplemental_pair(adapter.CORPUS_PATH, report_path)
        provenance = backend._decode_json(provenance_path.read_bytes(), "checked execution provenance")
        self.assertEqual(set(provenance), {
            "schemaVersion", "authority", "sourceCommit", "sourceFiles", "workflowRun", "artifact",
            "corpusSha256", "reportSha256", "profile",
        })
        self.assertEqual(provenance["schemaVersion"], 1)
        self.assertEqual(provenance["authority"], "python-compatibility-reference-observation")
        self.assertEqual(provenance["profile"], "bubblewrap-hosted-v2")
        self.assertEqual(report["sandbox"]["profile"], provenance["profile"])
        self.assertEqual(provenance["corpusSha256"], sha(adapter.CORPUS_PATH.read_bytes()))
        self.assertEqual(provenance["reportSha256"], sha(report_path.read_bytes()))
        self.assertRegex(provenance["sourceCommit"], r"^[0-9a-f]{40}$")
        run = provenance["workflowRun"]
        self.assertEqual(set(run), {"id", "url", "headSha", "event", "conclusion"})
        self.assertIs(type(run["id"]), int)
        self.assertGreater(run["id"], 0)
        self.assertEqual(run["headSha"], provenance["sourceCommit"])
        self.assertEqual(run["event"], "workflow_dispatch")
        self.assertEqual(run["conclusion"], "success")
        self.assertEqual(run["url"], f"https://github.com/minsago-elite/decomp_thing/actions/runs/{run['id']}")
        artifact = provenance["artifact"]
        self.assertEqual(set(artifact), {"id", "name", "sha256", "reportMember"})
        self.assertIs(type(artifact["id"]), int)
        self.assertGreater(artifact["id"], 0)
        self.assertEqual(artifact["name"], "llvm-produced-program-bwrap-observation")
        self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(artifact["reportMember"], "behavior-corpus-bwrap-v1-report.json")
        sources = (
            "oracle/__init__.py", "oracle/behavior_corpus.py", "oracle/behavior_corpus_bwrap.py",
            "oracle/behavior_corpus_bwrap_loader.py", "oracle/behavior_corpus_bwrap_seccomp.py",
            "oracle/behavior_storage_lease.py", "oracle/llvm/__init__.py",
            "oracle/llvm/behavior_corpus_bwrap.py", "oracle/llvm/produced_program.py",
            "oracle/llvm/produced_program_bwrap.py", "oracle/llvm/22.1.6/oracle-manifest.json",
            "oracle/llvm/22.1.6/produced-program-start.s",
        )
        self.assertEqual(set(provenance["sourceFiles"]), set(sources))
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(provenance["sourceFiles"][source], sha((ROOT / source).read_bytes()))
        self.assertEqual(provenance_path.read_bytes(), backend.corpus_json_bytes(provenance))


if __name__ == "__main__":
    unittest.main()
