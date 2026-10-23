"""Offline controls for the generic ``bubblewrap-v1`` behavior corpus backend (issue #97).

Nothing here launches bubblewrap or Clang: reports are synthesized from the committed corpus and a
static amd64 ELF that is only inspected, never executed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from oracle import behavior_corpus_bwrap as backend
from oracle.behavior_corpus import BehaviorCorpusError
from oracle.llvm import behavior_corpus_bwrap as adapter
from oracle.llvm.produced_program import CLANG, MANIFEST_SHA256, MARKER, PROFILE
from oracle.llvm.produced_program_bwrap import COMPILE_STDERR, EXPECTED_EXIT

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = {
    "oracle/llvm/22.1.6/behavior-corpus.json": "acaa7b33",
    "oracle/llvm/22.1.6/behavior-corpus-evidence.json": None,
}


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def git_blob(payload: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()


def synthetic_program(name: bytes, *, interpreter: bool = False, machine: int = 62) -> bytes:
    """Static ET_EXEC with one executable PT_LOAD holding a single temporary-object name."""
    code = b"\x90" * 16
    strings = b"\0start-" + name + b".o\0"
    phcount = 2 if interpreter else 1
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    body = 64 + 56 * phcount
    struct.pack_into("<HHIQQ", header, 16, 2, machine, 1, 0x401000 + body, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, phcount)
    size = body + len(code) + len(strings)
    headers = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x401000, 0x401000, size, size, 0x1000)
    if interpreter:
        headers += struct.pack("<IIQQQQQQ", 3, 4, body, 0, 0, 1, 1, 1)
    return bytes(header) + headers + code + strings


def observation(exit_code: int, stdout: bytes, stderr: bytes) -> dict:
    return {"exitCode": exit_code, "stdout": backend.blob(stdout), "stderr": backend.blob(stderr), "wallMillis": 7}


def artifact(program: bytes, corpus: dict) -> dict:
    normalizations = backend._validate_normalizations(corpus["artifactNormalizations"], "corpus")
    rules = [adapter.NORMALIZATION_ID]
    normalized = backend.normalize_artifact(program, rules, normalizations, "artifact")
    return {"path": "program", "mode": "0o755", "normalizations": rules, "normalizedSha256": sha(normalized),
            **backend.blob(program)}


def run_record(program: bytes, corpus: dict) -> dict:
    return {
        "compile": observation(0, b"", COMPILE_STDERR),
        "artifacts": [artifact(program, corpus)],
        "execution": observation(EXPECTED_EXIT, MARKER, b""),
    }


def valid_pair() -> tuple[dict, bytes, dict]:
    corpus = adapter.build_corpus()
    payload = backend.corpus_json_bytes(corpus)
    case = corpus["cases"][0]
    report = {
        "schemaVersion": 1,
        "backend": backend.BACKEND,
        "corpus": {"id": corpus["id"], "scope": corpus["scope"], "sha256": sha(payload)},
        "executable": copy.deepcopy(corpus["executable"]),
        "sandbox": copy.deepcopy(corpus["sandbox"]),
        "environment": copy.deepcopy(corpus["environment"]),
        "limits": copy.deepcopy(corpus["limits"]),
        "artifactNormalizations": copy.deepcopy(corpus["artifactNormalizations"]),
        "host": {"kernelRelease": "6.8.0", "machine": "x86_64", "osId": "ubuntu", "osVersionId": "24.04",
                 "bubblewrap": "bubblewrap 0.9.0"},
        "hostTools": [{"name": "ld", "path": "/usr/bin/ld", "realPath": "/usr/bin/x86_64-linux-gnu-ld.bfd",
                       "sandboxPath": "/usr/bin/ld", "versionLine": "GNU ld (GNU Binutils for Ubuntu) 2.42",
                       "bytes": 3, "sha256": "2" * 64}],
        "libraries": [{"path": "/lib64/ld-linux-x86-64.so.2", "bytes": 1, "sha256": "0" * 64},
                      {"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "bytes": 2, "sha256": "1" * 64}],
        "summary": {"cases": 1, "passed": 1, "categories": {category: 1 for category in sorted(case["categories"])}},
        "cases": [{
            "id": case["id"],
            "categories": list(case["categories"]),
            "runs": [run_record(synthetic_program(b"abcdef"), corpus), run_record(synthetic_program(b"123abc"), corpus)],
        }],
    }
    return corpus, payload, report


class CommittedCorpusTests(unittest.TestCase):
    def test_committed_corpus_is_the_reviewed_canonical_corpus(self) -> None:
        corpus, payload = backend.load_corpus(adapter.CORPUS_PATH)
        self.assertEqual(corpus, adapter.build_corpus())
        self.assertEqual(payload, backend.corpus_json_bytes(adapter.build_corpus()))
        self.assertEqual(corpus["cases"][0]["execute"]["expected"]["exitCode"], 42)
        self.assertEqual(base64.b64decode(corpus["cases"][0]["execute"]["expected"]["stdout"]["base64"]),
                         b"issue97-produced-program\n")

    def test_historical_oci_corpus_and_evidence_are_unchanged(self) -> None:
        corpus = (ROOT / "oracle/llvm/22.1.6/behavior-corpus.json").read_bytes()
        evidence = (ROOT / "oracle/llvm/22.1.6/behavior-corpus-evidence.json").read_bytes()
        self.assertEqual(git_blob(corpus), "0cde1d02e7b526880dda010dc7bc4051bfa91226")
        self.assertTrue(sha(corpus).startswith("acaa7b33") and sha(corpus).endswith("8d5b"))
        self.assertEqual(git_blob(evidence), "3f7fa365ce0c2caf8e7dea5f455766a29cc391d0")

    def test_adapter_rejects_a_drifted_corpus(self) -> None:
        corpus = adapter.build_corpus()
        corpus["cases"][0]["repetitions"] = 3
        with self.assertRaisesRegex(BehaviorCorpusError, "differs from the reviewed"):
            adapter._require_reviewed_corpus(backend.validate_corpus(corpus))


class PairTests(unittest.TestCase):
    def assert_pair_rejected(self, mutate, message: str) -> None:
        corpus, payload, report = valid_pair()
        mutate(corpus, report)
        with self.assertRaisesRegex(BehaviorCorpusError, message):
            backend.validate_corpus_report_pair(corpus, payload, report)

    def test_valid_pair_is_accepted(self) -> None:
        corpus, payload, report = valid_pair()
        checked = backend.validate_corpus_report_pair(corpus, payload, report)
        adapter._require_gnu_ld(checked)
        runs = checked["cases"][0]["runs"]
        self.assertNotEqual(runs[0]["artifacts"][0]["sha256"], runs[1]["artifacts"][0]["sha256"])
        self.assertEqual(runs[0]["artifacts"][0]["normalizedSha256"], runs[1]["artifacts"][0]["normalizedSha256"])

    def test_report_file_round_trip_and_offline_replay(self) -> None:
        _, _, report = valid_pair()
        with tempfile.TemporaryDirectory(dir=ROOT / "build" if (ROOT / "build").is_dir() else None) as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(backend.report_json_bytes(report))
            checked = adapter.verify_supplemental_pair(adapter.CORPUS_PATH, path)
            self.assertEqual(checked["summary"]["passed"], 1)
            path.write_bytes(json.dumps(report).encode())
            with self.assertRaisesRegex(BehaviorCorpusError, "canonical JSON"):
                adapter.verify_supplemental_pair(adapter.CORPUS_PATH, path)

    def test_execution_exit_code_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][1]["execution"]["exitCode"] = 0
        self.assert_pair_rejected(mutate, "execution exit code differs")

    def test_execution_stdout_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["execution"]["stdout"] = backend.blob(b"other\n")
        self.assert_pair_rejected(mutate, "execution stdout differs")

    def test_compile_stderr_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["compile"]["stderr"] = backend.blob(b"")
        self.assert_pair_rejected(mutate, "compile stderr differs")

    def test_missing_execution_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["execution"] = None
        self.assert_pair_rejected(mutate, "missing its execution")

    def test_cross_run_normalized_difference_is_rejected(self) -> None:
        def mutate(corpus, report):
            program = synthetic_program(b"abcdef") + b"drift"
            report["cases"][0]["runs"][1]["artifacts"] = [artifact(program, corpus)]
        self.assert_pair_rejected(mutate, "differ between repetitions")

    def test_forged_normalized_hash_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["artifacts"][0]["normalizedSha256"] = "f" * 64
        self.assert_pair_rejected(mutate, "normalizedSha256 does not match")

    def test_unknown_normalization_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["artifacts"][0]["normalizations"] = ["other-rule"]
        self.assert_pair_rejected(mutate, "unknown rule")

    def test_normalization_must_match_exactly_once(self) -> None:
        corpus = adapter.build_corpus()
        twice = synthetic_program(b"abcdef") + b"start-012345.o\0"
        with self.assertRaisesRegex(BehaviorCorpusError, "matched 2 times"):
            artifact(twice, corpus)
        never = synthetic_program(b"ABCDEF")
        with self.assertRaisesRegex(BehaviorCorpusError, "matched 0 times"):
            artifact(never, corpus)

    def test_dynamic_program_is_rejected(self) -> None:
        def mutate(corpus, report):
            for run, name in zip(report["cases"][0]["runs"], (b"abcdef", b"123abc")):
                run["artifacts"] = [artifact(synthetic_program(name, interpreter=True), corpus)]
        self.assert_pair_rejected(mutate, "no interpreter or dynamic section")

    def test_wrong_machine_program_is_rejected(self) -> None:
        def mutate(corpus, report):
            for run, name in zip(report["cases"][0]["runs"], (b"abcdef", b"123abc")):
                run["artifacts"] = [artifact(synthetic_program(name, machine=183), corpus)]
        self.assert_pair_rejected(mutate, "static ET_EXEC for machine 62")

    def test_host_machine_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["host"]["machine"] = "aarch64"
        self.assert_pair_rejected(mutate, "does not run the declared execute ELF machine")

    def test_host_tool_outside_search_path_is_rejected(self) -> None:
        def mutate(_, report):
            report["hostTools"][0]["path"] = "/opt/evil/ld"
        self.assert_pair_rejected(mutate, "outside the declared search path")

    def test_report_corpus_hash_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["corpus"]["sha256"] = "0" * 64
        self.assert_pair_rejected(mutate, "does not identify this corpus")

    def test_summary_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            report["summary"]["passed"] = 0
        self.assert_pair_rejected(mutate, "summary does not match")

    def test_run_count_mismatch_is_rejected(self) -> None:
        def mutate(_, report):
            del report["cases"][0]["runs"][1]
        self.assert_pair_rejected(mutate, "has 1 runs, expected 2")

    def test_non_gnu_ld_is_rejected_by_the_adapter(self) -> None:
        corpus, payload, report = valid_pair()
        report["hostTools"][0]["versionLine"] = "LLD 18.1.3 (compatible with GNU linkers)"
        checked = backend.validate_corpus_report_pair(corpus, payload, report)
        with self.assertRaisesRegex(BehaviorCorpusError, "requires the host GNU ld"):
            adapter._require_gnu_ld(checked)


class CorpusValidationTests(unittest.TestCase):
    def assert_corpus_rejected(self, mutate, message: str) -> None:
        corpus = copy.deepcopy(adapter.build_corpus())
        mutate(corpus)
        with self.assertRaisesRegex(BehaviorCorpusError, message):
            backend.validate_corpus(corpus)

    def test_other_backend_is_rejected(self) -> None:
        self.assert_corpus_rejected(lambda c: c["sandbox"].update(backend="oci-v1"), "backend must be")

    def test_weakened_base_argv_is_rejected(self) -> None:
        self.assert_corpus_rejected(lambda c: c["sandbox"]["baseArgv"].remove("--unshare-all"), "baseArgv must be")

    def test_loader_environment_is_rejected(self) -> None:
        def mutate(corpus):
            corpus["environment"] = {"LC_ALL": "C", "LD_PRELOAD": "/x.so", "PATH": "/usr/bin", "TMPDIR": "/tmp"}
        self.assert_corpus_rejected(mutate, "reserved for the backend")

    def test_unsorted_environment_is_rejected(self) -> None:
        def mutate(corpus):
            corpus["environment"] = {"PATH": "/usr/bin", "LC_ALL": "C", "TMPDIR": "/tmp"}
        self.assert_corpus_rejected(mutate, "keys must be sorted")

    def test_nested_sandbox_paths_are_rejected(self) -> None:
        self.assert_corpus_rejected(lambda c: c["sandbox"].update(programPath="/work/program"), "must not nest")

    def test_reserved_sandbox_path_is_rejected(self) -> None:
        self.assert_corpus_rejected(lambda c: c["sandbox"].update(workspacePath="/tmp/work"), "is reserved")

    def test_tool_name_with_path_is_rejected(self) -> None:
        self.assert_corpus_rejected(lambda c: c["sandbox"]["hostTools"][0].update(name="bin/ld"), "bare command name")

    def test_capturing_or_empty_normalization_is_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["artifactNormalizations"][0].update(pattern="(start)"), "must not capture"
        )
        self.assert_corpus_rejected(
            lambda c: c["artifactNormalizations"][0].update(pattern="x*"), "must not capture"
        )

    def test_unused_normalization_is_rejected(self) -> None:
        def mutate(corpus):
            corpus["cases"][0]["expected"]["artifacts"][0]["normalizations"] = []
        self.assert_corpus_rejected(mutate, "artifactNormalizations are unused")

    def test_execute_of_missing_artifact_is_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["cases"][0]["execute"].update(artifact="other"), "must name an expected artifact"
        )


class ManifestTests(unittest.TestCase):
    def test_locate_clang_uses_the_locked_manifest(self) -> None:
        manifest = PROFILE / "oracle-manifest.json"
        if not manifest.is_file():
            self.skipTest("locked LLVM manifest is not present")
        root = Path("/nonexistent-artifact-root")
        path = adapter.locate_clang(manifest, root)
        self.assertTrue(path.is_relative_to(root))
        self.assertEqual(sha(manifest.read_bytes()), MANIFEST_SHA256)
        self.assertEqual(adapter.build_corpus()["executable"], dict(CLANG))

    def test_locate_clang_rejects_an_unpinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "build" if (ROOT / "build").is_dir() else None) as directory:
            manifest = Path(directory) / "oracle-manifest.json"
            manifest.write_text("{}")
            with self.assertRaisesRegex(BehaviorCorpusError, "manifest identity mismatch"):
                adapter.locate_clang(manifest, Path(directory))


if __name__ == "__main__":
    unittest.main()
