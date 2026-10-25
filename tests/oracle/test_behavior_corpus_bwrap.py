"""Offline controls for the generic ``bubblewrap-v1`` behavior corpus backend (issue #97).

Offline reports are synthesized from the committed corpus and a static amd64 ELF.
Explicitly opted-in live controls execute a bounded authored adversary under bubblewrap.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import resource
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def synthetic_corpus() -> dict:
    """The reviewed corpus with its normalized digest repinned to the synthetic program's."""
    corpus = adapter.build_corpus()
    corpus["cases"][0]["expected"]["artifacts"][0]["normalizedSha256"] = artifact(
        synthetic_program(b"abcdef"), corpus
    )["normalizedSha256"]
    return backend.validate_corpus(corpus)


def valid_pair() -> tuple[dict, bytes, dict]:
    corpus = synthetic_corpus()
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
        corpus["cases"][0]["repetitions"] = 1
        with self.assertRaisesRegex(BehaviorCorpusError, "differs from the reviewed"):
            adapter._require_reviewed_corpus(backend.validate_corpus(corpus))


class PairTests(unittest.TestCase):
    def assert_pair_rejected(self, mutate, message: str) -> None:
        corpus, payload, report = valid_pair()
        original = copy.deepcopy(corpus)
        mutate(corpus, report)
        if corpus != original:
            payload = backend.corpus_json_bytes(corpus)
            report["corpus"]["sha256"] = sha(payload)
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
        corpus, payload, report = valid_pair()
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(backend.report_json_bytes(report))
            loaded, _ = backend.load_report(path)
            checked = backend.validate_corpus_report_pair(corpus, payload, loaded)
            self.assertEqual(checked["summary"]["passed"], 1)
            # The synthetic program is not the reviewed one, so the committed corpus refuses it even
            # when the report is otherwise bound to that corpus.
            report["corpus"]["sha256"] = sha(adapter.CORPUS_PATH.read_bytes())
            path.write_bytes(backend.report_json_bytes(report))
            with self.assertRaisesRegex(BehaviorCorpusError, "normalized digest differs from the corpus"):
                adapter.verify_supplemental_pair(adapter.CORPUS_PATH, path)
            path.write_bytes(json.dumps(report).encode())
            with self.assertRaisesRegex(BehaviorCorpusError, "canonical JSON"):
                backend.load_report(path)

    def test_consistently_replaced_artifact_is_rejected(self) -> None:
        def mutate(corpus, report):
            for run, name in zip(report["cases"][0]["runs"], (b"abcdef", b"123abc")):
                run["artifacts"] = [artifact(synthetic_program(name) + b"forged", corpus)]
        self.assert_pair_rejected(mutate, "normalized digest differs from the corpus")

    def test_single_repetition_artifact_is_still_pinned(self) -> None:
        def mutate(corpus, report):
            corpus["cases"][0]["repetitions"] = 1
            del report["cases"][0]["runs"][1]
            report["cases"][0]["runs"][0]["artifacts"] = [artifact(synthetic_program(b"abcdef") + b"x", corpus)]
        corpus, _, report = valid_pair()
        mutate(corpus, report)
        payload = backend.corpus_json_bytes(corpus)
        report["corpus"]["sha256"] = sha(payload)
        with self.assertRaisesRegex(BehaviorCorpusError, "normalized digest differs from the corpus"):
            backend.validate_corpus_report_pair(corpus, payload, report)

    def test_report_rules_are_bound_to_the_corpus_before_they_run(self) -> None:
        corpus, payload, report = valid_pair()
        # Well-formed but never matching: applying it first would fail with "matched 0 times".
        report["artifactNormalizations"][0]["pattern"] = "zzzz"
        backend.validate_report(copy.deepcopy(report))
        with self.assertRaisesRegex(BehaviorCorpusError, "artifactNormalizations differs from the corpus"):
            backend.validate_corpus_report_pair(corpus, payload, report)

    def test_report_with_a_backtracking_rule_is_rejected_structurally(self) -> None:
        _, _, report = valid_pair()
        report["artifactNormalizations"][0]["pattern"] = "(?:a|aa)+$"
        with self.assertRaisesRegex(BehaviorCorpusError, "may only use literals"):
            backend.validate_report(report)

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
        self.assert_pair_rejected(mutate, "run 1 artifact program normalized digest differs")

    def test_forged_normalized_hash_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["artifacts"][0]["normalizedSha256"] = "f" * 64
        self.assert_pair_rejected(mutate, "normalizedSha256 does not match its content")

    def test_unknown_normalization_is_rejected(self) -> None:
        def mutate(_, report):
            report["cases"][0]["runs"][0]["artifacts"][0]["normalizations"] = ["other-rule"]
        self.assert_pair_rejected(mutate, "unknown rule")

    def test_normalization_must_match_exactly_once(self) -> None:
        corpus = synthetic_corpus()
        twice = synthetic_program(b"abcdef") + b"start-012345.o\0"
        with self.assertRaisesRegex(BehaviorCorpusError, "matched 2 times"):
            artifact(twice, corpus)
        never = synthetic_program(b"ABCDEF")
        with self.assertRaisesRegex(BehaviorCorpusError, "matched 0 times"):
            artifact(never, corpus)

    @staticmethod
    def replace_programs(corpus: dict, report: dict, **options) -> None:
        """Replace both runs' programs and repin the corpus digest, so only the ELF check differs."""
        for run, name in zip(report["cases"][0]["runs"], (b"abcdef", b"123abc")):
            run["artifacts"] = [artifact(synthetic_program(name, **options), corpus)]
        digest = report["cases"][0]["runs"][0]["artifacts"][0]["normalizedSha256"]
        corpus["cases"][0]["expected"]["artifacts"][0]["normalizedSha256"] = digest

    def test_dynamic_program_is_rejected(self) -> None:
        def mutate(corpus, report):
            self.replace_programs(corpus, report, interpreter=True)
        self.assert_pair_rejected(mutate, "no interpreter or dynamic section")

    def test_wrong_machine_program_is_rejected(self) -> None:
        def mutate(corpus, report):
            self.replace_programs(corpus, report, machine=183)
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

    def test_storage_and_syscall_policy_substitutions_are_rejected(self) -> None:
        for field, value in (("storagePolicy", "polling-only"),
                             ("syscallPolicy", {"id": "bounded-file-storage-v1", "sha256": "0" * 64})):
            with self.subTest(field=field):
                corpus = adapter.build_corpus()
                corpus["sandbox"][field] = value
                with self.assertRaises(BehaviorCorpusError):
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
            lambda c: c["artifactNormalizations"][0].update(pattern="(start)"), "may only use literals"
        )
        self.assert_corpus_rejected(
            lambda c: c["artifactNormalizations"][0].update(pattern="x*"), "may only use literals"
        )

    def test_only_fixed_width_deterministic_patterns_are_accepted(self) -> None:
        for pattern in ("start-[0-9a-f]{6}\\.o\\x00", "abc", "[^a-z\\]]{3}x", "\\x00{64}", "[a-]z"):
            backend._pattern_width(pattern, "pattern")
        rejected = {
            "(?:a|aa)+$": "may only use literals",
            "a|b": "may only use literals",
            "a+": "may only use literals",
            "a{1,3}": "repeats must be exact",
            "a{0}": "repeats must be exact",
            "a{65}": "repeats must be exact",
            ".": "may only use literals",
            "^a": "may only use literals",
            "\\d": "may only escape punctuation",
            "[]": "empty or unterminated",
            "[ab": "empty or unterminated",
            "[[a]]": "must not nest",
            "a{64}b": "between 1 and 64 bytes",
            "": "between 1 and 64 bytes",
        }
        for pattern, message in rejected.items():
            with self.subTest(pattern=pattern), self.assertRaisesRegex(BehaviorCorpusError, message):
                backend._pattern_width(pattern, "pattern")

    def test_missing_normalized_digest_is_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["cases"][0]["expected"]["artifacts"][0].pop("normalizedSha256"), "normalizedSha256"
        )

    def test_unrepresentable_report_limits_are_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["limits"].update(artifactBytes=128 * 1024 * 1024), "beyond the 67108864-byte retention limit"
        )
        self.assert_corpus_rejected(lambda c: c["cases"][0].update(repetitions=4), "retention limit")

    def test_committed_corpus_worst_case_report_fits(self) -> None:
        bound = backend.worst_case_report_bytes(adapter.build_corpus())
        self.assertLessEqual(bound, backend.MAX_REPORT_BYTES)

    def test_worst_case_bound_covers_a_maximal_report(self) -> None:
        corpus = synthetic_corpus()
        corpus["limits"].update(streamBytes=3001, artifactBytes=70001)
        corpus["id"] = "x" * 120
        corpus["cases"][0]["categories"] = [f"category-{index}-" + "c" * 100 for index in range(40)]
        corpus = backend.validate_corpus(corpus)
        _, _, report = valid_pair()
        report["limits"] = copy.deepcopy(corpus["limits"])
        report["corpus"]["id"] = corpus["id"]
        report["cases"][0]["id"] = corpus["cases"][0]["id"]
        report["cases"][0]["categories"] = corpus["cases"][0]["categories"]
        report["summary"]["categories"] = {category: 1 for category in sorted(corpus["cases"][0]["categories"])}
        full = backend.blob(b"\xff" * 3001)
        for run in report["cases"][0]["runs"]:
            for record in (run["compile"], run["execution"]):
                record.update(stdout=full, stderr=full, wallMillis=10 ** 6)
            run["artifacts"][0].update(backend.blob(b"\xff" * 70001))
        metadata = {key: report[key] for key in ("host", "hostTools", "libraries")}
        encoded = len(backend.report_json_bytes(report))
        bound = backend.worst_case_report_bytes(corpus) - backend.HOST_METADATA_RESERVE_BYTES
        self.assertLessEqual(encoded, bound + backend._json_bytes(metadata))

    def test_oversized_declared_command_is_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["cases"][0].update(arguments=["a" * 4096] * 64), "exceed the 262144-byte command bound"
        )
        self.assert_corpus_rejected(
            lambda c: c["cases"][0]["execute"].update(arguments=["a" * 4096] * 64), "execute.arguments"
        )

    def test_aggregate_limits_are_required_and_bounded(self) -> None:
        for name in ("processes", "writableBytes", "writableEntries"):
            with self.subTest(name=name):
                self.assert_corpus_rejected(lambda c, name=name: c["limits"].pop(name), "limits")
        self.assert_corpus_rejected(lambda c: c["limits"].update(processes=100000), "processes")
        self.assert_corpus_rejected(lambda c: c["limits"].update(writableEntries=1), "writableEntries")

    def test_unused_normalization_is_rejected(self) -> None:
        def mutate(corpus):
            corpus["cases"][0]["expected"]["artifacts"][0]["normalizations"] = []
        self.assert_corpus_rejected(mutate, "artifactNormalizations are unused")

    def test_execute_of_missing_artifact_is_rejected(self) -> None:
        self.assert_corpus_rejected(
            lambda c: c["cases"][0]["execute"].update(artifact="other"), "must name an expected artifact"
        )


class SandboxConstructionTests(unittest.TestCase):
    def test_compile_sandbox_has_no_dev_and_a_read_only_root(self) -> None:
        corpus = adapter.build_corpus()
        tools = [{"realPath": "/usr/bin/ld.bfd", "sandboxPath": "/usr/bin/ld"}]
        command = backend._compile_command(
            Path("/usr/bin/bwrap"), corpus, Path("/r/exe"), tools, ["/lib/libc.so.6"], Path("/r/work"),
            Path("/r/tmp"), ["-c", "x.s"],
        )
        self.assertNotIn("--dev", command)
        self.assertNotIn("--tmpfs", command)
        self.assertIn(["--bind", "/r/tmp", "/tmp"], [command[i:i + 3] for i in range(len(command))])
        boundary = len(command) - 1 - command[::-1].index("/oracle/clang")
        self.assertEqual(command[boundary - 2:boundary], ["--remount-ro", "/"])
        self.assertEqual(command[boundary + 1:], ["-c", "x.s"])

    def test_execute_sandbox_root_is_read_only_and_empty(self) -> None:
        command = backend._execute_command(Path("/usr/bin/bwrap"), adapter.build_corpus(), Path("/r/p"), ["a"])
        self.assertEqual(command[len(backend.BASE_ARGV) + 1:],
                         ["--ro-bind", "/r/p", "/oracle/program", "--remount-ro", "/", "--chdir", "/",
                          "/oracle/program", "a"])

    def test_host_architecture_is_bound_before_any_subject_or_process_access(self) -> None:
        with mock.patch.object(backend.platform, "machine", return_value="aarch64"), \
                mock.patch.object(backend.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(BehaviorCorpusError, "host architecture"):
                backend.run_corpus(adapter.build_corpus(), Path("/nonexistent/subject"),
                                   bwrap=Path("/usr/bin/bwrap"), temporary_root=Path("/nonexistent/root"))
        popen.assert_not_called()

    def test_root_is_refused(self) -> None:
        with mock.patch.object(backend.os, "getuid", return_value=0), \
                self.assertRaisesRegex(BehaviorCorpusError, "must not run as root"):
            backend._run_sandboxed(["/bin/true"], Path("/nonexistent"), adapter.build_corpus()["limits"], 1 << 20,
                                   artifacts=False)

    def test_oversized_spawned_command_is_refused_before_spawning(self) -> None:
        with mock.patch.object(backend.subprocess, "Popen") as popen, \
                self.assertRaisesRegex(BehaviorCorpusError, "argument bound"):
            backend._run_sandboxed(["x" * 4096] * 512, Path("/nonexistent"), adapter.build_corpus()["limits"],
                                   1 << 20, artifacts=False)
        popen.assert_not_called()

    def test_limit_setter_applies_the_aggregate_task_ceiling(self) -> None:
        limits = adapter.build_corpus()["limits"]
        tasks = backend.user_task_count() + limits["processes"]
        self.assertGreater(tasks, limits["processes"])
        result = subprocess.run(
            ["python3", "-I", "-S", "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_NPROC))"],
            preexec_fn=backend._limit_setter(limits, 1 << 30, tasks, artifacts=False),
            capture_output=True, text=True, check=True, env={},
        )
        self.assertEqual(result.stdout.strip(), str((tasks, tasks)))


class WritableQuotaTests(unittest.TestCase):
    LIMITS = {"writableEntries": 4, "writableBytes": 64 * 1024}

    def setUp(self) -> None:
        (ROOT / "build").mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.work, self.tmp = self.root / "work", self.root / "tmp"
        self.work.mkdir()
        self.tmp.mkdir()

    def violation(self):
        return backend.writable_usage_violation([self.work, self.tmp], self.LIMITS)

    def test_usage_within_quota_is_accepted(self) -> None:
        (self.work / "a").write_bytes(b"x" * 1000)
        (self.tmp / "b").write_bytes(b"y")
        self.assertIsNone(self.violation())

    def test_entries_are_counted_recursively_across_directories(self) -> None:
        nested = self.work / "d" / "e"
        nested.mkdir(parents=True)
        (nested / "f").write_bytes(b"")
        (self.tmp / "g").write_bytes(b"")
        self.assertIsNone(self.violation())
        (self.tmp / "h").write_bytes(b"")
        self.assertRegex(self.violation(), "entry quota of 4")

    def test_bytes_are_counted_across_directories(self) -> None:
        (self.work / "a").write_bytes(b"x" * 40 * 1024)
        (self.tmp / "b").write_bytes(b"x" * 40 * 1024)
        self.assertRegex(self.violation(), "byte quota of 65536")

    def test_sparse_files_count_their_apparent_size(self) -> None:
        with (self.tmp / "sparse").open("wb") as handle:
            handle.truncate(1024 * 1024)
        self.assertRegex(self.violation(), "byte quota")

    def test_unreadable_directory_is_a_violation(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permissions")
        hidden = self.work / "hidden"
        hidden.mkdir()
        hidden.chmod(0)
        self.addCleanup(hidden.chmod, 0o700)
        self.assertRegex(self.violation(), "unreadable")


ADVERSARY_SOURCE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int entries(void) {
    int count = 0;
    char path[64];
    for (; count < 128; count++) {
        snprintf(path, sizeof path, "d%d", count);
        if (mkdir(path, 0755) != 0) break;
        if (chdir(path) != 0) return 3;
    }
    int bounded = count < 128 && errno == ENOSPC;
    for (int i = count - 1; i >= 0; i--) {
        if (chdir("..") != 0) return 4;
        snprintf(path, sizeof path, "d%d", i);
        if (rmdir(path) != 0) return 5;
    }
    puts(bounded ? "bounded entries" : "unbounded entries");
    return 0;
}

static int bytes(int remove_names) {
    static char chunk[1024 * 1024];
    int descriptors[16], count = 0, bounded = 0;
    char path[64];
    memset(chunk, 'x', sizeof chunk);
    for (; count < 16; count++) {
        snprintf(path, sizeof path, "/tmp/f%d", count);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) { bounded = errno == ENOSPC; break; }
        descriptors[count] = fd;
        if (remove_names && unlink(path) != 0) return 6;
        ssize_t written = write(fd, chunk, sizeof chunk);
        if (written < (ssize_t)sizeof chunk) {
            // A short write at the quota boundary must be followed by ENOSPC.
            bounded = written < 0 ? errno == ENOSPC : write(fd, chunk, 1) < 0 && errno == ENOSPC;
            count++;
            break;
        }
    }
    for (int i = 0; i < count; i++) {
        close(descriptors[i]);
        if (!remove_names) { snprintf(path, sizeof path, "/tmp/f%d", i); unlink(path); }
    }
    puts(bounded ? "bounded bytes" : "unbounded bytes");
    return 0;
}

static int forks(void) {
    int count = 0;
    for (; count < 500; count++) {
        pid_t child = fork();
        if (child == 0) { pause(); _exit(0); }
        if (child < 0) break;
    }
    printf(count < 500 && errno == EAGAIN && count < 16 ? "capped\n" : "uncapped %d\n", count);
    return 0;
}

static int readonly(void) {
    int writable = open("/escape", O_WRONLY | O_CREAT, 0644) >= 0 || mkdir("/oracle/escape", 0755) == 0;
    int device = access("/dev/null", F_OK) == 0;
    printf(writable || device ? "escaped\n" : "readonly\n");
    return 0;
}


static int nested_namespaces(void) {
    int result = unshare(CLONE_NEWUSER);
    puts(result < 0 && (errno == EPERM || errno == ENOSPC) ? "blocked namespaces" : "unblocked namespaces");
    return 0;
}

static int anonymous_storage(void) {
    int descriptor = syscall(SYS_memfd_create, "escape", 0);
    int memfd_blocked = descriptor < 0 && errno == EPERM;
    if (descriptor >= 0) close(descriptor);
    int segment = shmget(IPC_PRIVATE, 128 * 1024, IPC_CREAT | 0600);
    int sysv_blocked = segment < 0 && errno == EPERM;
    if (segment >= 0) shmctl(segment, IPC_RMID, 0);
    puts(memfd_blocked && sysv_blocked ? "blocked anonymous storage" : "unblocked anonymous storage");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "entries")) return entries();
    if (!strcmp(argv[1], "bytes")) return bytes(0);
    if (!strcmp(argv[1], "unlinked")) return bytes(1);
    if (!strcmp(argv[1], "forks")) return forks();
    if (!strcmp(argv[1], "readonly")) return readonly();
    if (!strcmp(argv[1], "namespaces")) return nested_namespaces();
    if (!strcmp(argv[1], "anonymous")) return anonymous_storage();
    return 2;
}
"""


@unittest.skipUnless(os.environ.get("BEHAVIOR_CORPUS_BWRAP_LIVE") == "1", "set BEHAVIOR_CORPUS_BWRAP_LIVE=1")
class LiveAggregateBoundTests(unittest.TestCase):
    """Run an adversarial executable through run_corpus under the real bubblewrap and kernel.

    Explicitly requested live verification fails rather than skips when a prerequisite is missing.
    """

    BWRAP = Path("/usr/bin/bwrap")

    @classmethod
    def setUpClass(cls) -> None:
        compiler = next((name for name in ("cc", "gcc", "clang") if subprocess.run(
            ["sh", "-c", f"command -v {name}"], capture_output=True).returncode == 0), None)
        if not cls.BWRAP.is_file() or compiler is None:
            raise AssertionError("live controls require /usr/bin/bwrap and a host C compiler")
        (ROOT / "build").mkdir(exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(dir=ROOT / "build")
        cls.root = Path(cls.directory.name)
        source = cls.root / "adversary.c"
        source.write_text(ADVERSARY_SOURCE)
        cls.executable = cls.root / "adversary"
        subprocess.run([compiler, "-O1", "-o", os.fspath(cls.executable), os.fspath(source)], check=True)
        cls.payload = cls.executable.read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def corpus(self, mode: str, stdout: bytes = b"") -> dict:
        return backend.validate_corpus({
            "schemaVersion": 1,
            "scope": "fixture",
            "id": f"aggregate-bound-{mode}",
            "executable": {"bytes": len(self.payload), "sha256": sha(self.payload)},
            "sandbox": {
                "backend": backend.BACKEND,
                "profile": "aggregate-bound-control",
                "baseArgv": list(backend.BASE_ARGV),
                "executablePath": "/oracle/exe",
                "workspacePath": "/work",
                "programPath": "/oracle/program",
                "executeElfMachine": 62,
                "hostTools": [],
                "storagePolicy": backend.STORAGE_POLICY_ID,
                "syscallPolicy": backend.storage_filter_identity(62),
            },
            "environment": {},
            "limits": {
                "wallSeconds": 10, "cpuSeconds": 10, "streamBytes": 4096, "artifactBytes": 1024 * 1024 + 4096,
                "compileAddressSpaceBytes": 1024 ** 3, "executeAddressSpaceBytes": 64 * 1024 * 1024,
                "openFiles": 64, "closureLibraries": 64, "workspaceEntries": 2,
                "processes": 8 if mode == "forks" else 32,
                "writableBytes": 4 * 1024 * 1024, "writableEntries": 64,
            },
            "artifactNormalizations": [],
            "cases": [{
                "id": mode,
                "categories": ["aggregate-bound"],
                "repetitions": 1,
                "arguments": [mode],
                "inputs": [],
                "expected": {"exitCode": 0, "stdout": backend.blob(stdout), "stderr": backend.blob(b""),
                             "artifacts": []},
                "execute": None,
            }],
        })

    def run_mode(self, mode: str, stdout: bytes = b"") -> dict:
        return backend.run_corpus(self.corpus(mode, stdout), self.executable, bwrap=self.BWRAP,
                                  temporary_root=self.root)

    def test_entry_flood_is_capped_by_the_kernel(self) -> None:
        report = self.run_mode("entries", b"bounded entries\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_byte_flood_in_tmp_is_capped_by_the_kernel(self) -> None:
        report = self.run_mode("bytes", b"bounded bytes\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_open_unlinked_byte_flood_is_capped_by_the_kernel(self) -> None:
        report = self.run_mode("unlinked", b"bounded bytes\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_nested_user_namespace_cannot_replace_the_quota_mount(self) -> None:
        report = self.run_mode("namespaces", b"blocked namespaces\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_anonymous_storage_cannot_bypass_the_filesystem_quota(self) -> None:
        report = self.run_mode("anonymous", b"blocked anonymous storage\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_fork_flood_is_capped_by_the_aggregate_task_limit(self) -> None:
        report = self.run_mode("forks", b"capped\n")
        self.assertEqual(report["summary"]["passed"], 1)

    def test_root_is_read_only_and_dev_is_absent(self) -> None:
        report = self.run_mode("readonly", b"readonly\n")
        self.assertEqual(report["summary"]["passed"], 1)


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
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            manifest = Path(directory) / "oracle-manifest.json"
            manifest.write_text("{}")
            with self.assertRaisesRegex(BehaviorCorpusError, "manifest identity mismatch"):
                adapter.locate_clang(manifest, Path(directory))


if __name__ == "__main__":
    unittest.main()
