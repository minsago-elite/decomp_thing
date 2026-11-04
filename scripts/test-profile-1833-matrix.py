#!/usr/bin/env python3
"""Offline controls for the #1833 matrix collector."""

from __future__ import annotations

import importlib.util
import json
import os
import hashlib
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("profile-1833-matrix.py")
SPEC = importlib.util.spec_from_file_location("profile_1833_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class Profile1833MatrixTests(unittest.TestCase):
    def test_archival_and_gcc_inputs_match_repository_pins(self) -> None:
        inputs = MATRIX.fixtures()
        self.assertEqual(inputs["large_project_mtu"]["sha256"],
            "940ea9fd464d194b3e3ea9e8cfaac9ae084afb5fe12fc4b14ca933a0d9819ea7")
        self.assertEqual(inputs["large_project"]["sha256"],
            "0c6da08bcb7ca936d20e76e816bf5bab2e94393cf5f2c7bf0a40d752c8b82bd1")
        driver = inputs["gcc_driver"]
        self.assertEqual(driver["manifest"], MATRIX.DRIVER_PROFILE)
        self.assertEqual(driver["identityManifest"], "oracle/gcc/reconstruction-neutrality-identities.json")
        self.assertEqual(MATRIX.sha256_file(driver["path"]), driver["sha256"])
        self.assertTrue(driver["manifestSha256"])
        self.assertTrue(driver["identityManifestSha256"])

    def test_driver_profile_cross_checks_binary_and_identity_manifest(self) -> None:
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            root = Path(scratch)
            profile_root = root / "oracle/gcc"
            binary = profile_root / "fixture.bin"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"pinned profile fixture")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            catalog = profile_root / "identities.json"
            catalog.write_text(json.dumps({"schemaVersion": 1, "identities": [
                {"name": "fixture-driver", "sha256": digest}]}), encoding="utf-8")
            profile = profile_root / "analysis-timing-profile-v1.json"
            value = {"schemaVersion": 1, "driver": {"id": "fixture_driver", "path": "fixture.bin",
                "sha256": digest, "identityName": "fixture-driver", "identityManifest": "identities.json"}}
            profile.write_text(json.dumps(value), encoding="utf-8")

            loaded = MATRIX.load_driver_fixture(root)
            self.assertEqual(loaded["path"], binary)
            self.assertEqual(loaded["sha256"], digest)
            self.assertEqual(loaded["identityName"], "fixture-driver")

            value["driver"]["path"] = "../outside.bin"
            profile.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.MatrixError, "unsafe binary path"):
                MATRIX.load_driver_fixture(root)

    def test_driver_profile_rejects_digest_and_catalog_substitution(self) -> None:
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            root = Path(scratch)
            profile_root = root / "oracle/gcc"
            profile_root.mkdir(parents=True)
            binary = profile_root / "fixture.bin"
            binary.write_bytes(b"pinned profile fixture")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            catalog = profile_root / "identities.json"
            catalog.write_text(json.dumps({"schemaVersion": 1, "identities": [
                {"name": "fixture-driver", "sha256": digest}]}), encoding="utf-8")
            profile = profile_root / "analysis-timing-profile-v1.json"
            value = {"schemaVersion": 1, "driver": {"id": "fixture_driver", "path": "fixture.bin",
                "sha256": digest, "identityName": "fixture-driver", "identityManifest": "identities.json"}}
            profile.write_text(json.dumps(value), encoding="utf-8")

            binary.write_bytes(b"substituted driver bytes")
            with self.assertRaisesRegex(MATRIX.MatrixError, "binary digest differs"):
                MATRIX.load_driver_fixture(root)

            binary.write_bytes(b"pinned profile fixture")
            catalog.write_text(json.dumps({"schemaVersion": 1, "identities": [
                {"name": "fixture-driver", "sha256": "0" * 64}]}), encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.MatrixError, "identity does not match"):
                MATRIX.load_driver_fixture(root)

    def test_child_environment_excludes_provider_and_external_ghidra_settings(self) -> None:
        old = os.environ.copy()
        try:
            os.environ.update({"OPENAI_API_KEY": "secret", "GHIDRA_HOME": "/external/ghidra",
                "JAVA_TOOL_OPTIONS": "-Dcredential=secret"})
            with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
                path = Path(scratch)
                env = MATRIX.safe_environment(path / "home", path / "tmp")
                self.assertNotIn("OPENAI_API_KEY", env)
                self.assertNotIn("GHIDRA_HOME", env)
                self.assertNotIn("JAVA_TOOL_OPTIONS", env)
                self.assertEqual(env["HOME"], str(path / "home"))
                self.assertEqual(env["TMPDIR"], str(path / "tmp"))
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_only_new_regular_uuid_run_directories_are_counted(self) -> None:
        run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            output = Path(scratch)
            history = output / "run-history"
            history.mkdir()
            (history / run_id).mkdir()
            (history / "not-a-run").mkdir()
            self.assertEqual(MATRIX.history_ids(output), {run_id})

    def test_run_context_binds_input_profile_and_observation_counts(self) -> None:
        run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            run_directory = Path(scratch)
            event = {"sequence": 2, "event": {"kind": "run_context",
                "inputSha256": "a" * 64, "profileSha256": "b" * 64}}
            reused = {"sequence": 3, "event": {"kind": "module_checkpoint_reused"}}
            tasks = {"sequence": 1, "event": {"kind": "task_started"}}
            (run_directory / "events.jsonl").write_text(
                "\n".join(json.dumps(item) for item in (tasks, event, reused)) + "\n",
                encoding="utf-8")
            result = MATRIX.read_context(run_directory)
            self.assertEqual(result["inputSha256"], "a" * 64)
            self.assertEqual(result["profileSha256"], "b" * 64)
            self.assertEqual(result["agentTasks"], 1)
            self.assertEqual(result["reusedModuleCheckpoints"], 1)

    def test_rejects_multiple_or_unbounded_context_records(self) -> None:
        valid = {"event": {"kind": "run_context", "inputSha256": "a" * 64,
            "profileSha256": "b" * 64}}
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            run_directory = Path(scratch)
            events = run_directory / "events.jsonl"
            events.write_text("\n".join((json.dumps(valid),
                json.dumps(valid))) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.MatrixError, "exactly one run_context"):
                MATRIX.read_context(run_directory)
            events.write_bytes(b"x" * (64 * 1024 + 2) + b"\n")
            with self.assertRaisesRegex(MATRIX.MatrixError, "oversized event"):
                MATRIX.read_context(run_directory)

    def test_evidence_path_must_be_new_and_inside_build_without_symlink(self) -> None:
        candidate = MATRIX.ROOT / "build" / "matrix-test-output"
        self.assertEqual(MATRIX.require_repo_child(candidate, "evidence"), candidate.resolve())
        with self.assertRaisesRegex(MATRIX.MatrixError, "repository build"):
            MATRIX.require_repo_child(MATRIX.ROOT / "docs" / "not-evidence", "evidence")

    def test_exporter_progress_requires_terminal_bounded_counters(self) -> None:
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            output = Path(scratch)
            reports = output / "analysis/reports"
            reports.mkdir(parents=True)
            path = reports / "program_model.json.progress.json"
            path.write_text(json.dumps({"schemaVersion": 1, "phase": "complete", "completed": 10,
                "total": 10, "recovered": 7, "partial": 0, "failed": 0, "reused": 10}),
                encoding="utf-8")
            value, _ = MATRIX.read_exporter_progress(output)
            self.assertEqual(value["reused"], 10)
            path.write_text(json.dumps({"schemaVersion": 1, "phase": "planning", "completed": 10,
                "total": 10, "recovered": 7, "partial": 0, "failed": 0, "reused": 10}),
                encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.MatrixError, "terminal progress"):
                MATRIX.read_exporter_progress(output)

    def test_capture_run_replays_and_binds_history_sidecar_and_exporter_progress(self) -> None:
        run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        fake_cli_source = r'''#!/usr/bin/env python3
import hashlib, json, pathlib, sys
run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
if sys.argv[1] == "reconstruct":
    binary = pathlib.Path(sys.argv[2])
    output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    input_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    history = output / "run-history" / run_id
    history.mkdir(parents=True)
    (history / "run.json").write_text(json.dumps({"state":"closed","complete":True,"runId":run_id}), encoding="utf-8")
    event = {"event":{"kind":"run_context","inputSha256":input_sha,"profileSha256":"b"*64}}
    (history / "events.jsonl").write_text(json.dumps(event)+"\n", encoding="utf-8")
    reports = output / "analysis/reports"
    timing = reports / "analysis-timings"
    timing.mkdir(parents=True)
    def span(phase, domain, status):
        return {"phase":phase,"clockDomain":domain,"startOffsetNanos":1,"durationNanos":5,"status":status}
    parent = [span("analysis-invocation","parent-monotonic","succeeded"),
              span("process-launch-request-to-worker-entry-frame","parent-monotonic","succeeded")]
    worker = [span(p,"worker-monotonic","completed") for p in (
        "worker-entry-to-parent-permit","application-initialization",
        "project-import-analysis-pre-script","exporter:ExportProgramModelOwned.java")]
    record = {"schemaVersion":1,"analysisInvocationId":"cccccccc-cccc-cccc-cccc-cccccccccccc",
      "workflowRunId":run_id,"recoveryMode":"reuse","analysisToolSha256":"a"*64,
      "profileSha256":"b"*64,"configurationSha256":"c"*64,"inputSha256":input_sha,
      "exporterSha256":"d"*64,"parentTotalElapsedNanos":100,"workerTerminalElapsedNanos":100,
      "terminalStatus":"succeeded","workerTerminalStatus":"succeeded","spans":parent,"workerSpans":worker,
      "coverage":{"complete":True,"missingPhases":[],"truncated":False}}
    (timing / (record["analysisInvocationId"]+".json")).write_text(json.dumps(record), encoding="utf-8")
    (reports / "program_model.json.progress.json").write_text(json.dumps({"schemaVersion":1,"phase":"complete",
      "completed":1,"total":1,"recovered":1,"partial":0,"failed":0,"reused":1}), encoding="utf-8")
    raise SystemExit(0)
if sys.argv[1:] and sys.argv[1] == "runs":
    if len(sys.argv) > 2 and sys.argv[2] == "list":
        print(run_id + " 2026-11-04T00:00:00Z reconstruction closed complete")
    raise SystemExit(0)
raise SystemExit(2)
'''
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            base = Path(scratch)
            cli = base / "fake-cli"
            cli.write_text(fake_cli_source, encoding="utf-8")
            cli.chmod(0o700)
            binary = base / "input.bin"
            binary.write_bytes(b"pinned test fixture")
            fixture = {"path": binary, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
            output = base / "output"
            output.mkdir()
            evidence = base / "evidence"
            evidence.mkdir()
            result = MATRIX.capture_run(cli, output, fixture, "generated-c-make-v1", "fake-run", evidence, [0])
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["runId"], run_id)
            self.assertEqual(result["context"]["inputSha256"], fixture["sha256"])
            self.assertEqual(result["exporterProgress"]["reused"], 1)
            self.assertEqual(result["replayReturnCodes"], {"list": 0, "replay": 0})


if __name__ == "__main__":
    unittest.main()
