#!/usr/bin/env python3
"""Offline controls for the #1833 matrix collector."""

from __future__ import annotations

import importlib.util
import json
import os
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path


SCRIPT = Path(__file__).with_name("profile-1833-matrix.py")
SPEC = importlib.util.spec_from_file_location("profile_1833_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class Profile1833MatrixTests(unittest.TestCase):
    def test_runtime_identity_probe_pins_jvm_writable_paths_inside_build(self) -> None:
        build_root = MATRIX.ROOT / "build"
        build_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_root) as scratch:
            root = Path(scratch)
            java = root / "jdk/bin/java"
            java.parent.mkdir(parents=True)
            java.write_bytes(b"fake pinned java executable")
            install = root / "install"
            cli = install / "bin/llm_bin_patch"
            cli.parent.mkdir(parents=True)
            cli.write_bytes(b"fake cli")
            library = install / "lib"
            library.mkdir()
            (library / "gcc-bundled-ghidra-reference-v1.json").write_text("{}", encoding="utf-8")
            (library / "app.jar").write_bytes(b"jar")

            calls: list[tuple[list[str], dict[str, object]]] = []

            def run(command, **kwargs):
                calls.append((command, kwargs))
                if command == [str(java), "-version"]:
                    return subprocess.CompletedProcess(command, 0, stdout=b"OpenJDK test version\n")
                if command == ["git", "rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(command, 0, stdout="test-commit\n", stderr="")
                raise AssertionError(f"unexpected runtime identity command: {command}")

            with mock.patch.object(MATRIX, "ROOT", root), \
                    mock.patch.dict(os.environ, {"JAVA_HOME": str(root / "jdk"), "PATH": os.environ.get("PATH", "")}), \
                    mock.patch.object(MATRIX.platform, "platform", return_value="Linux-test"), \
                    mock.patch.object(MATRIX.subprocess, "run", side_effect=run):
                result = MATRIX.host_pins(cli)

            self.assertEqual(result["javaPath"], str(java.resolve()))
            self.assertEqual(result["javaVersion"], "OpenJDK test version\n")
            java_call, kwargs = calls[0]
            self.assertEqual(java_call, [str(java), "-version"])
            self.assertEqual(kwargs["cwd"], root)
            environment = kwargs["env"]
            self.assertIn("-Duser.home=\"", environment["JAVA_TOOL_OPTIONS"])
            self.assertIn("-Djava.io.tmpdir=\"", environment["JAVA_TOOL_OPTIONS"])
            self.assertIn("-Djna.tmpdir=\"", environment["JAVA_TOOL_OPTIONS"])
            self.assertIn("-XX:-UsePerfData", environment["JAVA_TOOL_OPTIONS"])
            for key in ("user.home", "java.io.tmpdir", "jna.tmpdir"):
                value = environment["JAVA_TOOL_OPTIONS"].split(f"-D{key}=\"", 1)[1].split('"', 1)[0]
                self.assertTrue(Path(value).is_relative_to(root / "build" / "profile-1833-host-pins"))

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
            with tempfile.TemporaryDirectory(dir=MATRIX.ROOT, prefix="matrix JVM env ") as scratch:
                path = Path(scratch)
                home = path / "home dir"
                temporary = path / "tmp dir"
                home.mkdir()
                temporary.mkdir()
                env = MATRIX.safe_environment(home, temporary)
                self.assertNotIn("OPENAI_API_KEY", env)
                self.assertNotIn("GHIDRA_HOME", env)
                self.assertNotIn("credential", env["JAVA_TOOL_OPTIONS"])
                self.assertIn(f'-Duser.home="{home}"', env["JAVA_TOOL_OPTIONS"])
                self.assertIn(f'-Djava.io.tmpdir="{temporary}"', env["JAVA_TOOL_OPTIONS"])
                self.assertIn(f'-Djna.tmpdir="{temporary}"', env["JAVA_TOOL_OPTIONS"])
                self.assertIn("-XX:-UsePerfData", env["JAVA_TOOL_OPTIONS"])
                self.assertEqual(env["HOME"], str(home))
                self.assertEqual(env["TMPDIR"], str(temporary))

                java_home = env.get("JAVA_HOME")
                java = Path(java_home) / "bin/java" if java_home else Path(shutil.which("java", path=env["PATH"]) or "")
                self.assertTrue(java.is_file(), "the matrix runner must have a Java runtime")
                completed = subprocess.run(
                    [str(java), "-XshowSettings:properties", "-version"], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout[-2000:])
                for name, expected in (("user.home", str(home)), ("java.io.tmpdir", str(temporary)),
                    ("jna.tmpdir", str(temporary))):
                    self.assertIn(f"{name} = {expected}", completed.stdout)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_child_environment_rejects_external_jvm_directories(self) -> None:
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            path = Path(scratch)
            home = path / "home"
            home.mkdir()
            with self.assertRaisesRegex(MATRIX.MatrixError, "repository-local directory"):
                MATRIX.safe_environment(home, Path("/tmp"))

    def test_only_new_regular_uuid_run_directories_are_counted(self) -> None:
        run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            output = Path(scratch)
            history = output / "run-history"
            history.mkdir()
            (history / run_id).mkdir()
            (history / "not-a-run").mkdir()
            self.assertEqual(MATRIX.history_ids(output), {run_id})

    def test_invocation_timestamp_ignores_restored_history_when_input_switches_back(self) -> None:
        prior_input_run = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        new_input_run = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        started = datetime(2026, 11, 4, 12, 0, 1, tzinfo=timezone.utc)
        completed = datetime(2026, 11, 4, 12, 0, 3, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory(dir=MATRIX.ROOT) as scratch:
            output = Path(scratch)
            history = output / "run-history"
            history.mkdir()
            for run_id, timestamp in ((prior_input_run, "2026-11-04T12:00:00Z"),
                (new_input_run, "2026-11-04T12:00:02Z")):
                directory = history / run_id
                directory.mkdir()
                (directory / "run.json").write_text(json.dumps({
                    "schemaVersion": 1, "displayOnly": True, "runId": run_id,
                    "workflow": "reconstruction", "startedAt": timestamp,
                    "state": "closed", "complete": True,
                }), encoding="utf-8")
            self.assertEqual(MATRIX.history_ids_started_during(output, started, completed), [new_input_run])

    def test_profile_switch_is_recorded_only_for_exact_refusal_without_output_changes(self) -> None:
        before = {"source-tree.zip": "a" * 64, "reconstruction.json": "b" * 64}
        classified = MATRIX.classify_profile_switch_refusal(1,
            "reconstruction failed: " + MATRIX.PROFILE_SWITCH_REFUSAL, before, dict(before))
        self.assertEqual(classified["status"], "refused")
        self.assertTrue(classified["generatedOutputUnchanged"])
        with self.assertRaisesRegex(MATRIX.MatrixError, "expected evidence-carrier refusal"):
            MATRIX.classify_profile_switch_refusal(1, "compiler failed", before, dict(before))
        with self.assertRaisesRegex(MATRIX.MatrixError, "unexpectedly succeeded"):
            MATRIX.classify_profile_switch_refusal(0, MATRIX.PROFILE_SWITCH_REFUSAL, before, dict(before))
        after = dict(before, **{"source-tree.zip": "c" * 64})
        with self.assertRaisesRegex(MATRIX.MatrixError, "changed generated output"):
            MATRIX.classify_profile_switch_refusal(1,
                "reconstruction failed: " + MATRIX.PROFILE_SWITCH_REFUSAL, before, after)

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
from datetime import datetime, timezone
run_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
if sys.argv[1] == "reconstruct":
    binary = pathlib.Path(sys.argv[2])
    output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    input_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    history = output / "run-history" / run_id
    history.mkdir(parents=True)
    (history / "run.json").write_text(json.dumps({"state":"closed","complete":True,"runId":run_id,
      "startedAt":datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
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
        "project-open-import-pre-analysis","auto-analysis","exporter:ExportProgramModelOwned.java")]
    record = {"schemaVersion":1,"instrumentationVersion":"analysis-timing-pre-analysis-boundary-v2",
      "analysisInvocationId":"cccccccc-cccc-cccc-cccc-cccccccccccc",
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
