from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.behavior_corpus import (  # noqa: E402
    BehaviorCorpusError,
    ExactExecutorProfileMismatch,
    corpus_json_bytes,
    load_corpus,
    load_report,
    report_json_bytes,
    validate_corpus_report_pair,
)
from oracle.gcc.behavior_corpus import (  # noqa: E402
    run_gcc_behavior_corpus,
    verify_gcc_executor_profile,
)
from oracle.gcc.generate_behavior_corpus import (  # noqa: E402
    build_draft,
    generate_corpus,
    sandbox_profile,
)


PROFILE = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
CORPUS = PROFILE / "behavior-corpus.json"
EVIDENCE = PROFILE / "behavior-corpus-evidence.json"
MANIFEST = PROFILE / "oracle-manifest.json"
EXECUTABLE = PROFILE / "artifacts/gcc-driver.stripped"
IMAGE_DIGEST = "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248"


class GccBehaviorCorpusTest(unittest.TestCase):
    runtime: Path | None
    runtime_environment: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        configured_runtime = os.environ.get("DOCKER")
        fallback_runtime = Path("/tmp/decomp-docker/bin/docker")
        discovered_runtime = (
            configured_runtime
            or shutil.which("docker")
            or (os.fspath(fallback_runtime) if fallback_runtime.is_file() else None)
        )
        cls.runtime = Path(discovered_runtime) if discovered_runtime else None
        configured_host = os.environ.get("DOCKER_HOST")
        fallback_socket = Path("/tmp/decomp-docker/runtime/docker.sock")
        if configured_host:
            cls.runtime_environment = {"DOCKER_HOST": configured_host}
        elif fallback_socket.exists():
            cls.runtime_environment = {"DOCKER_HOST": f"unix://{fallback_socket}"}
        else:
            cls.runtime_environment = {}
        if cls.runtime is not None:
            try:
                verify_gcc_executor_profile(
                    cls.runtime,
                    container_runtime_environment=cls.runtime_environment,
                )
            except ExactExecutorProfileMismatch:
                cls.runtime = None

    def require_runtime(self) -> Path:
        if self.runtime is None:
            self.skipTest("production corpus requires the locked OCI sandbox image")
        return self.runtime

    def test_checked_corpus_covers_every_issue_category_with_exact_observations(self) -> None:
        corpus, payload = load_corpus(CORPUS)
        self.assertEqual(payload, corpus_json_bytes(corpus))
        self.assertEqual("production", corpus["scope"])
        self.assertEqual(14, len(corpus["cases"]))
        categories = {
            category for case in corpus["cases"] for category in case["categories"]
        }
        self.assertTrue(
            {
                "metadata",
                "target-query",
                "help",
                "diagnostics",
                "preprocessing",
                "stdin",
                "file-compile",
                "assembly",
                "linking",
                "response-files",
                "environment-search-paths",
                "invalid-inputs",
                "exit-status",
                "stdout",
                "stderr",
                "artifacts",
            }.issubset(categories)
        )
        for case in corpus["cases"]:
            self.assertIn("exitCode", case["expected"])
            for field in ("stdin",):
                self.assertEqual(
                    case[field]["bytes"],
                    len(base64.b64decode(case[field]["base64"], validate=True)),
                )
            for field in ("stdout", "stderr"):
                self.assertEqual(
                    case["expected"][field]["bytes"],
                    len(
                        base64.b64decode(
                            case["expected"][field]["base64"], validate=True
                        )
                    ),
                )

    def test_generic_contract_contains_no_gcc_identity_or_driver_rules(self) -> None:
        generic_files = [
            REPOSITORY_ROOT / "oracle/behavior_corpus.py",
            REPOSITORY_ROOT / "oracle/behavior-corpus.schema.json",
            REPOSITORY_ROOT / "oracle/behavior-corpus-report.schema.json",
            REPOSITORY_ROOT / "scripts/run-behavior-corpus.py",
            REPOSITORY_ROOT / "scripts/check-behavior-corpus-evidence.py",
        ]
        for path in generic_files:
            self.assertNotIn("gcc", path.read_text(encoding="utf-8").lower(), path.name)

    def test_checked_schemas_validate_production_corpus_and_evidence(self) -> None:
        try:
            import fastjsonschema
        except ImportError as error:
            self.skipTest(f"fastjsonschema unavailable: {error}")
        corpus_schema = json.loads(
            (REPOSITORY_ROOT / "oracle/behavior-corpus.schema.json").read_text()
        )
        report_schema = json.loads(
            (REPOSITORY_ROOT / "oracle/behavior-corpus-report.schema.json").read_text()
        )
        fastjsonschema.compile(corpus_schema)(json.loads(CORPUS.read_text()))
        fastjsonschema.compile(report_schema)(json.loads(EVIDENCE.read_text()))

        corpus, corpus_payload = load_corpus(CORPUS)
        report, _ = load_report(EVIDENCE)
        self.assertIs(
            report,
            validate_corpus_report_pair(
                corpus,
                report,
                corpus_payload=corpus_payload,
            ),
        )

    def test_profile_records_successful_driver_orchestration_not_shim_failures(self) -> None:
        corpus, _ = load_corpus(CORPUS)
        cases = {case["id"]: case for case in corpus["cases"]}
        self.assertEqual(1, cases["diagnostic-invalid-input"]["expected"]["exitCode"])
        self.assertEqual(1, cases["diagnostic-invalid-option"]["expected"]["exitCode"])
        for identifier in set(cases) - {
            "diagnostic-invalid-input",
            "diagnostic-invalid-option",
        }:
            self.assertEqual(0, cases[identifier]["expected"]["exitCode"], identifier)
        environment_stderr = base64.b64decode(
            cases["environment-search-path"]["expected"]["stderr"]["base64"]
        )
        self.assertEqual(
            b"observed-compiler-path=/workspace/env-tools/cc1\n",
            environment_stderr,
        )
        linked = cases["linking"]["expected"]["artifacts"]
        self.assertEqual(
            [("linked.bin", True, "0o700")],
            [(item["path"], item["present"], item["mode"]) for item in linked],
        )

    def test_generator_reproduces_checked_corpus_bytes(self) -> None:
        generated = generate_corpus(
            EXECUTABLE,
            container_runtime=self.require_runtime(),
            container_runtime_environment=self.runtime_environment,
        )
        self.assertEqual(CORPUS.read_bytes(), corpus_json_bytes(generated))

    def test_generator_uses_one_bounded_stable_executable_snapshot(self) -> None:
        with mock.patch(
            "oracle.gcc.generate_behavior_corpus._read_regular_snapshot",
            side_effect=BehaviorCorpusError("executable changed while it was read"),
        ):
            with self.assertRaisesRegex(BehaviorCorpusError, "changed while"):
                build_draft(EXECUTABLE)

    def test_executor_probe_uses_the_authenticated_client_snapshot(self) -> None:
        original_payload = b"authenticated control client"
        replacement_payload = b"pathname replacement"
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.write_bytes(original_payload)
            runtime.chmod(0o500)

            def snapshot_and_swap(path: Path) -> bytes:
                self.assertEqual(runtime, path)
                payload = path.read_bytes()
                replacement = path.with_name("runtime-replacement")
                replacement.write_bytes(replacement_payload)
                replacement.chmod(0o500)
                os.replace(replacement, path)
                return payload

            def verify_staged(
                path: Path,
                environment: dict[str, str],
                _sandbox: dict[str, object],
            ) -> None:
                self.assertNotEqual(runtime, path)
                self.assertEqual(original_payload, path.read_bytes())
                self.assertEqual(0o500, path.stat().st_mode & 0o777)
                self.assertEqual(
                    {
                        "DOCKER_CONFIG": "/nonexistent",
                        "HOME": "/nonexistent",
                        "LANG": "C",
                        "LC_ALL": "C",
                    },
                    environment,
                )

            with mock.patch(
                "oracle.gcc.behavior_corpus._snapshot_control_client",
                side_effect=snapshot_and_swap,
            ), mock.patch(
                "oracle.gcc.behavior_corpus._verify_oci_runtime",
                side_effect=verify_staged,
            ):
                verify_gcc_executor_profile(runtime)
            self.assertEqual(replacement_payload, runtime.read_bytes())

    def test_executor_probe_skips_only_exact_profile_differences(self) -> None:
        probe = REPOSITORY_ROOT / "scripts/check-gcc-behavior-executor.py"
        for error, expected_status in (
            (ExactExecutorProfileMismatch("different kernel"), 78),
            (BehaviorCorpusError("daemon inspection failed"), 1),
        ):
            with self.subTest(error=type(error).__name__), mock.patch(
                "oracle.gcc.behavior_corpus.verify_gcc_executor_profile",
                side_effect=error,
            ), mock.patch.dict(os.environ, {"DOCKER": "/bin/true"}):
                with self.assertRaises(SystemExit) as exited:
                    runpy.run_path(os.fspath(probe), run_name="__main__")
                self.assertEqual(expected_status, exited.exception.code)

    def test_production_runner_reproduces_checked_evidence_bytes(self) -> None:
        report = run_gcc_behavior_corpus(
            CORPUS,
            MANIFEST,
            container_runtime=self.require_runtime(),
            container_runtime_environment=self.runtime_environment,
        )
        self.assertEqual(EVIDENCE.read_bytes(), report_json_bytes(report))
        self.assertEqual(14, report["summary"]["passed"])
        self.assertEqual(IMAGE_DIGEST, report["sandbox"]["imageDigest"])

    def test_adapter_rejects_manifest_runtime_or_artifact_substitution(self) -> None:
        corpus = build_draft(EXECUTABLE)
        runtime_mutation = copy.deepcopy(corpus)
        runtime_mutation["sandbox"]["imageDigest"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(BehaviorCorpusError, "executor profile"):
            from oracle.gcc.behavior_corpus import _authenticate_profile

            _authenticate_profile(runtime_mutation, MANIFEST)

        for mutate in (
            lambda sandbox: sandbox["preExecArgv"].append("changed"),
            lambda sandbox: sandbox["keeperArgv"].append("changed"),
            lambda sandbox: sandbox["imageEnvironment"].append("EXTRA=value"),
            lambda sandbox: sandbox["controlClient"].update({"version": "changed\n"}),
            lambda sandbox: sandbox["engineProfile"].update(
                {"containerRuntimeVersion": "changed"}
            ),
        ):
            profile_mutation = copy.deepcopy(corpus)
            mutate(profile_mutation["sandbox"])
            with self.assertRaisesRegex(BehaviorCorpusError, "executor profile"):
                _authenticate_profile(profile_mutation, MANIFEST)

        artifact_mutation = copy.deepcopy(corpus)
        artifact_mutation["executable"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(BehaviorCorpusError, "verified stripped twin"):
            from oracle.gcc.behavior_corpus import _authenticate_profile

            _authenticate_profile(artifact_mutation, MANIFEST)

    def test_adapter_rejects_build_record_change_after_manifest_verification(self) -> None:
        import oracle.gcc.behavior_corpus as adapter

        corpus = build_draft(EXECUTABLE)
        with tempfile.TemporaryDirectory() as temporary:
            staged_profile = Path(temporary) / "profile"
            shutil.copytree(PROFILE, staged_profile)
            staged_manifest = staged_profile / "oracle-manifest.json"
            real_verify = adapter.verify_oracle_manifest

            def verify_then_mutate(path: Path) -> dict[str, object]:
                verified = real_verify(path)
                build_path = staged_profile / "build-record.json"
                payload = build_path.read_bytes()
                mutated = payload.replace(b'"CFLAGS": "-O1', b'"CFLAGS": "-O2', 1)
                self.assertEqual(len(payload), len(mutated))
                self.assertNotEqual(payload, mutated)
                build_path.write_bytes(mutated)
                return verified

            with mock.patch.object(
                adapter, "verify_oracle_manifest", side_effect=verify_then_mutate
            ):
                with self.assertRaisesRegex(
                    BehaviorCorpusError, "no longer matches the verified manifest"
                ):
                    adapter._authenticate_profile(corpus, staged_manifest)


if __name__ == "__main__":
    unittest.main()
