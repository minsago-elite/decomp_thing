from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.behavior_corpus import (  # noqa: E402
    load_corpus,
    load_report,
    validate_corpus,
    validate_corpus_report_pair,
)
from oracle.llvm.generate_behavior_corpus import build_draft, sandbox_profile  # noqa: E402
from oracle.llvm.generate_function_recovery_oracle import (  # noqa: E402
    _driver_compilation_unit,
    _driver_symbol,
)


class LlvmOracleProfilesTest(unittest.TestCase):
    PROFILE = REPOSITORY_ROOT / "oracle/llvm/22.1.6"

    def test_function_scope_is_explicit_and_program_owned(self) -> None:
        self.assertTrue(_driver_symbol("main"))
        self.assertTrue(_driver_symbol("_ZN5clang6driver6DriverC1Ev"))
        self.assertFalse(_driver_symbol("_ZN4llvm11raw_ostreamlsEj"))
        self.assertTrue(
            _driver_compilation_unit(
                "/usr/src/llvm-oracle/llvm-project-22.1.6.src/clang/lib/Driver/Driver.cpp"
            )
        )
        self.assertTrue(
            _driver_compilation_unit(
                "/usr/src/llvm-oracle/llvm-project-22.1.6.src/clang/tools/driver/driver.cpp"
            )
        )
        self.assertFalse(
            _driver_compilation_unit(
                "/usr/src/llvm-oracle/llvm-project-22.1.6.src/llvm/lib/IR/Module.cpp"
            )
        )

    def test_behavior_draft_is_closed_and_covers_driver_categories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "clang"
            executable.write_bytes(b"bounded fixture")
            executable.chmod(0o500)
            corpus = build_draft(executable)
        self.assertIs(corpus, validate_corpus(corpus))
        self.assertEqual("production", corpus["scope"])
        self.assertEqual(46, len(corpus["cases"]))
        categories = {
            category for case in corpus["cases"] for category in case["categories"]
        }
        self.assertTrue(
            {
                "metadata",
                "preprocessing",
                "file-compile",
                "diagnostics",
                "option-handling",
                "linking",
                "produced-program",
                "cxx",
                "objective-c",
                "llvm-ir",
                "assembly-emission",
                "dependency-output",
                "pch",
                "target-selection",
                "unsupported-mode",
                "fix-its",
                "color",
                "missing-tools",
            }.issubset(categories)
        )
        self.assertEqual(
            "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248",
            sandbox_profile()["imageDigest"],
        )

    def test_behavior_draft_binds_pch_reuse_and_invalidation_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "clang"
            executable.write_bytes(b"bounded fixture")
            executable.chmod(0o500)
            corpus = build_draft(executable, authenticated_pch=b"authenticated-pch")
        self.assertIs(corpus, validate_corpus(corpus))
        cases = {case["id"]: case for case in corpus["cases"]}
        self.assertEqual(48, len(cases))
        valid = cases["pch-reuse-valid"]
        invalid = cases["pch-reuse-wrong-target"]
        self.assertEqual(valid["inputs"], invalid["inputs"])
        pch = next(item for item in valid["inputs"] if item["path"] == "answer.pch")
        self.assertEqual(hashlib.sha256(b"authenticated-pch").hexdigest(), pch["sha256"])
        self.assertEqual(1, invalid["expected"]["exitCode"])

    def test_program_neutral_contracts_contain_no_llvm_identity(self) -> None:
        for relative in (
            "oracle/elf_oracle.py",
            "oracle/function_recovery_oracle.py",
            "oracle/behavior_corpus.py",
            "oracle/build-record.schema.json",
            "oracle/oracle-manifest.schema.json",
        ):
            path = REPOSITORY_ROOT / relative
            content = path.read_text(encoding="utf-8").lower()
            self.assertNotIn("clang-driver-22", content, relative)
            self.assertNotIn("clang-22-1-6", content, relative)
            self.assertNotIn("22.1.6", content, relative)

    def test_checked_behavior_evidence_covers_real_driver_outputs(self) -> None:
        corpus, corpus_payload = load_corpus(self.PROFILE / "behavior-corpus.json")
        report, _ = load_report(self.PROFILE / "behavior-corpus-evidence.json")
        self.assertIs(
            report,
            validate_corpus_report_pair(
                corpus,
                report,
                corpus_payload=corpus_payload,
            ),
        )
        self.assertEqual(48, report["summary"]["cases"])
        self.assertEqual(48, report["summary"]["passed"])
        self.assertEqual(
            {
                "bytes": 84561368,
                "sha256": "65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006",
            },
            report["executable"],
        )
        cases = {case["id"]: case for case in report["cases"]}
        self.assertEqual(1, cases["diagnostic-invalid-option"]["exitCode"])
        self.assertEqual(1, cases["diagnostic-syntax"]["exitCode"])
        self.assertEqual(1, cases["target-unsupported-aarch64"]["exitCode"])
        self.assertEqual(1, cases["driver-missing-linker"]["exitCode"])
        self.assertEqual(1, cases["pch-reuse-wrong-target"]["exitCode"])
        self.assertEqual(0, cases["pch-reuse-valid"]["exitCode"])
        self.assertEqual(0, cases["response-file-quoted-paths"]["exitCode"])
        self.assertEqual(0, cases["response-file-stdin"]["exitCode"])
        self.assertGreater(cases["diagnostic-color-always"]["stderr"]["bytes"], 0)
        self.assertGreater(cases["diagnostic-fixit"]["stderr"]["bytes"], 0)
        self.assertGreater(cases["diagnostic-template-backtrace"]["stderr"]["bytes"], 0)
        linked = cases["link-program"]["artifacts"]
        self.assertEqual(1, len(linked))
        self.assertEqual("program", linked[0]["path"])
        self.assertTrue(linked[0]["present"])
        self.assertEqual("0o755", linked[0]["mode"])
        self.assertGreater(linked[0]["bytes"], 0)
        emitted = {
            case_id: cases[case_id]["artifacts"][0]
            for case_id in (
                "assemble-valid",
                "emit-assembly",
                "emit-llvm-ir",
                "precompile-header",
                "target-i386-object",
            )
        }
        self.assertTrue(all(artifact["present"] for artifact in emitted.values()))
        self.assertTrue(all(artifact["bytes"] > 0 for artifact in emitted.values()))

    def test_diagnostic_matrix_retains_semantic_bytes_without_normalization(self) -> None:
        corpus, _ = load_corpus(self.PROFILE / "behavior-corpus.json")
        self.assertEqual([], corpus["normalizations"])
        cases = {case["id"]: case for case in corpus["cases"]}

        def stderr(identifier: str) -> bytes:
            return base64.b64decode(cases[identifier]["expected"]["stderr"]["base64"])

        self.assertIn(b"\x1b[", stderr("diagnostic-color-always"))
        self.assertNotIn(b"\x1b[", stderr("diagnostic-color-never"))
        self.assertIn(b'fix-it:"fixit.c":', stderr("diagnostic-fixit"))
        self.assertIn(b"[-Wunused-parameter]", stderr("diagnostic-warning-option"))
        self.assertIn(b"note: in instantiation of function template", stderr("diagnostic-template-backtrace"))
        self.assertIn(b"fatal error: 'absent.h' file not found", stderr("diagnostic-missing-include"))

    def test_checked_function_oracle_is_manifest_bound_and_driver_scoped(self) -> None:
        manifest_payload = (self.PROFILE / "oracle-manifest.json").read_bytes()
        document = json.loads(
            (self.PROFILE / "function-recovery-oracle.json").read_text(encoding="utf-8")
        )
        self.assertEqual("clang-driver-22.1.6", document["oracle"]["id"])
        self.assertEqual(
            hashlib.sha256(manifest_payload).hexdigest(),
            document["oracle"]["artifactManifestSha256"],
        )
        self.assertEqual(
            "c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a",
            document["artifacts"]["rich"]["inputSha256"],
        )
        self.assertEqual(
            "65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006",
            document["artifacts"]["stripped"]["inputSha256"],
        )
        self.assertEqual(4303, len(document["functions"]))
        self.assertTrue(all(function["exclusion"] is None for function in document["functions"]))
        names = {
            alias["name"]
            for function in document["functions"]
            for alias in function["aliases"]
        }
        self.assertIn("main", names)
        self.assertIn("clang_main", names)
        self.assertIn(
            "_ZN5clang6driver6Driver16BuildCompilationEN4llvm8ArrayRefIPKcEE",
            names,
        )
        rvas = [int(function["rva"], 16) for function in document["functions"]]
        self.assertEqual(sorted(set(rvas)), rvas)


class ProducedProgramObservationTest(unittest.TestCase):
    """Synthetic wire/ELF metadata only: no compiler, OCI, or ELF execution."""

    @staticmethod
    def inert_elf_metadata() -> bytes:
        import struct
        payload = bytearray(128)
        payload[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", payload, 16,
                         2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into("<IIQQQQQQ", payload, 64,
                         1, 5, 120, 0x400078, 0x400078, 8, 8, 1)
        return bytes(payload)

    @staticmethod
    def synthetic_report(corpus):
        import copy
        from oracle.behavior_corpus import corpus_json_bytes
        # An existing wire-template is reused, never called an execution observation.
        template = json.loads((LlvmOracleProfilesTest.PROFILE / "behavior-corpus-evidence.json").read_text())
        template["corpus"] = {"id": corpus["id"], "sha256": hashlib.sha256(corpus_json_bytes(corpus)).hexdigest()}
        template["executable"] = copy.deepcopy(corpus["executable"])
        template["limits"] = copy.deepcopy(corpus["limits"])
        template["summary"] = {"cases": 1, "passed": 1, "categories": corpus["cases"][0]["categories"]}
        template["cases"] = [{"id": corpus["cases"][0]["id"], "status": "passed",
                              **copy.deepcopy(corpus["cases"][0]["expected"])}]
        return template

    def synthetic_pair(self):
        import copy
        from oracle.llvm import produced_program as pair
        draft = pair.compile_corpus()
        artifact = {"path": "program", "present": True, "mode": "0o755",
                    **pair._blob(self.inert_elf_metadata())}
        draft["cases"][0]["expected"]["artifacts"] = [artifact]
        runtime = pair.execution_corpus(artifact)
        return {"schemaVersion": 1, "authority": dict(pair.AUTHORITY),
                "manifestSha256": pair.MANIFEST_SHA256, "sourceSha256": pair.SOURCE_SHA256,
                "compileCorpus": draft, "compileReport": self.synthetic_report(draft),
                "executionCorpus": runtime, "executionReport": self.synthetic_report(runtime),
                "producedArtifact": copy.deepcopy(artifact)}

    def test_closed_pair_preserves_historical_profile_and_finite_bounds(self):
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        self.assertIs(document, pair.verify_observation(document))
        historical, _ = load_corpus(LlvmOracleProfilesTest.PROFILE / "behavior-corpus.json")
        self.assertEqual(historical["limits"], document["executionCorpus"]["limits"])
        self.assertEqual(historical["sandbox"], document["executionCorpus"]["sandbox"])
        self.assertEqual(128, document["executionCorpus"]["limits"]["processes"])
        self.assertEqual(42, document["executionReport"]["cases"][0]["exitCode"])
        self.assertEqual(pair.MARKER, base64.b64decode(document["executionReport"]["cases"][0]["stdout"]["base64"]))
        self.assertFalse(document["authority"]["releaseQualified"])
        self.assertNotIn("-e,answer", " ".join(document["compileCorpus"]["cases"][0]["arguments"]))

    def test_missing_wrong_mutated_and_oversize_artifacts_refuse(self):
        import copy
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        base = self.synthetic_pair()
        mutations = [lambda a: a.update(present=False), lambda a: a.update(path="other"),
                     lambda a: a.update(mode="0o777"), lambda a: a.update(bytes=16777217),
                     lambda a: a.update(sha256="0" * 64), lambda a: a.update(base64="AA==")]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = copy.deepcopy(base)
                mutate(document["compileReport"]["cases"][0]["artifacts"][0])
                with self.assertRaises(BehaviorCorpusError):
                    pair.verify_observation(document)
        document = copy.deepcopy(base)
        document["compileReport"]["cases"][0]["artifacts"] = []
        with self.assertRaises(BehaviorCorpusError):
            pair.verify_observation(document)

    def test_self_consistent_second_executable_substitution_refuses(self):
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        document["executionCorpus"]["executable"]["sha256"] = "0" * 64
        document["executionReport"] = self.synthetic_report(document["executionCorpus"])
        with self.assertRaises(BehaviorCorpusError):
            pair.verify_observation(document)

    def test_changed_process_limit_profile_source_argv_and_expected_result_refuse(self):
        import copy
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        base = self.synthetic_pair()
        for field in ("processes", "timeoutMilliseconds", "stdoutBytes", "memoryBytes", "workspaceEntries"):
            document = copy.deepcopy(base)
            document["compileCorpus"]["limits"][field] -= 1
            document["compileReport"] = self.synthetic_report(document["compileCorpus"])
            with self.subTest(field=field), self.assertRaises(BehaviorCorpusError):
                pair.verify_observation(document)
        for mutate in (
            lambda d: d["compileCorpus"]["cases"][0]["arguments"].append("-v"),
            lambda d: d["compileCorpus"]["sandbox"].update(imageDigest="sha256:" + "0" * 64),
            lambda d: d["executionCorpus"]["cases"][0]["expected"].update(exitCode=0),
            lambda d: d.update(sourceSha256="0" * 64),
            lambda d: d.update(extra=True),
            lambda d: d["authority"].update(releaseQualified=True),
        ):
            document = copy.deepcopy(base)
            mutate(document)
            with self.assertRaises(BehaviorCorpusError):
                pair.verify_observation(document)

    def test_dynamic_interpreter_dependency_wrong_machine_and_nonentry_elf_refuse(self):
        import struct
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        for offset, fmt, value in ((64, "<I", 3), (64, "<I", 2), (18, "<H", 183), (24, "<Q", 0), (32, "<Q", 999999)):
            payload = bytearray(self.inert_elf_metadata())
            struct.pack_into(fmt, payload, offset, value)
            with self.subTest(value=value), self.assertRaises(BehaviorCorpusError):
                pair._require_static_amd64(bytes(payload))

    def test_private_snapshot_rejects_links_nonregular_mutation_and_mode_changes(self):
        import os
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "program"
            program.write_bytes(b"inert metadata")
            program.chmod(0o755)
            pair._private_snapshot(program, b"inert metadata", 0o755)
            link = root / "symlink"
            link.symlink_to(program)
            with self.assertRaises(BehaviorCorpusError):
                pair._private_snapshot(link, b"inert metadata", 0o755)
            hardlink = root / "hardlink"
            os.link(program, hardlink)
            with self.assertRaises(BehaviorCorpusError):
                pair._private_snapshot(program, b"inert metadata", 0o755)
            hardlink.unlink()
            with self.assertRaises(BehaviorCorpusError):
                pair._private_snapshot(root, b"inert metadata", 0o755)
            program.write_bytes(b"mutated")
            with self.assertRaises(BehaviorCorpusError):
                pair._private_snapshot(program, b"inert metadata", 0o755)
            program.write_bytes(b"inert metadata")
            program.chmod(0o644)
            with self.assertRaises(BehaviorCorpusError):
                pair._private_snapshot(program, b"inert metadata", 0o755)

    def test_generic_recording_retains_actual_report_and_legacy_wrapper_parity(self):
        from unittest.mock import patch
        from oracle import behavior_corpus as generic
        from oracle.llvm import produced_program as pair
        draft = pair.compile_corpus()
        # Authored inert target bytes only. All control-client and case execution boundaries mocked.
        payload = b"not executable: generic API wire control"
        draft["executable"] = pair._blob(payload)
        draft["executable"].pop("base64")
        observation = {"id": draft["cases"][0]["id"], "status": "passed", **pair._expected(0)}
        observation["artifacts"] = [{"path": "program", "present": True, "mode": "0o755", **pair._blob(self.inert_elf_metadata())}]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inert"
            target.write_bytes(payload)
            with patch.object(generic, "_snapshot_control_client", return_value=b"inert client"), \
                 patch.object(generic, "_verify_oci_runtime"), \
                 patch.object(generic, "_run_case", return_value=observation) as execute:
                recorded, report = generic.record_corpus_observations(draft, target, container_runtime=Path("/inert-never-launched"))
                self.assertEqual(1, execute.call_count)
                legacy = generic.record_corpus_expectations(draft, target, container_runtime=Path("/inert-never-launched"))
                self.assertEqual(recorded, legacy)
                self.assertEqual(observation, report["cases"][0])
                self.assertIs(report, generic.validate_corpus_report_pair(recorded, report, corpus_payload=generic.corpus_json_bytes(recorded)))

    def test_adapter_passes_exact_collector_snapshot_and_propagates_run_failure(self):
        from unittest.mock import patch
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        captured = []
        def inert_runtime(corpus, path, **kwargs):
            captured.append((path.read_bytes(), path.stat().st_mode & 0o777, corpus))
            return document["executionReport"]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pair, "record_corpus_observations", return_value=(document["compileCorpus"], document["compileReport"])) as compiler, \
                 patch.object(pair, "run_corpus", side_effect=inert_runtime) as runtime:
                actual = pair.observe_produced_program(pair.PROFILE / "oracle-manifest.json", Path("/never-opened-artifact-root"), Path(directory), container_runtime=Path("/never-launched"))
                self.assertEqual(document, actual)
                self.assertEqual(1, compiler.call_count)
                self.assertEqual(1, runtime.call_count)
                self.assertEqual(self.inert_elf_metadata(), captured[0][0])
                self.assertEqual(0o755, captured[0][1])
                runtime.side_effect = BehaviorCorpusError("inert timeout/cleanup refusal")
                with self.assertRaises(BehaviorCorpusError):
                    pair.observe_produced_program(pair.PROFILE / "oracle-manifest.json", Path("/never-opened-artifact-root"), Path(directory), container_runtime=Path("/never-launched"))

    def test_invalid_first_observation_prevents_second_target_start(self):
        from unittest.mock import patch
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        document["compileReport"]["cases"][0]["exitCode"] = 1
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pair, "record_corpus_observations", return_value=(document["compileCorpus"], document["compileReport"])), \
                 patch.object(pair, "run_corpus") as runtime:
                with self.assertRaises(BehaviorCorpusError):
                    pair.observe_produced_program(pair.PROFILE / "oracle-manifest.json", Path("/never-opened"), Path(directory), container_runtime=Path("/never-launched"))
                runtime.assert_not_called()

    def test_offline_loader_rejects_duplicate_fields_noncanonical_and_unknown_authority_types(self):
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
            self.assertEqual(document, pair.load_observation(path))
            path.write_text(json.dumps(document))
            with self.assertRaises(BehaviorCorpusError):
                pair.load_observation(path)
            path.write_text('{"schemaVersion":1,"schemaVersion":1}')
            with self.assertRaises(BehaviorCorpusError):
                pair.load_observation(path)
        document["authority"]["candidateExecuted"] = 0
        with self.assertRaises(BehaviorCorpusError):
            pair.verify_observation(document)

    def test_generic_replay_still_refuses_unknown_artifacts(self):
        from oracle.behavior_corpus import BehaviorCorpusError
        from oracle.llvm import produced_program as pair
        document = self.synthetic_pair()
        document["compileCorpus"]["cases"][0]["expected"]["artifacts"] = []
        with self.assertRaises(BehaviorCorpusError):
            validate_corpus_report_pair(document["compileCorpus"], document["compileReport"])


if __name__ == "__main__":
    unittest.main()
