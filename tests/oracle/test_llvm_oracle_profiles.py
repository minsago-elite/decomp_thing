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


if __name__ == "__main__":
    unittest.main()
