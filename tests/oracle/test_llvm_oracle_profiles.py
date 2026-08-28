from __future__ import annotations

from pathlib import Path
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.behavior_corpus import validate_corpus  # noqa: E402
from oracle.llvm.generate_behavior_corpus import build_draft, sandbox_profile  # noqa: E402
from oracle.llvm.generate_function_recovery_oracle import (  # noqa: E402
    _driver_compilation_unit,
    _driver_symbol,
)


class LlvmOracleProfilesTest(unittest.TestCase):
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
        self.assertEqual(11, len(corpus["cases"]))
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
            }.issubset(categories)
        )
        self.assertEqual(
            "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248",
            sandbox_profile()["imageDigest"],
        )

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


if __name__ == "__main__":
    unittest.main()
