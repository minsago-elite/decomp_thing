from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402
from oracle.llvm.verify_source_lock import load_and_validate_lock  # noqa: E402
from oracle.source_lock import load_and_validate_lock as dispatch_lock  # noqa: E402


LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/source-lock.json"
SCHEMA = REPOSITORY_ROOT / "oracle/llvm/source-lock.schema.json"


class LlvmSourceLockTest(unittest.TestCase):
    def test_checked_lock_validates_with_runtime_and_formal_schema(self) -> None:
        data = load_and_validate_lock(LOCK)
        try:
            import fastjsonschema
        except ModuleNotFoundError:
            fastjsonschema = None
        if fastjsonschema is not None:
            fastjsonschema.compile(json.loads(SCHEMA.read_text(encoding="utf-8")))(data)
        self.assertEqual(data["oracle"]["id"], "clang-driver-22.1.6")
        self.assertEqual(data["revision"]["commit"], "fc4aad7b5db3fff421df9a9637605b9ca5667881")

    def test_program_neutral_dispatch_selects_llvm_and_preserves_gcc(self) -> None:
        self.assertEqual(dispatch_lock(LOCK)["oracle"]["project"], "LLVM Project")
        gcc = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"
        self.assertEqual(dispatch_lock(gcc)["oracle"]["project"], "GNU Compiler Collection")

    def test_unknown_or_cross_project_identity_is_rejected(self) -> None:
        with self.staged_lock() as staged:
            data = json.loads(staged.read_text(encoding="utf-8"))
            data["oracle"]["unexpected"] = True
            staged.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "unexpected"):
                load_and_validate_lock(staged)
        with self.staged_lock() as staged:
            data = json.loads(staged.read_text(encoding="utf-8"))
            data["oracle"]["project"] = "GNU Compiler Collection"
            staged.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(VerificationError):
                dispatch_lock(staged)

    def test_tag_payload_and_signing_key_tampering_are_rejected(self) -> None:
        for relative, message in (
            ("tag/llvmorg-22.1.6.payload", "byte length mismatch"),
            ("keys/douglas-yung-llvm-release.asc", "SHA-256 mismatch"),
        ):
            with self.subTest(relative=relative), self.staged_lock() as staged:
                target = staged.parent / relative
                target.write_bytes(target.read_bytes() + b"tamper")
                with self.assertRaisesRegex(VerificationError, message):
                    load_and_validate_lock(staged)

    def test_metadata_cli_is_deterministic_and_concise(self) -> None:
        command = ["python3", "scripts/verify-llvm-oracle-source.py", "--metadata-only"]
        first = subprocess.run(command, cwd=REPOSITORY_ROOT, check=True, capture_output=True, text=True)
        second = subprocess.run(command, cwd=REPOSITORY_ROOT, check=True, capture_output=True, text=True)
        self.assertEqual(first.stdout, second.stdout)
        self.assertIn("22.1.6 / fc4aad7b5db3fff421df9a9637605b9ca5667881", first.stdout)

    def test_archive_identity_is_independently_locked(self) -> None:
        data = load_and_validate_lock(LOCK)
        archive = data["source"]["archive"]
        self.assertEqual(archive["bytes"], 167043464)
        self.assertEqual(
            archive["sha256"],
            "6e0b376a1f6d9873e7dfb09ae6e04b9c7024400f01733fa4c29be69d5c138bc2",
        )
        self.assertNotEqual(archive["sha256"], hashlib.sha256(b"not llvm").hexdigest())

    def staged_lock(self):
        temporary = tempfile.TemporaryDirectory(prefix="llvm-source-lock-test-")
        root = Path(temporary.name) / "22.1.6"
        shutil.copytree(LOCK.parent, root)

        class Context:
            def __enter__(self):
                return root / "source-lock.json"

            def __exit__(self, *_: object) -> None:
                temporary.cleanup()

        return Context()


if __name__ == "__main__":
    unittest.main()
