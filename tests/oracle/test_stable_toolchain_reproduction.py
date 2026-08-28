from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.source_lock import VerificationError  # noqa: E402
from oracle.toolchain_reproduction import verify_reproduction_recipe  # noqa: E402


CHECKED_PROFILE = REPOSITORY_ROOT / "oracle/llvm/22.1.6"
CHECKED_LOCK = CHECKED_PROFILE / "toolchain-reproduction.json"
SCHEMA = REPOSITORY_ROOT / "oracle/toolchain-reproduction.schema.json"


class StableToolchainReproductionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="stable-reproduction-lock-")
        self.directory = Path(self.temporary.name)
        for name in (
            "build-toolchain.Dockerfile",
            "build-record.json",
            "toolchain-reproduction.json",
        ):
            shutil.copyfile(CHECKED_PROFILE / name, self.directory / name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self, digest: str = f"sha256:{'8' * 64}") -> dict[str, object]:
        return verify_reproduction_recipe(
            self.directory / "toolchain-reproduction.json",
            self.directory / "build-record.json",
            running_image_digest=digest,
        )

    def test_checked_schema_is_closed_and_matches_lock_root(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        checked = json.loads(CHECKED_LOCK.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(checked))
        self.assertEqual(set(schema["properties"]), set(checked))

    def test_new_image_id_maps_to_historical_origin(self) -> None:
        lock = self.verify()
        self.assertEqual(
            "sha256:73285d9a2dad159a7171fe4bbcac7d97d285402955d8c6fb8b44b101cf2df550",
            lock["recordedOrigin"]["imageDigest"],
        )
        self.assertNotEqual(f"sha256:{'8' * 64}", lock["recordedOrigin"]["imageDigest"])

    def test_recipe_or_historical_record_mutation_is_rejected(self) -> None:
        dockerfile = self.directory / "build-toolchain.Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8") + "\n# mutation\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(VerificationError, "Dockerfile SHA-256 mismatch"):
            self.verify()

        shutil.copyfile(CHECKED_PROFILE / "build-toolchain.Dockerfile", dockerfile)
        record = self.directory / "build-record.json"
        record.write_text(record.read_text(encoding="utf-8") + " ", encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "build-record SHA-256 mismatch"):
            self.verify()

    def test_base_image_and_running_digest_mutation_are_rejected(self) -> None:
        dockerfile = self.directory / "build-toolchain.Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8").replace("FROM ubuntu@", "FROM debian@"),
            encoding="utf-8",
        )
        lock_path = self.directory / "toolchain-reproduction.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["recipe"]["dockerfileSha256"] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "FROM instructions"):
            self.verify()

        shutil.copyfile(CHECKED_PROFILE / "toolchain-reproduction.json", lock_path)
        shutil.copyfile(CHECKED_PROFILE / "build-toolchain.Dockerfile", dockerfile)
        with self.assertRaisesRegex(VerificationError, "running image digest"):
            self.verify("latest")

    def test_lock_is_closed_and_build_bindings_are_exact(self) -> None:
        lock_path = self.directory / "toolchain-reproduction.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["unchecked"] = True
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "unexpected.*unchecked"):
            self.verify()

        shutil.copyfile(CHECKED_PROFILE / "toolchain-reproduction.json", lock_path)
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        changed = copy.deepcopy(lock)
        changed["recipe"]["sourceDateEpoch"] = "1"
        lock_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "SOURCE_DATE_EPOCH"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
