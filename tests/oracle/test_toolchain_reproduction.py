from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.gcc.toolchain_reproduction import (  # noqa: E402
    approved_origin_digest,
    verify_toolchain_reproduction,
)
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


CHECKED_LOCK = REPOSITORY_ROOT / "oracle/gcc/16.2.0/toolchain-reproduction.json"
SCHEMA = REPOSITORY_ROOT / "oracle/gcc/toolchain-reproduction.schema.json"


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ToolchainReproductionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gcc-reproduction-lock-")
        self.directory = Path(self.temporary.name)
        source_directory = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
        shutil.copyfile(
            source_directory / "build-toolchain.Dockerfile",
            self.directory / "build-toolchain.Dockerfile",
        )
        shutil.copyfile(
            source_directory / "build-record.json",
            self.directory / "build-record.json",
        )
        self.inspect = {
            "Id": f"sha256:{'8' * 64}",
            "Created": "2026-08-07T00:00:00Z",
            "Architecture": "amd64",
            "Os": "linux",
            "Config": {"Cmd": ["bash"], "Env": ["FIXTURE=1"]},
            "RootFS": {
                "Layers": [f"sha256:{'1' * 64}", f"sha256:{'2' * 64}"]
            },
        }
        checked = json.loads(CHECKED_LOCK.read_text(encoding="utf-8"))
        self.lock = {
            "schemaVersion": 1,
            "recordedOrigin": checked["recordedOrigin"],
            "recipe": checked["recipe"],
            "reproducedImage": {
                "imageDigest": self.inspect["Id"],
                "created": self.inspect["Created"],
                "configSha256": canonical_sha256(self.inspect["Config"]),
                "rootfsDiffIds": self.inspect["RootFS"]["Layers"],
            },
        }
        self.lock_path = self.directory / "toolchain-reproduction.json"
        self.write_lock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_lock(self) -> None:
        self.lock_path.write_text(
            json.dumps(self.lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def verify(self, inspected: object | None = None) -> dict[str, object]:
        return verify_toolchain_reproduction(
            self.lock_path,
            self.directory / "build-record.json",
            self.inspect if inspected is None else inspected,
        )

    def test_checked_schema_is_closed_and_matches_lock_root(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        checked = json.loads(CHECKED_LOCK.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(checked))
        self.assertEqual(set(schema["properties"]), set(checked))

    def test_exact_recipe_and_inspect_response_are_accepted(self) -> None:
        verified = self.verify([self.inspect])
        self.assertEqual(self.inspect["Id"], verified["reproducedImage"]["imageDigest"])
        self.assertNotEqual(
            verified["recordedOrigin"]["imageDigest"],
            verified["reproducedImage"]["imageDigest"],
        )

    def test_layer_or_config_mutation_is_rejected(self) -> None:
        changed_layer = copy.deepcopy(self.inspect)
        changed_layer["RootFS"]["Layers"][0] = f"sha256:{'3' * 64}"
        with self.assertRaisesRegex(VerificationError, "rootfsDiffIds mismatch"):
            self.verify(changed_layer)

        changed_config = copy.deepcopy(self.inspect)
        changed_config["Config"]["User"] = "nobody"
        with self.assertRaisesRegex(VerificationError, "configSha256 mismatch"):
            self.verify(changed_config)

    def test_platform_and_image_identity_mutation_is_rejected(self) -> None:
        wrong_platform = copy.deepcopy(self.inspect)
        wrong_platform["Architecture"] = "arm64"
        with self.assertRaisesRegex(VerificationError, "platform"):
            self.verify(wrong_platform)

        wrong_image = copy.deepcopy(self.inspect)
        wrong_image["Id"] = f"sha256:{'9' * 64}"
        with self.assertRaisesRegex(VerificationError, "imageDigest mismatch"):
            self.verify(wrong_image)

    def test_recipe_or_historical_record_mutation_is_rejected(self) -> None:
        dockerfile = self.directory / "build-toolchain.Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8") + "\n# mutation\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(VerificationError, "Dockerfile SHA-256 mismatch"):
            self.verify()

        shutil.copyfile(
            REPOSITORY_ROOT / "oracle/gcc/16.2.0/build-toolchain.Dockerfile",
            dockerfile,
        )
        build_record = self.directory / "build-record.json"
        build_record.write_text(
            build_record.read_text(encoding="utf-8") + " ", encoding="utf-8"
        )
        with self.assertRaisesRegex(VerificationError, "build-record SHA-256 mismatch"):
            self.verify()

    def test_only_locked_reproduction_maps_to_historical_origin(self) -> None:
        origin = approved_origin_digest(self.lock_path, self.inspect["Id"])
        self.assertEqual(self.lock["recordedOrigin"]["imageDigest"], origin)
        with self.assertRaisesRegex(VerificationError, "not the approved"):
            approved_origin_digest(self.lock_path, f"sha256:{'0' * 64}")

    def test_unknown_lock_field_is_rejected(self) -> None:
        self.lock["unchecked"] = True
        self.write_lock()
        with self.assertRaisesRegex(VerificationError, "unexpected.*unchecked"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
