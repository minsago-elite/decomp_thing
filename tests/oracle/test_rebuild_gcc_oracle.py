from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from oracle.gcc import rebuild_oracle

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
safe_extract = rebuild_oracle._safe_extract
VerificationError = rebuild_oracle.VerificationError


def add_file(archive: tarfile.TarFile, name: str, payload: bytes = b"fixture\n") -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o644
    archive.addfile(member, BytesIO(payload))


class GccOracleRebuildRunnerTest(unittest.TestCase):
    def _write_build_record(self, root: Path, digest: str) -> Path:
        version_root = root / "profile"
        version_root.mkdir()
        record_path = version_root / "build-record.json"
        record_path.write_text(
            json.dumps({"environment": {"container": {"image": "pinned:gcc", "digest": digest}}}),
            encoding="utf-8",
        )
        return record_path

    def test_reproduced_image_is_used_only_after_toolchain_lock_verification(self) -> None:
        origin = f"sha256:{'1' * 64}"
        reproduced = f"sha256:{'2' * 64}"
        inspect = {"Id": reproduced}
        with tempfile.TemporaryDirectory(prefix="gcc-reproduced-container-") as temporary:
            root = Path(temporary)
            record_path = self._write_build_record(root, origin)
            lock_path = record_path.parent / "toolchain-reproduction.json"
            lock_path.write_text("{}", encoding="utf-8")
            verification = {
                "recordedOrigin": {"imageDigest": origin},
                "reproducedImage": {"imageDigest": reproduced},
            }
            with patch.object(rebuild_oracle, "_run", return_value=json.dumps([inspect])) as run, \
                    patch.object(rebuild_oracle, "verify_toolchain_reproduction", return_value=verification) as verify:
                runtime_digest, selected_lock = rebuild_oracle.verified_container_image(
                    "docker", record_path.parent, record_path,
                )

            self.assertEqual(reproduced, runtime_digest)
            self.assertEqual(lock_path, selected_lock)
            run.assert_called_once_with(["docker", "image", "inspect", "pinned:gcc"], capture=True)
            verify.assert_called_once_with(lock_path, record_path, [inspect])

    def test_unverified_reproduction_is_rejected(self) -> None:
        origin = f"sha256:{'1' * 64}"
        observed = f"sha256:{'2' * 64}"
        with tempfile.TemporaryDirectory(prefix="gcc-reproduced-container-") as temporary:
            root = Path(temporary)
            record_path = self._write_build_record(root, origin)
            (record_path.parent / "toolchain-reproduction.json").write_text("{}", encoding="utf-8")
            with patch.object(rebuild_oracle, "_run", return_value=json.dumps([{"Id": observed}])), \
                    patch.object(
                        rebuild_oracle,
                        "verify_toolchain_reproduction",
                        side_effect=VerificationError("image layers differ from the checked lock"),
                    ):
                with self.assertRaisesRegex(VerificationError, "layers differ"):
                    rebuild_oracle.verified_container_image("docker", record_path.parent, record_path)

    def test_original_image_still_requires_the_recorded_digest(self) -> None:
        digest = f"sha256:{'1' * 64}"
        with tempfile.TemporaryDirectory(prefix="gcc-original-container-") as temporary:
            root = Path(temporary)
            record_path = self._write_build_record(root, digest)
            with patch.object(rebuild_oracle, "_run", return_value=json.dumps([{"Id": digest}])):
                self.assertEqual(
                    (digest, None),
                    rebuild_oracle.verified_container_image("docker", record_path.parent, record_path),
                )
            with patch.object(rebuild_oracle, "_run", return_value=json.dumps([{"Id": f"sha256:{'2' * 64}"}])):
                with self.assertRaisesRegex(VerificationError, "container image digest mismatch"):
                    rebuild_oracle.verified_container_image("docker", record_path.parent, record_path)

    def test_extracts_a_canonical_regular_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-rebuild-extract-") as temporary:
            root = Path(temporary)
            archive_path = root / "source.tar.xz"
            destination = root / "destination"
            destination.mkdir()
            with tarfile.open(archive_path, "w:xz") as archive:
                directory = tarfile.TarInfo("gcc-16.2.0")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                archive.addfile(directory)
                add_file(archive, "gcc-16.2.0/README")

            safe_extract(archive_path, destination, "gcc-16.2.0")

            self.assertEqual(
                (destination / "gcc-16.2.0/README").read_bytes(),
                b"fixture\n",
            )

    def test_rejects_parent_traversal_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-rebuild-traversal-") as temporary:
            root = Path(temporary)
            archive_path = root / "source.tar.xz"
            destination = root / "destination"
            destination.mkdir()
            with tarfile.open(archive_path, "w:xz") as archive:
                add_file(archive, "gcc-16.2.0/../../escaped.txt")

            with self.assertRaisesRegex(VerificationError, "not canonical"):
                safe_extract(archive_path, destination, "gcc-16.2.0")
            self.assertFalse((root / "escaped.txt").exists())

    def test_rejects_members_below_a_link(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-rebuild-link-") as temporary:
            root = Path(temporary)
            archive_path = root / "source.tar.xz"
            destination = root / "destination"
            destination.mkdir()
            with tarfile.open(archive_path, "w:xz") as archive:
                directory = tarfile.TarInfo("gcc-16.2.0")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                add_file(archive, "gcc-16.2.0/target.txt")
                link = tarfile.TarInfo("gcc-16.2.0/alias")
                link.type = tarfile.SYMTYPE
                link.linkname = "target.txt"
                archive.addfile(link)
                add_file(archive, "gcc-16.2.0/alias/escaped.txt")

            with self.assertRaisesRegex(VerificationError, "non-directory"):
                safe_extract(archive_path, destination, "gcc-16.2.0")
            self.assertFalse((destination / "gcc-16.2.0/escaped.txt").exists())


if __name__ == "__main__":
    unittest.main()
