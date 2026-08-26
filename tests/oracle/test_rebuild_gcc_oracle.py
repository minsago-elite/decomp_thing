from __future__ import annotations

from io import BytesIO
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER = runpy.run_path(str(REPOSITORY_ROOT / "scripts/rebuild-gcc-oracle.py"))
safe_extract = RUNNER["_safe_extract"]
VerificationError = RUNNER["VerificationError"]


def add_file(archive: tarfile.TarFile, name: str, payload: bytes = b"fixture\n") -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o644
    archive.addfile(member, BytesIO(payload))


class GccOracleRebuildRunnerTest(unittest.TestCase):
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
