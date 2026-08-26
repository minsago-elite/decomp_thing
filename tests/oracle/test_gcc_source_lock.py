from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from typing import Callable, Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.gcc.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_locked_file,
)


LOCK_PATH = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"
SCHEMA_PATH = REPOSITORY_ROOT / "oracle/gcc/source-lock.schema.json"
KEY_RELATIVE_PATH = Path("keys/richard-guenther-gcc-release.asc")


class GccSourceLockTest(unittest.TestCase):
    @contextmanager
    def staged_lock(
        self,
        mutation: Callable[[dict[str, object]], None],
    ) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="gcc-source-lock-test-") as temporary:
            directory = Path(temporary)
            (directory / KEY_RELATIVE_PATH.parent).mkdir(parents=True)
            shutil.copyfile(LOCK_PATH.parent / KEY_RELATIVE_PATH, directory / KEY_RELATIVE_PATH)
            shutil.copytree(LOCK_PATH.parent / "tag", directory / "tag")
            data = copy.deepcopy(json.loads(LOCK_PATH.read_text(encoding="utf-8")))
            mutation(data)
            staged = directory / "source-lock.json"
            staged.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            yield staged

    def test_checked_in_lock_and_vendored_key_are_valid(self) -> None:
        data = load_and_validate_lock(LOCK_PATH)

        self.assertEqual("16.2.0", data["oracle"]["version"])
        self.assertEqual(
            "78d4ac73dd391005b895a6148cd9831e28e1208b",
            data["revision"]["commit"],
        )

    def test_formal_schema_is_closed_and_matches_root_fields(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(lock), set(schema["required"]))
        self.assertEqual(set(lock), set(schema["properties"]))

    def test_unknown_schema_field_is_rejected(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            data["uncheckedField"] = True

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "unexpected.*uncheckedField"):
                load_and_validate_lock(lock)

    def test_duplicate_json_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-source-lock-test-") as temporary:
            directory = Path(temporary)
            text = LOCK_PATH.read_text(encoding="utf-8").replace(
                '  "schemaVersion": 1,',
                '  "schemaVersion": 1,\n  "schemaVersion": 1,',
                1,
            )
            duplicate = directory / "source-lock.json"
            duplicate.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(VerificationError, "duplicate JSON object key"):
                load_and_validate_lock(duplicate)

    def test_commit_cannot_change_without_its_signed_tag(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            data["revision"]["commit"] = "0" * 40  # type: ignore[index]

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "tag payload does not bind"):
                load_and_validate_lock(lock)

    def test_archive_revision_marker_cannot_change_independently(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            marker = data["revision"]["archiveMarkers"]["revision"]  # type: ignore[index]
            marker["text"] = "Obtained from an untrusted source\n"  # type: ignore[index]

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "revision marker must bind"):
                load_and_validate_lock(lock)

    def test_annotated_tag_object_id_is_recomputed_from_signed_evidence(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            data["revision"]["tagObject"] = "0" * 40  # type: ignore[index]

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "annotated Git tag object mismatch"):
                load_and_validate_lock(lock)

    def test_canonical_download_url_cannot_be_replaced_by_a_mirror(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            archive = data["source"]["archive"]  # type: ignore[index]
            archive["url"] = (  # type: ignore[index]
                "https://example.invalid/gcc-16.2.0/gcc-16.2.0.tar.xz"
            )

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "canonical GNU release URL"):
                load_and_validate_lock(lock)

    def test_signing_fingerprint_is_bound_to_the_vendored_key(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            fingerprint = "A" * 40
            data["signing"]["signingFingerprint"] = fingerprint  # type: ignore[index]
            data["signing"]["keyRetrievalUrl"] = (  # type: ignore[index]
                "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x"
                f"{fingerprint}"
            )

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "does not contain locked signing"):
                load_and_validate_lock(lock)

    def test_vendored_key_hash_mutation_is_rejected(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            data["signing"]["keySha256"] = "0" * 64  # type: ignore[index]

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "signing key SHA-256 mismatch"):
                load_and_validate_lock(lock)

    def test_missing_redistribution_notice_is_rejected(self) -> None:
        def mutate(data: dict[str, object]) -> None:
            data["redistribution"]["licenseFiles"].pop()  # type: ignore[index,union-attr]

        with self.staged_lock(mutate) as lock:
            with self.assertRaisesRegex(VerificationError, "must lock COPYING"):
                load_and_validate_lock(lock)

    def test_locked_artifact_detects_same_size_byte_mutation(self) -> None:
        original = b"locked artifact bytes"
        specification = {
            "fileName": "artifact.bin",
            "bytes": len(original),
            "sha256": hashlib.sha256(original).hexdigest(),
        }
        with tempfile.TemporaryDirectory(prefix="gcc-source-lock-test-") as temporary:
            artifact = Path(temporary) / "artifact.bin"
            artifact.write_bytes(original)
            verify_locked_file(artifact, specification, "fixture")

            artifact.write_bytes(b"Locked artifact bytes")
            with self.assertRaisesRegex(VerificationError, "SHA-256 mismatch"):
                verify_locked_file(artifact, specification, "fixture")


if __name__ == "__main__":
    unittest.main()
