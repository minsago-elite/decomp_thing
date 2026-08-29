from __future__ import annotations

from contextlib import AbstractContextManager
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.release_artifacts import (  # noqa: E402
    load_release_artifact_lock,
    materialize_release_artifacts,
)
from oracle.source_lock import VerificationError  # noqa: E402


CHECKED_LOCK = REPOSITORY_ROOT / "oracle/llvm/22.1.6/release-artifacts.json"
SCHEMA = REPOSITORY_ROOT / "oracle/release-artifacts.schema.json"


class FakeResponse(AbstractContextManager["FakeResponse"]):
    def __init__(
        self,
        payload: bytes,
        *,
        url: str,
        content_length: int | None = None,
        content_encoding: str | None = None,
    ) -> None:
        self.stream = io.BytesIO(payload)
        self.url = url
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        if content_encoding is not None:
            self.headers["Content-Encoding"] = content_encoding

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *arguments: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)


class ReleaseArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-artifact-lock-")
        self.directory = Path(self.temporary.name)
        self.payloads = {"full": b"rich fixture", "stripped": b"thin fixture"}
        repository = "minsago-elite/decomp_thing-oracle-artifacts"
        tag = "fixture-v1"
        base = f"https://github.com/{repository}/releases/download/{tag}"
        self.manifest = {
            "oracle": {"id": "fixture", "version": "1.0.0"},
            "artifacts": {
                role: {
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for role, payload in self.payloads.items()
            },
        }
        manifest_payload = (
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        (self.directory / "oracle-manifest.json").write_bytes(manifest_payload)
        self.lock: dict[str, Any] = {
            "schemaVersion": 1,
            "oracle": {
                "id": "fixture",
                "version": "1.0.0",
                "artifactManifestPath": "oracle-manifest.json",
                "artifactManifestSha256": hashlib.sha256(manifest_payload).hexdigest(),
            },
            "release": {
                "repository": repository,
                "tag": tag,
                "pageUrl": f"https://github.com/{repository}/releases/tag/{tag}",
            },
            "artifacts": {
                role: {
                    "path": f"artifacts/fixture.{role}",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "url": f"{base}/fixture.{role}",
                }
                for role, payload in self.payloads.items()
            },
        }
        self.lock_path = self.directory / "release-artifacts.json"
        self.write_lock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_lock(self) -> None:
        self.lock_path.write_text(
            json.dumps(self.lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def opener(self, request: object, **keywords: object) -> FakeResponse:
        del keywords
        url = request.full_url  # type: ignore[attr-defined]
        role = "full" if url.endswith(".full") else "stripped"
        payload = self.payloads[role]
        return FakeResponse(
            payload,
            url="https://release-assets.githubusercontent.com/signed-fixture",
            content_length=len(payload),
        )

    def test_checked_lock_and_schema_are_closed_and_match_manifest(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        lock = load_release_artifact_lock(CHECKED_LOCK)
        manifest = json.loads(
            (CHECKED_LOCK.parent / "oracle-manifest.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(lock))
        self.assertEqual(set(schema["properties"]), set(lock))
        self.assertEqual(
            "minsago-elite/decomp_thing-oracle-artifacts",
            lock["release"]["repository"],
        )
        for role in ("full", "stripped"):
            self.assertEqual(
                manifest["artifacts"][role]["bytes"],
                lock["artifacts"][role]["bytes"],
            )
            self.assertEqual(
                manifest["artifacts"][role]["sha256"],
                lock["artifacts"][role]["sha256"],
            )

    def test_pair_is_downloaded_verified_and_atomically_materialized(self) -> None:
        output = self.directory / "output"
        paths = materialize_release_artifacts(
            self.lock_path,
            output,
            opener=self.opener,
        )
        self.assertEqual(self.payloads["full"], paths["full"].read_bytes())
        self.assertEqual(self.payloads["stripped"], paths["stripped"].read_bytes())
        self.assertEqual([], list(output.rglob(".oracle-asset-*")))

    def test_verified_cache_is_reused_without_network(self) -> None:
        output = self.directory / "output"
        first = materialize_release_artifacts(self.lock_path, output, opener=self.opener)

        def forbidden(*arguments: object, **keywords: object) -> object:
            raise AssertionError((arguments, keywords))

        second = materialize_release_artifacts(
            self.lock_path,
            output,
            opener=forbidden,
        )
        self.assertEqual(first, second)

    def test_truncated_oversized_and_bad_length_downloads_fail_cleanly(self) -> None:
        output = self.directory / "output"
        full = self.lock["artifacts"]["full"]

        for payload, content_length, message in (
            (self.payloads["full"][:-1], full["bytes"], "byte length mismatch"),
            (self.payloads["full"] + b"x", full["bytes"] + 1, "Content-Length mismatch"),
            (self.payloads["full"], full["bytes"] + 1, "Content-Length mismatch"),
        ):
            def bad_opener(request: object, **keywords: object) -> FakeResponse:
                del request, keywords
                return FakeResponse(
                    payload,
                    url="https://release-assets.githubusercontent.com/fixture",
                    content_length=content_length,
                )

            with self.assertRaisesRegex(VerificationError, message):
                materialize_release_artifacts(
                    self.lock_path,
                    output,
                    opener=bad_opener,
                )
            self.assertFalse((output / full["path"]).exists())

    def test_redirect_encoding_and_existing_file_tampering_fail_closed(self) -> None:
        for url, encoding, message in (
            ("http://release-assets.githubusercontent.com/fixture", None, "trusted HTTPS"),
            ("https://example.com/fixture", None, "trusted HTTPS"),
            ("https://release-assets.githubusercontent.com/fixture", "gzip", "content encoding"),
        ):
            def bad_opener(request: object, **keywords: object) -> FakeResponse:
                del request, keywords
                return FakeResponse(
                    self.payloads["full"],
                    url=url,
                    content_length=len(self.payloads["full"]),
                    content_encoding=encoding,
                )

            with self.assertRaisesRegex(VerificationError, message):
                materialize_release_artifacts(
                    self.lock_path,
                    self.directory / "bad-output",
                    opener=bad_opener,
                )

        target = self.directory / "existing" / self.lock["artifacts"]["full"]["path"]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"tampered")
        with self.assertRaisesRegex(VerificationError, "byte length mismatch"):
            materialize_release_artifacts(
                self.lock_path,
                self.directory / "existing",
                opener=self.opener,
            )
        self.assertEqual(b"tampered", target.read_bytes())

    def test_unknown_fields_paths_urls_and_duplicate_hashes_are_rejected(self) -> None:
        mutations: list[tuple[dict[str, Any], str]] = []
        unknown = copy.deepcopy(self.lock)
        unknown["unchecked"] = True
        mutations.append((unknown, "unexpected.*unchecked"))
        traversal = copy.deepcopy(self.lock)
        traversal["artifacts"]["full"]["path"] = "../fixture.full"
        mutations.append((traversal, "normalized relative"))
        wrong_repository = copy.deepcopy(self.lock)
        wrong_repository["artifacts"]["full"]["url"] = (
            "https://github.com/minsago-elite/decomp_thing/releases/download/fixture-v1/fixture.full"
        )
        mutations.append((wrong_repository, "artifacts.full.url must be"))
        duplicate = copy.deepcopy(self.lock)
        duplicate["artifacts"]["stripped"]["sha256"] = duplicate["artifacts"]["full"]["sha256"]
        mutations.append((duplicate, "must be unique"))

        for mutation, message in mutations:
            self.lock_path.write_text(json.dumps(mutation), encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, message):
                load_release_artifact_lock(self.lock_path)

    def test_manifest_identity_hash_and_artifact_bindings_are_enforced(self) -> None:
        manifest_path = self.directory / "oracle-manifest.json"
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        with self.assertRaisesRegex(VerificationError, "manifest SHA-256 mismatch"):
            load_release_artifact_lock(self.lock_path)

        manifest_path.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        changed = copy.deepcopy(self.lock)
        changed["oracle"]["id"] = "substituted"
        self.lock_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "oracle.id does not match"):
            load_release_artifact_lock(self.lock_path)

        changed = copy.deepcopy(self.lock)
        changed["artifacts"]["full"]["bytes"] -= 1
        self.lock_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "artifacts.full.bytes does not match"):
            load_release_artifact_lock(self.lock_path)


if __name__ == "__main__":
    unittest.main()
