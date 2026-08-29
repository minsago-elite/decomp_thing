"""Fail-closed materialization of hash-locked oracle release assets."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import tempfile
from typing import Any, Callable
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from oracle.source_lock import VerificationError


_SHA256 = re.compile(r"[0-9a-f]{64}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ROLES = ("full", "stripped")
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def _object(value: Any, path: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must be an object")
    if set(value) != fields:
        missing = sorted(fields - set(value))
        unexpected = sorted(set(value) - fields)
        raise VerificationError(
            f"{path} has invalid fields: missing {missing}, unexpected {unexpected}"
        )
    return value


def _string(value: Any, path: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise VerificationError(f"{path} must be a non-empty string without NUL bytes")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise VerificationError(f"{path} has an invalid format")
    return value


def _integer(value: Any, path: str, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise VerificationError(f"{path} must be an integer from {minimum} to {maximum}")
    return value


def _relative_path(value: Any, path: str) -> str:
    text = _string(value, path)
    relative = PurePosixPath(text)
    if (
        relative.is_absolute()
        or str(relative) != text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise VerificationError(f"{path} must be a normalized relative POSIX path")
    return text


def _load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"release artifact lock is not a regular file: {path}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON object key in release lock: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot load release artifact lock {path}: {error}") from error


def validate_release_artifact_lock(value: Any) -> dict[str, Any]:
    root = _object(value, "release artifact lock", {"schemaVersion", "oracle", "release", "artifacts"})
    if root["schemaVersion"] != 1:
        raise VerificationError("release artifact lock.schemaVersion must be 1")
    oracle = _object(
        root["oracle"],
        "release artifact lock.oracle",
        {"id", "version", "artifactManifestPath", "artifactManifestSha256"},
    )
    _string(oracle["id"], "oracle.id")
    _string(oracle["version"], "oracle.version")
    manifest_path = _relative_path(oracle["artifactManifestPath"], "oracle.artifactManifestPath")
    if "/" in manifest_path:
        raise VerificationError("oracle.artifactManifestPath must be a base name")
    _string(oracle["artifactManifestSha256"], "oracle.artifactManifestSha256", _SHA256)
    release = _object(
        root["release"],
        "release artifact lock.release",
        {"repository", "tag", "pageUrl"},
    )
    repository = _string(release["repository"], "release.repository", _REPOSITORY)
    tag = _string(release["tag"], "release.tag", _TAG)
    expected_page = f"https://github.com/{repository}/releases/tag/{tag}"
    if release["pageUrl"] != expected_page:
        raise VerificationError(f"release.pageUrl must be {expected_page}")
    artifacts = _object(root["artifacts"], "release artifact lock.artifacts", set(_ROLES))
    total = 0
    paths: list[str] = []
    hashes: list[str] = []
    expected_base = f"https://github.com/{repository}/releases/download/{tag}"
    for role in _ROLES:
        record = _object(
            artifacts[role],
            f"release artifact lock.artifacts.{role}",
            {"path", "bytes", "sha256", "url"},
        )
        relative = _relative_path(record["path"], f"artifacts.{role}.path")
        if not relative.startswith("artifacts/") or len(PurePosixPath(relative).parts) != 2:
            raise VerificationError(f"artifacts.{role}.path must be directly under artifacts/")
        size = _integer(
            record["bytes"],
            f"artifacts.{role}.bytes",
            minimum=1,
            maximum=MAX_ARTIFACT_BYTES,
        )
        digest = _string(record["sha256"], f"artifacts.{role}.sha256", _SHA256)
        expected_url = f"{expected_base}/{PurePosixPath(relative).name}"
        if record["url"] != expected_url:
            raise VerificationError(f"artifacts.{role}.url must be {expected_url}")
        total += size
        paths.append(relative)
        hashes.append(digest)
    if total > MAX_TOTAL_BYTES:
        raise VerificationError("release artifact lock exceeds its total byte bound")
    if len(set(paths)) != len(paths) or len(set(hashes)) != len(hashes):
        raise VerificationError("release artifact paths and SHA-256 digests must be unique")
    return root


def load_release_artifact_lock(path: Path) -> dict[str, Any]:
    absolute = path.absolute()
    lock = validate_release_artifact_lock(_load_json(absolute))
    manifest_path = absolute.parent / lock["oracle"]["artifactManifestPath"]
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise VerificationError(
            f"locked artifact manifest is not a non-symlink regular file: {manifest_path}"
        )
    try:
        payload = manifest_path.read_bytes()
        manifest = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot load locked artifact manifest {manifest_path}: {error}") from error
    observed_hash = hashlib.sha256(payload).hexdigest()
    if observed_hash != lock["oracle"]["artifactManifestSha256"]:
        raise VerificationError(
            "artifact manifest SHA-256 mismatch: "
            f"expected {lock['oracle']['artifactManifestSha256']}, observed {observed_hash}"
        )
    try:
        manifest_oracle = manifest["oracle"]
        manifest_artifacts = manifest["artifacts"]
        if manifest_oracle["id"] != lock["oracle"]["id"]:
            raise VerificationError("release lock oracle.id does not match artifact manifest")
        if manifest_oracle["version"] != lock["oracle"]["version"]:
            raise VerificationError("release lock oracle.version does not match artifact manifest")
        for role in _ROLES:
            for field in ("bytes", "sha256"):
                if manifest_artifacts[role][field] != lock["artifacts"][role][field]:
                    raise VerificationError(
                        f"release lock artifacts.{role}.{field} does not match artifact manifest"
                    )
    except (KeyError, TypeError) as error:
        raise VerificationError("locked artifact manifest lacks required release bindings") from error
    return lock


def _verify_file(path: Path, record: dict[str, Any], label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} is not a non-symlink regular file: {path}")
    try:
        size = path.stat().st_size
        if size != record["bytes"]:
            raise VerificationError(
                f"{label} byte length mismatch: expected {record['bytes']}, observed {size}"
            )
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise VerificationError(f"cannot verify {label} {path}: {error}") from error
    observed = digest.hexdigest()
    if observed != record["sha256"]:
        raise VerificationError(
            f"{label} SHA-256 mismatch: expected {record['sha256']}, observed {observed}"
        )


def _destination(root: Path, relative: str, label: str) -> Path:
    parts = PurePosixPath(relative).parts
    parent = root.joinpath(*parts[:-1])
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise VerificationError(f"cannot create {label} directory {parent}: {error}") from error
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            raise VerificationError(f"{label} parent is not a non-symlink directory: {current}")
    return parent / parts[-1]


def materialize_release_artifacts(
    lock_path: Path,
    output_root: Path,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Path]:
    """Download and atomically install the locked pair below ``output_root``."""

    lock = load_release_artifact_lock(lock_path)
    root = output_root.absolute()
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise VerificationError(f"output root is not a non-symlink directory: {root}")
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise VerificationError(f"cannot create output root {root}: {error}") from error
    results: dict[str, Path] = {}
    context = ssl.create_default_context()
    for role in _ROLES:
        record = lock["artifacts"][role]
        label = f"{role} release artifact"
        target = _destination(root, record["path"], label)
        if target.exists() or target.is_symlink():
            _verify_file(target, record, label)
            results[role] = target
            continue
        request = urllib.request.Request(
            record["url"], headers={"User-Agent": "decomp-thing-oracle-assets/1"}
        )
        try:
            with tempfile.TemporaryDirectory(prefix=".oracle-asset-", dir=target.parent) as temporary:
                staged = Path(temporary) / target.name
                with opener(request, context=context, timeout=300) as response:
                    final = urlsplit(response.geturl())
                    if final.scheme != "https" or final.hostname not in {
                        "github.com",
                        "release-assets.githubusercontent.com",
                    }:
                        raise VerificationError(f"{label} redirected outside trusted HTTPS hosts")
                    if response.headers.get("Content-Encoding") not in {None, "identity"}:
                        raise VerificationError(f"{label} used an unexpected content encoding")
                    content_length = response.headers.get("Content-Length")
                    if content_length is not None and int(content_length) != record["bytes"]:
                        raise VerificationError(
                            f"{label} HTTP Content-Length mismatch: expected "
                            f"{record['bytes']}, observed {content_length}"
                        )
                    observed = 0
                    with staged.open("xb") as destination:
                        while chunk := response.read(1024 * 1024):
                            observed += len(chunk)
                            if observed > record["bytes"]:
                                raise VerificationError(f"{label} exceeded its locked byte length")
                            destination.write(chunk)
                        destination.flush()
                        os.fsync(destination.fileno())
                _verify_file(staged, record, label)
                try:
                    os.link(staged, target)
                except FileExistsError:
                    _verify_file(target, record, label)
        except VerificationError:
            raise
        except (OSError, ValueError, urllib.error.URLError) as error:
            raise VerificationError(f"could not fetch {label}: {error}") from error
        results[role] = target
    return results
