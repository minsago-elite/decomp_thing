"""Stable provenance checks for oracle toolchain container rebuilds.

Docker image IDs include layer and configuration metadata.  Rebuilding an
otherwise identical recipe against a package repository can therefore produce
a different ID.  This module binds a rebuild to the immutable recipe and the
historical build record; the build-record verifier remains responsible for
checking every live tool's exact bytes and version output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from oracle.source_lock import VerificationError


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_NAME = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*")
_PLATFORM = "linux/amd64"


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


def _load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} is not a non-symlink regular file: {path}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON object key in {label}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot load {label} {path}: {error}") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _relative_file(directory: Path, value: Any, path: str) -> Path:
    text = _string(value, path)
    relative = PurePosixPath(text)
    if relative.is_absolute() or str(relative) != text or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise VerificationError(f"{path} must be a normalized relative POSIX path")
    candidate = directory.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise VerificationError(f"{path} is not a non-symlink regular file: {candidate}")
    return candidate


def validate_reproduction_lock(data: Any) -> dict[str, Any]:
    root = _object(data, "reproduction lock", {"schemaVersion", "recordedOrigin", "recipe"})
    if root["schemaVersion"] != 1:
        raise VerificationError("reproduction lock.schemaVersion must be 1")
    origin = _object(
        root["recordedOrigin"],
        "reproduction lock.recordedOrigin",
        {"buildRecordSha256", "imageDigest"},
    )
    _string(origin["buildRecordSha256"], "recordedOrigin.buildRecordSha256", _SHA256)
    _string(origin["imageDigest"], "recordedOrigin.imageDigest", _DIGEST)
    recipe = _object(
        root["recipe"],
        "reproduction lock.recipe",
        {
            "baseImage",
            "baseImageDigest",
            "dockerfile",
            "dockerfileSha256",
            "platform",
            "sourceDateEpoch",
        },
    )
    _string(recipe["baseImage"], "recipe.baseImage", _IMAGE_NAME)
    _string(recipe["baseImageDigest"], "recipe.baseImageDigest", _DIGEST)
    _string(recipe["dockerfile"], "recipe.dockerfile")
    _string(recipe["dockerfileSha256"], "recipe.dockerfileSha256", _SHA256)
    if recipe["platform"] != _PLATFORM:
        raise VerificationError(f"recipe.platform must be {_PLATFORM}")
    epoch = _string(recipe["sourceDateEpoch"], "recipe.sourceDateEpoch")
    if not epoch.isdecimal() or epoch.startswith("0"):
        raise VerificationError("recipe.sourceDateEpoch must be a positive decimal string")
    return root


def verify_reproduction_recipe(
    lock_path: Path,
    build_record_path: Path,
    *,
    running_image_digest: str | None = None,
) -> dict[str, Any]:
    """Verify stable recipe/origin bindings for a rebuilt toolchain image.

    ``running_image_digest`` is deliberately format-checked but not compared to
    the historical origin.  The live build-record check authenticates the tools
    in that running image by exact executable bytes and version output.
    """

    lock = validate_reproduction_lock(_load_json(lock_path, "reproduction lock"))
    directory = lock_path.absolute().parent
    dockerfile = _relative_file(directory, lock["recipe"]["dockerfile"], "recipe.dockerfile")
    dockerfile_payload = dockerfile.read_bytes()
    observed_dockerfile_hash = _sha256(dockerfile_payload)
    if observed_dockerfile_hash != lock["recipe"]["dockerfileSha256"]:
        raise VerificationError(
            "Dockerfile SHA-256 mismatch: "
            f"recorded {lock['recipe']['dockerfileSha256']}, observed {observed_dockerfile_hash}"
        )
    base_reference = f"{lock['recipe']['baseImage']}@{lock['recipe']['baseImageDigest']}"
    try:
        from_lines = [
            line.split()[1]
            for line in dockerfile_payload.decode("utf-8", errors="strict").splitlines()
            if line.strip().upper().startswith("FROM ")
        ]
    except UnicodeDecodeError as error:
        raise VerificationError(f"Dockerfile is not UTF-8: {error}") from error
    if not from_lines or any(reference != base_reference for reference in from_lines):
        raise VerificationError("Dockerfile FROM instructions do not match locked base image")

    if build_record_path.is_symlink() or not build_record_path.is_file():
        raise VerificationError("build record must be a non-symlink regular file")
    build_payload = build_record_path.read_bytes()
    observed_build_hash = _sha256(build_payload)
    origin = lock["recordedOrigin"]
    if observed_build_hash != origin["buildRecordSha256"]:
        raise VerificationError(
            "build-record SHA-256 mismatch: "
            f"recorded {origin['buildRecordSha256']}, observed {observed_build_hash}"
        )
    try:
        build = json.loads(build_payload.decode("utf-8"))
        recorded_digest = build["environment"]["container"]["digest"]
        recorded_platform = build["environment"]["container"]["platform"]
        recorded_epoch = build["environment"]["variables"]["SOURCE_DATE_EPOCH"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise VerificationError("build record lacks required reproduction bindings") from error
    if recorded_digest != origin["imageDigest"]:
        raise VerificationError("reproduction lock does not match build-record origin digest")
    if recorded_platform != lock["recipe"]["platform"]:
        raise VerificationError("reproduction lock platform does not match build record")
    if recorded_epoch != lock["recipe"]["sourceDateEpoch"]:
        raise VerificationError("reproduction lock SOURCE_DATE_EPOCH does not match build record")
    if running_image_digest is not None:
        _string(running_image_digest, "running image digest", _DIGEST)
    return lock
