"""Fail-closed verification of a reproduced GCC oracle toolchain image.

The historical build record remains bound to the image that produced the
checked artifacts.  This module separately authenticates a deterministic
rebuild before its live tools may be compared with that historical record.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from oracle.gcc.verify_source_lock import VerificationError


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
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


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256(payload)


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
    root = _object(
        data,
        "reproduction lock",
        {"schemaVersion", "recordedOrigin", "recipe", "reproducedImage"},
    )
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
            "baseImageDigest",
            "dockerfile",
            "dockerfileSha256",
            "platform",
            "sourceDateEpoch",
        },
    )
    _string(recipe["baseImageDigest"], "recipe.baseImageDigest", _DIGEST)
    _string(recipe["dockerfile"], "recipe.dockerfile")
    _string(recipe["dockerfileSha256"], "recipe.dockerfileSha256", _SHA256)
    if recipe["platform"] != _PLATFORM:
        raise VerificationError(f"recipe.platform must be {_PLATFORM}")
    epoch = _string(recipe["sourceDateEpoch"], "recipe.sourceDateEpoch")
    if not epoch.isdecimal() or epoch.startswith("0"):
        raise VerificationError("recipe.sourceDateEpoch must be a positive decimal string")

    image = _object(
        root["reproducedImage"],
        "reproduction lock.reproducedImage",
        {"configSha256", "created", "imageDigest", "rootfsDiffIds"},
    )
    _string(image["imageDigest"], "reproducedImage.imageDigest", _DIGEST)
    _string(image["configSha256"], "reproducedImage.configSha256", _SHA256)
    _string(image["created"], "reproducedImage.created")
    layers = image["rootfsDiffIds"]
    if not isinstance(layers, list) or not layers:
        raise VerificationError("reproducedImage.rootfsDiffIds must be a non-empty array")
    for index, layer in enumerate(layers):
        _string(layer, f"reproducedImage.rootfsDiffIds[{index}]", _DIGEST)
    if len(layers) != len(set(layers)):
        raise VerificationError("reproducedImage.rootfsDiffIds must not contain duplicates")
    return root


def verify_toolchain_reproduction(
    lock_path: Path,
    build_record_path: Path,
    docker_inspect: Any,
) -> dict[str, Any]:
    """Authenticate recipe bytes and one Docker image-inspect response."""

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
    base_reference = f"gcc@{lock['recipe']['baseImageDigest']}"
    from_lines = [
        line.split()[1]
        for line in dockerfile_payload.decode("utf-8", errors="strict").splitlines()
        if line.strip().upper().startswith("FROM ")
    ]
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
    build = json.loads(build_payload.decode("utf-8"))
    try:
        recorded_digest = build["environment"]["container"]["digest"]
        recorded_platform = build["environment"]["container"]["platform"]
        recorded_epoch = build["environment"]["variables"]["SOURCE_DATE_EPOCH"]
    except (KeyError, TypeError) as error:
        raise VerificationError("build record lacks required reproduction bindings") from error
    if recorded_digest != origin["imageDigest"]:
        raise VerificationError("reproduction lock does not match build-record origin digest")
    if recorded_platform != lock["recipe"]["platform"]:
        raise VerificationError("reproduction lock platform does not match build record")
    if recorded_epoch != lock["recipe"]["sourceDateEpoch"]:
        raise VerificationError("reproduction lock SOURCE_DATE_EPOCH does not match build record")

    if isinstance(docker_inspect, list):
        if len(docker_inspect) != 1:
            raise VerificationError("Docker inspect response must contain exactly one image")
        docker_inspect = docker_inspect[0]
    if not isinstance(docker_inspect, dict):
        raise VerificationError("Docker inspect response must be an object")
    try:
        observed = {
            "imageDigest": docker_inspect["Id"],
            "created": docker_inspect["Created"],
            "configSha256": _canonical_sha256(docker_inspect["Config"]),
            "rootfsDiffIds": docker_inspect["RootFS"]["Layers"],
        }
        architecture = docker_inspect["Architecture"]
        operating_system = docker_inspect["Os"]
    except (KeyError, TypeError) as error:
        raise VerificationError("Docker inspect response lacks required image fields") from error
    if architecture != "amd64" or operating_system != "linux":
        raise VerificationError("reproduced image platform is not linux/amd64")
    for field, value in observed.items():
        if value != lock["reproducedImage"][field]:
            raise VerificationError(
                f"reproduced image {field} mismatch: "
                f"recorded {lock['reproducedImage'][field]!r}, observed {value!r}"
            )
    return lock


def approved_origin_digest(lock_path: Path, observed_image_digest: str) -> str:
    """Map an already-inspected reproduction digest to its historical origin."""

    lock = validate_reproduction_lock(_load_json(lock_path, "reproduction lock"))
    _string(observed_image_digest, "observed image digest", _DIGEST)
    if observed_image_digest != lock["reproducedImage"]["imageDigest"]:
        raise VerificationError("running image is not the approved reproduced image")
    return lock["recordedOrigin"]["imageDigest"]
