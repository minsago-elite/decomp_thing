"""Fail-closed provenance verification for the pinned LLVM/Clang release."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from oracle.gcc.verify_source_lock import (
    VerificationError,
    _load_json,
    _resolve_local_file,
    _verify_detached_signature,
    _verify_key_identity,
    verify_locked_file,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}")
_FINGERPRINT = re.compile(r"[0-9A-F]{40}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _object(value: Any, path: str, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must be an object")
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        details: list[str] = []
        if missing := sorted(expected - actual):
            details.append(f"missing {missing}")
        if extra := sorted(actual - expected):
            details.append(f"unexpected {extra}")
        raise VerificationError(f"{path} has invalid fields: {', '.join(details)}")
    return value


def _array(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        raise VerificationError(f"{path} must be {'a non-empty' if nonempty else 'an'} array")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or "\x00" in value:
        raise VerificationError(f"{path} must be a valid {'possibly empty ' if allow_empty else ''}string")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise VerificationError(f"{path} must be an integer >= {minimum}")
    return value


def _matches(value: Any, path: str, pattern: re.Pattern[str]) -> str:
    text = _string(value, path)
    if pattern.fullmatch(text) is None:
        raise VerificationError(f"{path} has an invalid format")
    return text


def _relative(value: Any, path: str) -> str:
    text = _string(value, path)
    candidate = PurePosixPath(text)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or "\\" in text
        or str(candidate) != text
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise VerificationError(f"{path} must be a normalized relative POSIX path")
    return text


def _https(value: Any, path: str) -> str:
    text = _string(value, path)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in text)
    ):
        raise VerificationError(f"{path} must be a canonical HTTPS URL")
    return text


def _artifact(value: Any, path: str) -> dict[str, Any]:
    record = _object(value, path, {"fileName", "url", "bytes", "sha256"})
    name = _relative(record["fileName"], f"{path}.fileName")
    if "/" in name:
        raise VerificationError(f"{path}.fileName must be a base name")
    url = _https(record["url"], f"{path}.url")
    if not url.endswith(f"/{name}"):
        raise VerificationError(f"{path}.url must end with its fileName")
    _integer(record["bytes"], f"{path}.bytes", minimum=1)
    _matches(record["sha256"], f"{path}.sha256", _SHA256)
    return record


def _content(value: Any, path: str, *, text: bool) -> dict[str, Any]:
    last = "text" if text else "description"
    record = _object(value, path, {"path", "bytes", "sha256", last})
    _relative(record["path"], f"{path}.path")
    _integer(record["bytes"], f"{path}.bytes")
    _matches(record["sha256"], f"{path}.sha256", _SHA256)
    _string(record[last], f"{path}.{last}", allow_empty=text)
    return record


def _checked_file(lock_directory: Path, record: Mapping[str, Any], prefix: str) -> Path:
    relative = _relative(record[f"{prefix}File"], f"revision.tagEvidence.{prefix}File")
    local = _resolve_local_file(lock_directory, relative, f"tag {prefix}")
    verify_locked_file(
        local,
        {
            "fileName": local.name,
            "bytes": record[f"{prefix}Bytes"],
            "sha256": record[f"{prefix}Sha256"],
        },
        f"tag {prefix}",
    )
    return local


def validate_lock(data: dict[str, Any], lock_path: Path) -> Path:
    """Validate the closed LLVM source-lock structure and checked tag evidence."""

    root = _object(
        data,
        "source lock",
        {"schemaVersion", "oracle", "source", "revision", "signing", "redistribution"},
    )
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise VerificationError("source lock schemaVersion must be the integer 1")

    oracle = _object(root["oracle"], "oracle", {"id", "project", "purpose", "version"})
    version = _matches(oracle["version"], "oracle.version", _VERSION)
    if _string(oracle["id"], "oracle.id") != f"clang-driver-{version}":
        raise VerificationError("oracle.id must identify the locked Clang driver version")
    if oracle["project"] != "LLVM Project":
        raise VerificationError("oracle.project must be 'LLVM Project'")
    _string(oracle["purpose"], "oracle.purpose")

    source = _object(
        root["source"],
        "source",
        {"archiveRoot", "releasePageUrl", "archive", "detachedSignature"},
    )
    expected_root = f"llvm-project-{version}.src"
    if source["archiveRoot"] != expected_root:
        raise VerificationError(f"source.archiveRoot must be {expected_root}")
    tag = f"llvmorg-{version}"
    release_page = _https(source["releasePageUrl"], "source.releasePageUrl")
    if release_page != f"https://github.com/llvm/llvm-project/releases/tag/{tag}":
        raise VerificationError("source.releasePageUrl must be the canonical LLVM release page")
    archive = _artifact(source["archive"], "source.archive")
    signature = _artifact(source["detachedSignature"], "source.detachedSignature")
    expected_base = f"https://github.com/llvm/llvm-project/releases/download/{tag}"
    if archive["url"] != f"{expected_base}/{expected_root}.tar.xz":
        raise VerificationError("source.archive.url must be the canonical LLVM release asset")
    if signature["url"] != f"{archive['url']}.sig":
        raise VerificationError("source.detachedSignature.url must match the archive URL")

    revision = _object(
        root["revision"],
        "revision",
        {"repositoryUrl", "tag", "tagObject", "commit", "tagEvidence", "archiveMarkers"},
    )
    if revision["repositoryUrl"] != "https://github.com/llvm/llvm-project.git":
        raise VerificationError("revision.repositoryUrl must be the canonical LLVM repository")
    if revision["tag"] != tag:
        raise VerificationError(f"revision.tag must be {tag}")
    _matches(revision["tagObject"], "revision.tagObject", _GIT_OBJECT)
    commit = _matches(revision["commit"], "revision.commit", _GIT_OBJECT)
    evidence = _object(
        revision["tagEvidence"],
        "revision.tagEvidence",
        {"payloadFile", "payloadBytes", "payloadSha256", "signatureFile", "signatureBytes", "signatureSha256"},
    )
    for prefix in ("payload", "signature"):
        _integer(evidence[f"{prefix}Bytes"], f"revision.tagEvidence.{prefix}Bytes", minimum=1)
        _matches(evidence[f"{prefix}Sha256"], f"revision.tagEvidence.{prefix}Sha256", _SHA256)
    markers = _object(revision["archiveMarkers"], "revision.archiveMarkers", {"version"})
    version_marker = _content(markers["version"], "revision.archiveMarkers.version", text=True)
    if version_marker["path"] != "cmake/Modules/LLVMVersion.cmake":
        raise VerificationError("revision.archiveMarkers.version has the wrong path")
    required_version_lines = (
        f"set(LLVM_VERSION_MAJOR {version.split('.')[0]})",
        f"set(LLVM_VERSION_MINOR {version.split('.')[1]})",
        f"set(LLVM_VERSION_PATCH {version.split('.')[2]})",
    )
    if any(line not in version_marker["text"] for line in required_version_lines):
        raise VerificationError("revision.archiveMarkers.version text does not encode the version")

    signing = _object(
        root["signing"],
        "signing",
        {"authorityUrl", "keyRetrievalUrl", "keyFile", "keySha256", "primaryFingerprint", "signingFingerprint"},
    )
    for field in ("authorityUrl", "keyRetrievalUrl"):
        if _https(signing[field], f"signing.{field}") != "https://releases.llvm.org/release-keys.asc":
            raise VerificationError(f"signing.{field} must use the official LLVM release keyring")
    _relative(signing["keyFile"], "signing.keyFile")
    _matches(signing["keySha256"], "signing.keySha256", _SHA256)
    for field in ("primaryFingerprint", "signingFingerprint"):
        _matches(signing[field], f"signing.{field}", _FINGERPRINT)

    redistribution = _object(root["redistribution"], "redistribution", {"summary", "licenseFiles"})
    _string(redistribution["summary"], "redistribution.summary")
    licenses = _array(redistribution["licenseFiles"], "redistribution.licenseFiles", nonempty=True)
    normalized_licenses = [
        _content(item, f"redistribution.licenseFiles[{index}]", text=False)
        for index, item in enumerate(licenses)
    ]
    if [item["path"] for item in normalized_licenses] != ["LICENSE.TXT", "clang/LICENSE.TXT"]:
        raise VerificationError("redistribution.licenseFiles must lock root and Clang licenses")

    directory = lock_path.parent.resolve()
    key_path = _resolve_local_file(directory, signing["keyFile"], "vendored signing key")
    _verify_key_identity(key_path, signing)
    payload_path = _checked_file(directory, evidence, "payload")
    signature_path = _checked_file(directory, evidence, "signature")
    payload = payload_path.read_text(encoding="utf-8")
    expected_header = f"object {commit}\ntype commit\ntag {tag}\n"
    if not payload.startswith(expected_header) or not payload.endswith(f"\nLLVM {version}\n"):
        raise VerificationError("annotated LLVM tag payload does not match locked revision")
    _verify_detached_signature(payload_path, signature_path, key_path, signing, "LLVM release tag")
    return key_path


def load_and_validate_lock(lock_path: Path) -> dict[str, Any]:
    lock_path = lock_path.resolve()
    data = _load_json(lock_path)
    validate_lock(data, lock_path)
    return data


def _archive_records(data: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    root = data["source"]["archiveRoot"]
    records = [data["revision"]["archiveMarkers"]["version"]]
    records.extend(data["redistribution"]["licenseFiles"])
    return {f"{root}/{record['path']}": record for record in records}


def _verify_archive_contents(archive_path: Path, data: Mapping[str, Any]) -> None:
    expected = _archive_records(data)
    seen: set[str] = set()
    root = data["source"]["archiveRoot"]
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            for member in archive:
                candidate = PurePosixPath(member.name.rstrip("/"))
                if (
                    candidate.is_absolute()
                    or not candidate.parts
                    or any(part in {"", ".", ".."} for part in candidate.parts)
                    or str(candidate) != member.name.rstrip("/")
                    or candidate.parts[0] != root
                ):
                    raise VerificationError(f"archive contains non-canonical path: {member.name}")
                if member.name not in expected:
                    continue
                if member.name in seen or not member.isfile():
                    raise VerificationError(f"locked archive path is duplicate or non-regular: {member.name}")
                record = expected[member.name]
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"could not read locked archive path: {member.name}")
                payload = extracted.read()
                if len(payload) != record["bytes"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
                    raise VerificationError(f"archive marker hash or size mismatch: {member.name}")
                if "text" in record and payload.decode("utf-8") != record["text"]:
                    raise VerificationError(f"archive marker text mismatch: {member.name}")
                seen.add(member.name)
    except (OSError, tarfile.TarError, UnicodeDecodeError) as error:
        raise VerificationError(f"cannot inspect LLVM source archive {archive_path}: {error}") from error
    if missing := sorted(set(expected) - seen):
        raise VerificationError(f"archive is missing locked provenance paths: {missing}")


def verify_source_release(lock_path: Path, archive_path: Path, signature_path: Path) -> dict[str, Any]:
    """Verify the exact source bytes, signer, embedded version, and licenses."""

    lock_path = lock_path.resolve()
    data = _load_json(lock_path)
    key_path = validate_lock(data, lock_path)
    verify_locked_file(archive_path.resolve(), data["source"]["archive"], "LLVM source archive")
    verify_locked_file(signature_path.resolve(), data["source"]["detachedSignature"], "LLVM source signature")
    _verify_detached_signature(
        archive_path.resolve(), signature_path.resolve(), key_path, data["signing"], "LLVM source release"
    )
    _verify_archive_contents(archive_path.resolve(), data)
    return data
