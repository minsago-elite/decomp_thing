"""Strict verification for a pinned GCC source release.

The verifier intentionally treats the JSON lock as a closed schema.  Adding,
removing, or misspelling a field is an error rather than an ignored change.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


class VerificationError(RuntimeError):
    """Raised when locked provenance or an input artifact does not match."""


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
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"unexpected {extra}")
        raise VerificationError(f"{path} has invalid fields: {', '.join(details)}")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{path} must be an array")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise VerificationError(f"{path} must be {qualifier}")
    return value


def _integer(value: Any, path: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "a non-negative integer" if allow_zero else "a positive integer"
        raise VerificationError(f"{path} must be {qualifier}")
    return value


def _matching_string(value: Any, path: str, pattern: re.Pattern[str]) -> str:
    text = _string(value, path)
    if pattern.fullmatch(text) is None:
        raise VerificationError(f"{path} has an invalid format")
    return text


def _https_url(value: Any, path: str, *, allow_query: bool = False) -> str:
    text = _string(value, path)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not allow_query)
        or any(character.isspace() for character in text)
    ):
        raise VerificationError(f"{path} must be a canonical HTTPS URL")
    return text


def _relative_path(value: Any, path: str) -> str:
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


def _artifact(value: Any, path: str) -> dict[str, Any]:
    artifact = _object(value, path, {"fileName", "url", "bytes", "sha256"})
    file_name = _relative_path(artifact["fileName"], f"{path}.fileName")
    if "/" in file_name:
        raise VerificationError(f"{path}.fileName must be a base name")
    url = _https_url(artifact["url"], f"{path}.url")
    if not url.endswith(f"/{file_name}"):
        raise VerificationError(f"{path}.url must end with its locked fileName")
    _integer(artifact["bytes"], f"{path}.bytes")
    _matching_string(artifact["sha256"], f"{path}.sha256", _SHA256)
    return artifact


def _content_record(
    value: Any,
    path: str,
    *,
    with_text: bool,
) -> dict[str, Any]:
    trailing = "text" if with_text else "description"
    record = _object(value, path, {"path", "bytes", "sha256", trailing})
    _relative_path(record["path"], f"{path}.path")
    _integer(record["bytes"], f"{path}.bytes", allow_zero=True)
    _matching_string(record["sha256"], f"{path}.sha256", _SHA256)
    _string(record[trailing], f"{path}.{trailing}", allow_empty=with_text)
    return record


def _load_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source, object_pairs_hook=reject_duplicates)
    except OSError as error:
        raise VerificationError(f"cannot read source lock {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON in source lock {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError("source lock root must be an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise VerificationError(f"cannot read {path}: {error}") from error
    return digest.hexdigest()


def _verify_size_and_hash(
    path: Path,
    expected_bytes: int,
    expected_sha256: str,
    label: str,
) -> None:
    if not path.is_file():
        raise VerificationError(f"{label} is not a regular file: {path}")
    actual_bytes = path.stat().st_size
    if actual_bytes != expected_bytes:
        raise VerificationError(
            f"{label} byte length mismatch: expected {expected_bytes}, got {actual_bytes}"
        )
    actual_sha256 = _sha256(path)
    if actual_sha256 != expected_sha256:
        raise VerificationError(
            f"{label} SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )


def verify_locked_file(path: Path, specification: Mapping[str, Any], label: str) -> None:
    """Verify an artifact's exact file name, byte length, and SHA-256 digest."""

    if not path.is_file():
        raise VerificationError(f"{label} is not a regular file: {path}")
    if path.name != specification["fileName"]:
        raise VerificationError(
            f"{label} file name mismatch: expected {specification['fileName']}, got {path.name}"
        )
    _verify_size_and_hash(
        path,
        specification["bytes"],
        specification["sha256"],
        label,
    )


def _resolve_local_file(directory: Path, relative: str, label: str) -> Path:
    path = (directory / relative).resolve()
    try:
        path.relative_to(directory)
    except ValueError as error:
        raise VerificationError(f"{label} escapes the source-lock directory") from error
    if not path.is_file():
        raise VerificationError(f"{label} is missing: {path}")
    return path


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {label} {path}: {error}") from error


def _run_gpg(arguments: list[str], home: Path) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("gpg")
    if executable is None:
        raise VerificationError("gpg is required to verify the GCC release signer")
    command = [
        executable,
        "--no-options",
        "--homedir",
        str(home),
        "--batch",
        "--no-auto-key-retrieve",
        *arguments,
    ]
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    except OSError as error:
        raise VerificationError(f"could not run gpg: {error}") from error


def _import_key(home: Path, key_path: Path) -> None:
    imported = _run_gpg(["--quiet", "--import", str(key_path)], home)
    if imported.returncode != 0:
        diagnostic = imported.stderr.strip() or "no diagnostic"
        raise VerificationError(f"could not import vendored signing key: {diagnostic}")


def _verify_key_identity(key_path: Path, signing: Mapping[str, Any]) -> None:
    expected_sha256 = signing["keySha256"]
    actual_sha256 = _sha256(key_path)
    if actual_sha256 != expected_sha256:
        raise VerificationError(
            "vendored signing key SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )

    with tempfile.TemporaryDirectory(prefix="gcc-oracle-gpg-") as temporary:
        home = Path(temporary)
        os.chmod(home, 0o700)
        _import_key(home, key_path)
        listed = _run_gpg(
            ["--with-colons", "--fingerprint", "--fingerprint", "--list-keys"],
            home,
        )
        if listed.returncode != 0:
            diagnostic = listed.stderr.strip() or "no diagnostic"
            raise VerificationError(f"could not inspect vendored signing key: {diagnostic}")

    primary_fingerprints: list[str] = []
    subkey_fingerprints: list[str] = []
    pending: str | None = None
    for line in listed.stdout.splitlines():
        fields = line.split(":")
        record_type = fields[0]
        if record_type == "pub":
            pending = "primary"
        elif record_type == "sub":
            pending = "subkey"
        elif record_type == "fpr" and pending is not None and len(fields) > 9:
            if pending == "primary":
                primary_fingerprints.append(fields[9])
            else:
                subkey_fingerprints.append(fields[9])
            pending = None

    expected_primary = signing["primaryFingerprint"]
    expected_signer = signing["signingFingerprint"]
    if primary_fingerprints != [expected_primary]:
        raise VerificationError(
            "vendored key primary fingerprint mismatch: "
            f"expected only {expected_primary}, got {primary_fingerprints}"
        )
    if expected_signer not in subkey_fingerprints and expected_signer != expected_primary:
        raise VerificationError(
            f"vendored key does not contain locked signing fingerprint {expected_signer}"
        )


def validate_lock(data: dict[str, Any], lock_path: Path) -> Path:
    """Validate the closed schema and return the resolved vendored-key path."""

    lock_directory = lock_path.resolve().parent
    root = _object(
        data,
        "root",
        {"schemaVersion", "oracle", "source", "revision", "signing", "redistribution"},
    )
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise VerificationError("schemaVersion must be the integer 1")

    oracle = _object(root["oracle"], "oracle", {"id", "project", "version", "purpose"})
    version = _matching_string(oracle["version"], "oracle.version", _VERSION)
    if _string(oracle["id"], "oracle.id") != f"gcc-driver-{version}":
        raise VerificationError("oracle.id must be derived from oracle.version")
    if _string(oracle["project"], "oracle.project") != "GNU Compiler Collection":
        raise VerificationError("oracle.project must identify the GNU Compiler Collection")
    _string(oracle["purpose"], "oracle.purpose")

    source = _object(
        root["source"],
        "source",
        {
            "archiveRoot",
            "releaseAnnouncementUrl",
            "releasePageUrl",
            "archive",
            "detachedSignature",
        },
    )
    archive_root = _relative_path(source["archiveRoot"], "source.archiveRoot")
    expected_root = f"gcc-{version}"
    if archive_root != expected_root:
        raise VerificationError(f"source.archiveRoot must be {expected_root}")
    announcement = _https_url(
        source["releaseAnnouncementUrl"], "source.releaseAnnouncementUrl"
    )
    if urlsplit(announcement).hostname != "gcc.gnu.org":
        raise VerificationError("source.releaseAnnouncementUrl must be hosted by gcc.gnu.org")
    release_page = _https_url(source["releasePageUrl"], "source.releasePageUrl")
    expected_release_page = f"https://gcc.gnu.org/gcc-{version.split('.')[0]}/"
    if release_page != expected_release_page:
        raise VerificationError(f"source.releasePageUrl must be {expected_release_page}")

    archive = _artifact(source["archive"], "source.archive")
    signature = _artifact(source["detachedSignature"], "source.detachedSignature")
    expected_archive_name = f"{archive_root}.tar.xz"
    if archive["fileName"] != expected_archive_name:
        raise VerificationError(f"source.archive.fileName must be {expected_archive_name}")
    if signature["fileName"] != f"{expected_archive_name}.sig":
        raise VerificationError(
            f"source.detachedSignature.fileName must be {expected_archive_name}.sig"
        )
    expected_base_url = f"https://ftp.gnu.org/gnu/gcc/{archive_root}"
    if archive["url"] != f"{expected_base_url}/{archive['fileName']}":
        raise VerificationError("source.archive.url must use the canonical GNU release URL")
    if signature["url"] != f"{expected_base_url}/{signature['fileName']}":
        raise VerificationError(
            "source.detachedSignature.url must use the canonical GNU release URL"
        )

    revision = _object(
        root["revision"],
        "revision",
        {
            "repositoryUrl",
            "tag",
            "tagObject",
            "commit",
            "tagEvidence",
            "archiveMarkers",
        },
    )
    if _https_url(revision["repositoryUrl"], "revision.repositoryUrl") != (
        "https://gcc.gnu.org/git/gcc.git"
    ):
        raise VerificationError("revision.repositoryUrl must be the canonical GCC Git repository")
    expected_tag = f"releases/{archive_root}"
    if _string(revision["tag"], "revision.tag") != expected_tag:
        raise VerificationError(f"revision.tag must be {expected_tag}")
    tag_object = _matching_string(revision["tagObject"], "revision.tagObject", _GIT_OBJECT)
    commit = _matching_string(revision["commit"], "revision.commit", _GIT_OBJECT)
    if tag_object == commit:
        raise VerificationError(
            "revision.tagObject must identify the annotated tag, not its commit"
        )

    tag_evidence = _object(
        revision["tagEvidence"],
        "revision.tagEvidence",
        {
            "payloadFile",
            "payloadBytes",
            "payloadSha256",
            "signatureFile",
            "signatureBytes",
            "signatureSha256",
        },
    )
    payload_relative = _relative_path(
        tag_evidence["payloadFile"], "revision.tagEvidence.payloadFile"
    )
    signature_relative = _relative_path(
        tag_evidence["signatureFile"], "revision.tagEvidence.signatureFile"
    )
    payload_bytes = _integer(
        tag_evidence["payloadBytes"], "revision.tagEvidence.payloadBytes"
    )
    signature_bytes = _integer(
        tag_evidence["signatureBytes"], "revision.tagEvidence.signatureBytes"
    )
    payload_sha256 = _matching_string(
        tag_evidence["payloadSha256"], "revision.tagEvidence.payloadSha256", _SHA256
    )
    signature_sha256 = _matching_string(
        tag_evidence["signatureSha256"],
        "revision.tagEvidence.signatureSha256",
        _SHA256,
    )
    tag_payload_path = _resolve_local_file(
        lock_directory, payload_relative, "annotated-tag payload"
    )
    tag_signature_path = _resolve_local_file(
        lock_directory, signature_relative, "annotated-tag signature"
    )
    _verify_size_and_hash(
        tag_payload_path, payload_bytes, payload_sha256, "annotated-tag payload"
    )
    _verify_size_and_hash(
        tag_signature_path,
        signature_bytes,
        signature_sha256,
        "annotated-tag signature",
    )
    tag_payload = _read_bytes(tag_payload_path, "annotated-tag payload")
    tag_signature = _read_bytes(tag_signature_path, "annotated-tag signature")
    try:
        payload_lines = tag_payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("annotated-tag payload is not UTF-8") from error
    if (
        len(payload_lines) != 6
        or payload_lines[0] != f"object {commit}"
        or payload_lines[1] != "type commit"
        or payload_lines[2] != f"tag {expected_tag}"
        or re.fullmatch(r"tagger .+ <[^<>]+> [0-9]+ [+-][0-9]{4}", payload_lines[3]) is None
        or payload_lines[4] != ""
        or payload_lines[5] != f"GCC {version} release"
        or not tag_payload.endswith(b"\n")
    ):
        raise VerificationError("annotated-tag payload does not bind the locked release and commit")
    raw_tag = tag_payload + tag_signature
    git_header = f"tag {len(raw_tag)}\0".encode("ascii")
    calculated_tag_object = hashlib.sha1(git_header + raw_tag).hexdigest()
    if calculated_tag_object != tag_object:
        raise VerificationError(
            f"annotated Git tag object mismatch: expected {tag_object}, "
            f"got {calculated_tag_object}"
        )

    markers = _object(
        revision["archiveMarkers"],
        "revision.archiveMarkers",
        {"revision", "version", "developmentPhase"},
    )
    revision_marker = _content_record(
        markers["revision"], "revision.archiveMarkers.revision", with_text=True
    )
    version_marker = _content_record(
        markers["version"], "revision.archiveMarkers.version", with_text=True
    )
    phase_marker = _content_record(
        markers["developmentPhase"],
        "revision.archiveMarkers.developmentPhase",
        with_text=True,
    )
    if revision_marker["path"] != "LAST_UPDATED" or revision_marker["text"] != (
        f"Obtained from git: {expected_tag} revision {commit}\n"
    ):
        raise VerificationError("revision marker must bind the locked tag and commit")
    if version_marker["path"] != "gcc/BASE-VER" or version_marker["text"] != f"{version}\n":
        raise VerificationError("version marker must bind oracle.version")
    if phase_marker["path"] != "gcc/DEV-PHASE" or phase_marker["text"] != "":
        raise VerificationError("development phase marker must lock an empty release phase")

    signing = _object(
        root["signing"],
        "signing",
        {
            "authorityUrl",
            "keyRetrievalUrl",
            "keyFile",
            "keySha256",
            "primaryFingerprint",
            "signingFingerprint",
        },
    )
    if _https_url(signing["authorityUrl"], "signing.authorityUrl") != (
        "https://gcc.gnu.org/mirrors.html"
    ):
        raise VerificationError("signing.authorityUrl must be the GCC release-key authority")
    key_retrieval_url = _https_url(
        signing["keyRetrievalUrl"], "signing.keyRetrievalUrl", allow_query=True
    )
    _matching_string(signing["keySha256"], "signing.keySha256", _SHA256)
    _matching_string(
        signing["primaryFingerprint"], "signing.primaryFingerprint", _FINGERPRINT
    )
    signing_fingerprint = _matching_string(
        signing["signingFingerprint"], "signing.signingFingerprint", _FINGERPRINT
    )
    expected_key_retrieval_url = (
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x"
        f"{signing_fingerprint}"
    )
    if key_retrieval_url != expected_key_retrieval_url:
        raise VerificationError(
            "signing.keyRetrievalUrl must be derived from signing.signingFingerprint"
        )
    key_relative = _relative_path(signing["keyFile"], "signing.keyFile")
    key_path = _resolve_local_file(lock_directory, key_relative, "vendored signing key")
    _verify_key_identity(key_path, signing)
    _verify_detached_signature(
        tag_payload_path,
        tag_signature_path,
        key_path,
        signing,
        "annotated GCC tag",
    )

    redistribution = _object(
        root["redistribution"], "redistribution", {"summary", "licenseFiles"}
    )
    _string(redistribution["summary"], "redistribution.summary")
    license_values = _list(redistribution["licenseFiles"], "redistribution.licenseFiles")
    license_records = [
        _content_record(value, f"redistribution.licenseFiles[{index}]", with_text=False)
        for index, value in enumerate(license_values)
    ]
    paths = [record["path"] for record in license_records]
    if len(paths) != len(set(paths)):
        raise VerificationError("redistribution.licenseFiles contains duplicate paths")
    expected_license_paths = {"COPYING", "COPYING3", "COPYING3.LIB", "COPYING.RUNTIME"}
    if set(paths) != expected_license_paths:
        raise VerificationError(
            "redistribution.licenseFiles must lock COPYING, COPYING3, COPYING3.LIB, "
            "and COPYING.RUNTIME"
        )

    marker_paths = {
        revision_marker["path"],
        version_marker["path"],
        phase_marker["path"],
    }
    if marker_paths & set(paths):
        raise VerificationError("archive marker and license paths must be distinct")
    return key_path


def load_and_validate_lock(lock_path: Path) -> dict[str, Any]:
    lock_path = lock_path.resolve()
    data = _load_json(lock_path)
    validate_lock(data, lock_path)
    return data


def _expected_archive_records(data: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    markers = data["revision"]["archiveMarkers"]
    records = [markers["revision"], markers["version"], markers["developmentPhase"]]
    records.extend(data["redistribution"]["licenseFiles"])
    root = data["source"]["archiveRoot"]
    return {f"{root}/{record['path']}": record for record in records}


def _verify_archive_contents(archive_path: Path, data: Mapping[str, Any]) -> None:
    expected = _expected_archive_records(data)
    seen: set[str] = set()
    root = data["source"]["archiveRoot"]
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            for member in archive:
                normalized = PurePosixPath(member.name)
                canonical = str(normalized)
                if member.isdir():
                    canonical = canonical.rstrip("/")
                if (
                    normalized.is_absolute()
                    or any(part in {"", ".", ".."} for part in normalized.parts)
                    or member.name.rstrip("/") != canonical
                    or not normalized.parts
                    or normalized.parts[0] != root
                ):
                    raise VerificationError(f"archive contains non-canonical path: {member.name}")
                if member.name not in expected:
                    continue
                if member.name in seen:
                    raise VerificationError(
                        f"archive contains duplicate locked path: {member.name}"
                    )
                if not member.isfile():
                    raise VerificationError(
                        f"locked archive path is not a regular file: {member.name}"
                    )
                specification = expected[member.name]
                if member.size != specification["bytes"]:
                    raise VerificationError(
                        f"archive member {member.name} byte length mismatch: "
                        f"expected {specification['bytes']}, got {member.size}"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"could not read locked archive path: {member.name}")
                payload = extracted.read()
                digest = hashlib.sha256(payload).hexdigest()
                if digest != specification["sha256"]:
                    raise VerificationError(
                        f"archive member {member.name} SHA-256 mismatch: "
                        f"expected {specification['sha256']}, got {digest}"
                    )
                if "text" in specification:
                    try:
                        text = payload.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise VerificationError(
                            f"archive marker {member.name} is not UTF-8"
                        ) from error
                    if text != specification["text"]:
                        raise VerificationError(
                            f"archive marker {member.name} text does not match the lock"
                        )
                seen.add(member.name)
    except (OSError, tarfile.TarError) as error:
        raise VerificationError(f"cannot inspect source archive {archive_path}: {error}") from error

    missing = sorted(set(expected) - seen)
    if missing:
        raise VerificationError(f"archive is missing locked provenance paths: {missing}")


def _verify_detached_signature(
    signed_path: Path,
    signature_path: Path,
    key_path: Path,
    signing: Mapping[str, Any],
    label: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="gcc-oracle-gpg-") as temporary:
        home = Path(temporary)
        os.chmod(home, 0o700)
        _import_key(home, key_path)
        verified = _run_gpg(
            ["--status-fd", "1", "--verify", str(signature_path), str(signed_path)],
            home,
        )
    if verified.returncode != 0:
        diagnostic = verified.stderr.strip() or "no diagnostic"
        raise VerificationError(f"{label} signature verification failed: {diagnostic}")

    valid_signatures: list[tuple[str, str]] = []
    for line in verified.stdout.splitlines():
        prefix = "[GNUPG:] VALIDSIG "
        if not line.startswith(prefix):
            continue
        fields = line[len(prefix) :].split()
        if len(fields) < 10:
            raise VerificationError("gpg returned a malformed VALIDSIG status record")
        valid_signatures.append((fields[0], fields[-1]))
    expected = (signing["signingFingerprint"], signing["primaryFingerprint"])
    if valid_signatures != [expected]:
        raise VerificationError(
            f"{label} signer mismatch: expected {expected}, got {valid_signatures}"
        )


def verify_source_release(
    lock_path: Path,
    archive_path: Path,
    signature_path: Path,
) -> dict[str, Any]:
    """Verify exact source bytes, signature, embedded revision, and license notices."""

    lock_path = lock_path.resolve()
    data = _load_json(lock_path)
    key_path = validate_lock(data, lock_path)
    verify_locked_file(archive_path.resolve(), data["source"]["archive"], "source archive")
    verify_locked_file(
        signature_path.resolve(),
        data["source"]["detachedSignature"],
        "detached signature",
    )
    _verify_detached_signature(
        archive_path.resolve(),
        signature_path.resolve(),
        key_path,
        data["signing"],
        "GCC source release",
    )
    _verify_archive_contents(archive_path.resolve(), data)
    return data
