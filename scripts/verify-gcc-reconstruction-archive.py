#!/usr/bin/env python3
"""Qualify a reproduced cc1 reconstruction archive at the archive boundary.

This command verifies the checked GCC control plane, compares two accepted
archive byte streams, strictly extracts both into private temporary trees, and
rebuilds each tree using its recorded Make command.  It deliberately does not
claim that the archive was produced by a qualified bundled-Ghidra
reconstruction run; the emitted receipt records that limitation.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.compiler_engines import load_compiler_engine_profile  # noqa: E402
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


MAXIMUM_ARCHIVE_ENTRIES = 100_000
MAXIMUM_ARCHIVE_FILE_BYTES = 128 * 1024 * 1024
MAXIMUM_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
SHA256 = set("0123456789abcdef")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} must be a non-symlink regular file: {path}")


def _bound_file(root: Path, relative: str, expected: str, label: str) -> dict[str, Any]:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise VerificationError(f"{label} escapes the compiler profile directory") from error
    _regular(candidate, label)
    actual = _sha256_file(candidate)
    if actual != expected:
        raise VerificationError(f"{label} SHA-256 differs from its profile binding")
    return {"path": relative, "bytes": candidate.stat().st_size, "sha256": actual}


def _authenticate_controls(profile_path: Path, engine_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        profile, derived_records = load_compiler_engine_profile(profile_path)
    except Exception as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError(f"compiler-engine profile is not authenticated: {error}") from error
    engine = next((item for item in profile["engines"] if item["id"] == engine_id), None)
    if engine is None:
        raise VerificationError(f"compiler-engine profile has no {engine_id} engine")
    if engine_id != "cc1":
        raise VerificationError("this qualification command is owned by cc1 and cannot use another engine")

    root = profile_path.resolve().parent
    provenance = profile["provenance"]
    controls = [
        ("benchmarkProfile", profile_path, _sha256_file(profile_path)),
        ("sourceLock", root / provenance["sourceLockPath"], provenance["sourceLockSha256"]),
        ("baseBuildRecord", root / provenance["baseBuildRecordPath"], provenance["baseBuildRecordSha256"]),
        ("toolchainReproduction", root / provenance["toolchainReproductionPath"], provenance["toolchainReproductionSha256"]),
        ("engineBuildRecord", root / engine["buildRecord"], engine["buildRecordSha256"]),
        ("engineOracleManifest", root / engine["oracleManifest"], engine["oracleManifestSha256"]),
    ]
    evidence = []
    for role, path, expected in controls:
        _regular(path, role)
        actual = _sha256_file(path)
        if actual != expected:
            raise VerificationError(f"{role} SHA-256 differs from its authenticated binding")
        evidence.append({"role": role, "path": str(path), "bytes": path.stat().st_size, "sha256": actual})

    record_path = root / engine["buildRecord"]
    record = _read_json(record_path, "cc1 build record")
    if record["oracle"]["id"] != "gcc-cc1-" + profile["benchmark"]["version"]:
        raise VerificationError("cc1 build record does not identify the selected engine")
    if record["outputs"]["stripped"] != engine["strippedArtifact"]:
        raise VerificationError("cc1 build record stripped output differs from its profile")
    if record["oracle"]["sourceLockSha256"] != provenance["sourceLockSha256"]:
        raise VerificationError("cc1 build record is not bound to the profile source lock")
    manifest = _read_json(root / engine["oracleManifest"], "cc1 oracle manifest")
    if manifest["oracle"]["sourceRevision"] != record["oracle"]["sourceRevision"]:
        raise VerificationError("cc1 oracle manifest source revision differs from the build record")
    if manifest["inputs"]["sourceLock"]["sha256"] != provenance["sourceLockSha256"]:
        raise VerificationError("cc1 oracle manifest source lock binding differs from the profile")
    if manifest["inputs"]["buildRecord"]["sha256"] != engine["buildRecordSha256"]:
        raise VerificationError("cc1 oracle manifest build-record binding differs from the profile")
    stripped = manifest["artifacts"]["stripped"]
    # The profile stores the authoritative stripped digest in the manifest
    # rather than repeating it in compiler-engines.json.
    if stripped["path"] != engine["strippedArtifact"]:
        raise VerificationError("cc1 oracle manifest stripped artifact path differs from the profile")

    return profile, {
        "profileSha256": _sha256_file(profile_path),
        "profileId": profile["benchmark"]["id"],
        "sourceLockSha256": provenance["sourceLockSha256"],
        "strippedArtifactSha256": stripped["sha256"],
        "controls": evidence,
        "derivedBuildRecord": derived_records[engine_id],
    }


def _archive_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise VerificationError(f"archive member path is not canonical: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(part in {"", ".", ".."} for part in name.split("/")):
        raise VerificationError(f"archive member path is not canonical: {name!r}")
    return name


def _source_revision(root: Path) -> tuple[str, list[dict[str, Any]]]:
    inputs = []
    candidates = [root / "Makefile"]
    for directory in (root / "src", root / "include"):
        if directory.exists():
            candidates.extend(path for path in directory.rglob("*") if path.is_file() and not path.is_symlink())
    for path in sorted(candidates):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = _sha256_file(path)
        inputs.append({"path": relative, "bytes": size, "sha256": digest})
    if not inputs or inputs[0]["path"] != "Makefile":
        raise VerificationError("extracted cc1 archive has no complete Make source revision")
    canonical = "".join(f"{item['path'].__len__()}:{item['path']}:{item['bytes']}:{item['sha256']}\n" for item in inputs)
    return _sha256_bytes(canonical.encode("utf-8")), inputs


def _verify_source_tree(root: Path, profile: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    required = (
        "ARCHIVE_MANIFEST.sha256",
        "ARCHIVE_README.md",
        "BUILDING.md",
        "Makefile",
        "UNRESOLVED.md",
        "source_tree_manifest.json",
        "reports/archival_audit.json",
        "reports/build_contract.json",
        "reports/program_model.json",
        "reports/toolchain.json",
    )
    for relative in required:
        _regular(root / relative, f"archive evidence {relative}")
    source_manifest = _read_json(root / "source_tree_manifest.json", "source tree manifest")
    expected_profile_id = "generated-c-make-v1-" + profile["benchmark"]["id"]
    if source_manifest.get("profileId") != expected_profile_id:
        raise VerificationError("source tree manifest is not bound to the GCC compiler-engine profile")
    if source_manifest.get("inputSha256") != control["strippedArtifactSha256"]:
        raise VerificationError("source tree manifest input is not the authenticated cc1 stripped artifact")
    if (
        not isinstance(source_manifest.get("profileSha256"), str)
        or len(source_manifest["profileSha256"]) != 64
        or any(character not in SHA256 for character in source_manifest["profileSha256"])
    ):
        raise VerificationError("source tree manifest has no reconstruction-profile digest")
    model = _read_json(root / "reports/program_model.json", "program model evidence")
    if model.get("inputSha256") != control["strippedArtifactSha256"]:
        raise VerificationError("program model evidence is not bound to the authenticated cc1 input")
    source_revision, inputs = _source_revision(root)
    contract = _read_json(root / "reports/build_contract.json", "build contract")
    if contract.get("schemaVersion") != 2 or contract.get("returnCode") != 0:
        raise VerificationError("cc1 archive build contract is not a successful schema-2 build")
    for field in ("sourceStableDuringBuild", "warningsAsErrors", "reproduciblePathMapping"):
        if contract.get(field) is not True:
            raise VerificationError(f"cc1 archive build contract does not prove {field}")
    if contract.get("apiCredentialsRequired") is not False or contract.get("analysisCachesRequired") is not False:
        raise VerificationError("cc1 archive build contract has undeclared external requirements")
    if contract.get("sourceInputs") != inputs or contract.get("sourceRevisionSha256") != source_revision:
        raise VerificationError("cc1 archive source revision differs from its build contract")
    command = contract.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise VerificationError("cc1 archive build contract has no executable command")
    if Path(command[0]).name not in {"make", "gmake"}:
        raise VerificationError("cc1 archive qualification only executes the recorded Make command")
    artifact = contract.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("path") != "build/reconstructed":
        raise VerificationError("cc1 archive build contract has no reconstructed executable identity")
    manifest_files = source_manifest.get("files")
    if not isinstance(manifest_files, list):
        raise VerificationError("source tree manifest has no generated-file inventory")
    for item in manifest_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
            raise VerificationError("source tree manifest contains an invalid generated-file record")
        relative = _archive_member_name(item["path"])
        if len(item["sha256"]) != 64 or any(character not in SHA256 for character in item["sha256"]):
            raise VerificationError(f"source tree manifest has an invalid file digest: {relative}")
        _regular(root / relative, f"source tree manifest file {relative}")
        if _sha256_file(root / relative) != item["sha256"]:
            raise VerificationError(f"source tree manifest hash differs: {relative}")
    return {
        "sourceTreeManifestSha256": _sha256_file(root / "source_tree_manifest.json"),
        "sourceRevisionSha256": source_revision,
        "sourceInputs": inputs,
        "buildContractSha256": _sha256_file(root / "reports/build_contract.json"),
        "toolchainEvidenceSha256": _sha256_file(root / "reports/toolchain.json"),
        "validationEvidenceSha256": _sha256_file(root / "reports/archival_audit.json"),
        "command": command,
        "expectedArtifact": artifact,
    }


def _extract_and_build(
    archive: Path,
    profile: dict[str, Any],
    control: dict[str, Any],
) -> dict[str, Any]:
    _regular(archive, "reconstruction archive")
    archive_sha256 = _sha256_file(archive)
    archive_bytes = archive.stat().st_size
    with tempfile.TemporaryDirectory(prefix="cc1-archive-extract-") as temporary:
        root = Path(temporary) / "source"
        root.mkdir()
        seen: set[str] = set()
        portable: set[str] = set()
        total = 0
        try:
            with zipfile.ZipFile(archive) as source:
                infos = source.infolist()
                if not infos or len(infos) > MAXIMUM_ARCHIVE_ENTRIES:
                    raise VerificationError("reconstruction archive entry count is outside its bound")
                manifest: dict[str, str] = {}
                for info in infos:
                    name = _archive_member_name(info.filename)
                    if name in seen or name.casefold() in portable:
                        raise VerificationError(f"reconstruction archive has duplicate path: {name}")
                    seen.add(name)
                    portable.add(name.casefold())
                    if info.is_dir() or info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 0x1:
                        raise VerificationError(f"reconstruction archive member is not an uncompressed regular file: {name}")
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK or mode not in (0, stat.S_IFREG):
                        raise VerificationError(f"reconstruction archive member has unsafe file mode: {name}")
                    if info.file_size > MAXIMUM_ARCHIVE_FILE_BYTES:
                        raise VerificationError(f"reconstruction archive member exceeds its file bound: {name}")
                    total += info.file_size
                    if total > MAXIMUM_ARCHIVE_TOTAL_BYTES:
                        raise VerificationError("reconstruction archive exceeds its total byte bound")
                    target = root / name
                    if name == "build" or name.startswith("build/"):
                        raise VerificationError("reconstruction archive must not contain a prior build tree")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(info) as input_stream, target.open("xb") as output:
                        shutil.copyfileobj(input_stream, output, 1024 * 1024)
                if "ARCHIVE_MANIFEST.sha256" not in seen:
                    raise VerificationError("archive hash manifest does not cover the complete payload")
                try:
                    lines = (root / "ARCHIVE_MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError) as error:
                    raise VerificationError("archive hash manifest is not UTF-8") from error
                for line in lines:
                    if not line:
                        continue
                    digest, separator, relative = line.partition("  ")
                    if not separator or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                        raise VerificationError("archive hash manifest contains an invalid line")
                    _archive_member_name(relative)
                    if relative == "ARCHIVE_MANIFEST.sha256" or relative in manifest:
                        raise VerificationError("archive hash manifest contains a duplicate or self reference")
                    if _sha256_file(root / relative) != digest:
                        raise VerificationError(f"archive hash manifest digest differs: {relative}")
                    manifest[relative] = digest
                if set(manifest) != seen - {"ARCHIVE_MANIFEST.sha256"}:
                    raise VerificationError("archive hash manifest does not cover the complete payload")
        except zipfile.BadZipFile as error:
            raise VerificationError(f"cannot read reconstruction archive: {error}") from error

        evidence = _verify_source_tree(root, profile, control)
        contract = _read_json(root / "reports/build_contract.json", "build contract")
        maximum_output = contract.get("maximumOutputBytes", 32 * 1024 * 1024)
        timeout_millis = contract.get("wallClockTimeoutMillis", 600_000)
        if not isinstance(maximum_output, int) or not 0 < maximum_output <= 32 * 1024 * 1024:
            raise VerificationError("archive build output bound is invalid")
        if not isinstance(timeout_millis, int) or not 0 < timeout_millis <= 600_000:
            raise VerificationError("archive build timeout bound is invalid")
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"}
        try:
            completed = subprocess.run(
                evidence["command"], cwd=root, env=environment, capture_output=True,
                timeout=timeout_millis / 1000, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError(f"clean extraction build did not complete: {error}") from error
        output_bytes = len(completed.stdout) + len(completed.stderr)
        if output_bytes > maximum_output:
            raise VerificationError("clean extraction build exceeded its recorded output bound")
        if completed.returncode != 0:
            raise VerificationError(f"clean extraction build failed with exit {completed.returncode}")
        artifact = root / evidence["expectedArtifact"]["path"]
        _regular(artifact, "rebuilt cc1 archive executable")
        artifact_bytes = artifact.stat().st_size
        artifact_sha256 = _sha256_file(artifact)
        if artifact_bytes != evidence["expectedArtifact"]["bytes"] or artifact_sha256 != evidence["expectedArtifact"]["sha256"]:
            raise VerificationError("clean extraction executable differs from its accepted build evidence")
        return {
            "archiveBytes": archive_bytes,
            "archiveSha256": archive_sha256,
            "build": evidence,
            "executable": {"path": evidence["expectedArtifact"]["path"], "bytes": artifact_bytes, "sha256": artifact_sha256},
            "buildOutputBytes": output_bytes,
        }


def verify_archive(profile_path: Path, engine_id: str, archive: Path, repeat_archive: Path) -> dict[str, Any]:
    profile, control = _authenticate_controls(profile_path.resolve(), engine_id)
    _regular(archive, "first reconstruction archive")
    _regular(repeat_archive, "repeat reconstruction archive")
    if archive.stat().st_size != repeat_archive.stat().st_size or not filecmp.cmp(archive, repeat_archive, shallow=False):
        raise VerificationError("repeated accepted cc1 archives are not byte-identical")
    first = _extract_and_build(archive, profile, control)
    repeat = _extract_and_build(repeat_archive, profile, control)
    if first["executable"] != repeat["executable"]:
        raise VerificationError("repeated cc1 archive builds produced different executable evidence")
    return {
        "provider": "gcc-cc1-reconstruction-archive-verifier-v1",
        "schemaVersion": 1,
        "engine": engine_id,
        "complete": False,
        "releaseEligible": False,
        "authority": "local-clean-extraction-build-evidence",
        "profile": {
            "benchmarkId": control["profileId"],
            "sha256": control["profileSha256"],
            "strippedArtifactSha256": control["strippedArtifactSha256"],
        },
        "authenticatedControls": control["controls"],
        "archives": {
            "byteIdentical": True,
            "first": {"bytes": first["archiveBytes"], "sha256": first["archiveSha256"]},
            "repeat": {"bytes": repeat["archiveBytes"], "sha256": repeat["archiveSha256"]},
        },
        "cleanBuilds": [first, repeat],
        "limitations": [
            "The verifier does not establish that a qualified bundled-Ghidra fresh run produced the archive.",
            "The verifier does not establish the parent engine interruption/resume equivalence proof.",
            "The compiler and Make process are run in a temporary extraction; their host identity is retained as archive evidence only.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--engine", choices=("cc1",), default="cc1")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--repeat-archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        evidence = verify_archive(arguments.profile, arguments.engine, arguments.archive, arguments.repeat_archive)
        destination = arguments.evidence.absolute()
        if destination.is_symlink() or destination.exists() and not destination.is_file():
            raise VerificationError("evidence destination must be a regular non-symlink path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
        print(f"verified byte-identical cc1 reconstruction archives: {evidence['archives']['first']['sha256']}")
        print(f"wrote evidence: {destination}")
        return 0
    except (OSError, VerificationError) as error:
        print(f"cc1 reconstruction archive verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
