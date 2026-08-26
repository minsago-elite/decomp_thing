#!/usr/bin/env python3
"""Rebuild the pinned GCC benchmark pair in its recorded container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.gcc.verify_oracle_artifacts import (  # noqa: E402
    create_oracle_manifest,
    validate_build_record,
    verify_oracle_manifest,
)
from oracle.gcc.verify_source_lock import (  # noqa: E402
    VerificationError,
    load_and_validate_lock,
    verify_source_release,
)


DEFAULT_VERSION_ROOT = REPOSITORY_ROOT / "oracle/gcc/16.2.0"


def _load_json(path: Path, label: str) -> dict[str, Any]:
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
        raise VerificationError(f"cannot load {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _run(arguments: list[str], *, cwd: Path | None = None, capture: bool = False) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if completed.returncode != 0:
        detail = ""
        if capture:
            detail = (completed.stderr or completed.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise VerificationError(
            f"command failed with exit {completed.returncode}: {arguments!r}{suffix}"
        )
    return (completed.stdout or "").strip()


def _safe_extract(archive_path: Path, destination: Path, expected_root: str) -> None:
    """Extract the already authenticated archive without permitting escaping links."""

    def member_parts(member: tarfile.TarInfo) -> tuple[str, ...]:
        name = member.name
        if member.isdir() and name.endswith("/") and not name.endswith("//"):
            name = name[:-1]
        raw_parts = name.split("/")
        if (
            not name
            or name.startswith("/")
            or "\\" in name
            or "\x00" in name
            or any(part in {"", ".", ".."} for part in raw_parts)
        ):
            raise VerificationError(f"archive member path is not canonical: {member.name}")
        if raw_parts[0] != expected_root:
            raise VerificationError(f"archive member is outside {expected_root}: {member.name}")
        return tuple(raw_parts)

    def link_target(member: tarfile.TarInfo, parts: tuple[str, ...]) -> tuple[str, ...]:
        linkname = member.linkname
        if not linkname or linkname.startswith("/") or "\\" in linkname or "\x00" in linkname:
            raise VerificationError(f"archive link target is invalid: {member.name}")
        normalized = [] if member.islnk() else list(parts[:-1])
        for part in linkname.split("/"):
            if part in {"", "."}:
                raise VerificationError(f"archive link target is not canonical: {member.name}")
            if part == "..":
                if not normalized:
                    raise VerificationError(f"archive link escapes its root: {member.name}")
                normalized.pop()
            else:
                normalized.append(part)
        if not normalized or normalized[0] != expected_root:
            raise VerificationError(f"archive link escapes {expected_root}: {member.name}")
        return tuple(normalized)

    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            members = archive.getmembers()
            indexed: dict[tuple[str, ...], tarfile.TarInfo] = {}
            for member in members:
                parts = member_parts(member)
                if parts in indexed:
                    raise VerificationError(f"archive contains a duplicate member: {member.name}")
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise VerificationError(f"archive contains a special file: {member.name}")
                indexed[parts] = member

            for parts, member in indexed.items():
                for length in range(1, len(parts)):
                    parent = indexed.get(parts[:length])
                    if parent is not None and not parent.isdir():
                        raise VerificationError(
                            f"archive member descends through a non-directory: {member.name}"
                        )
                if member.issym() or member.islnk():
                    target = link_target(member, parts)
                    if member.islnk():
                        target_member = indexed.get(target)
                        if target_member is None or not target_member.isfile():
                            raise VerificationError(
                                f"archive hard link does not target a regular member: {member.name}"
                            )

            # PEP 706's data filter is explicit so extraction behavior cannot
            # silently change with the interpreter's process-wide default.
            archive.extractall(destination, members=members, filter="data")
    except TypeError as error:
        raise VerificationError("safe archive extraction requires PEP 706 tar filters") from error
    except tarfile.TarError as error:
        raise VerificationError(f"cannot safely extract source archive: {error}") from error


def _container_arguments(
    docker: str,
    digest: str,
    platform: str,
    variables: dict[str, str],
    mount: Path,
    workdir: str,
    command: list[str],
    *,
    read_only_mount: bool = False,
) -> list[str]:
    if "," in str(mount):
        raise VerificationError("Docker --mount source paths may not contain commas")
    mount_spec = f"type=bind,src={mount},dst=/oracle"
    if read_only_mount:
        mount_spec += ",readonly"
    return [
        docker,
        "run",
        "--rm",
        "--platform",
        platform,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec",
        "--mount",
        mount_spec,
        "--workdir",
        workdir,
        "--entrypoint",
        "/usr/bin/env",
        digest,
        "-i",
        *(f"{name}={value}" for name, value in variables.items()),
        *command,
    ]


def _replace_outputs(command: list[str], full: str, stripped: str) -> list[str]:
    return [argument.replace("{full}", full).replace("{stripped}", stripped) for argument in command]


def _copy_source_lock_evidence(
    source_lock: dict[str, Any], version_root: Path, workspace: Path
) -> None:
    """Stage the signed-revision evidence needed to revalidate a copied lock."""

    tag_evidence = source_lock["revision"]["tagEvidence"]
    relative_paths = (
        tag_evidence["payloadFile"],
        tag_evidence["signatureFile"],
        source_lock["signing"]["keyFile"],
    )
    resolved_root = version_root.resolve()
    for relative in relative_paths:
        source = version_root
        for part in PurePosixPath(relative).parts:
            source = source / part
            if source.is_symlink():
                raise VerificationError(f"source-lock evidence path contains a symlink: {source}")
        source = source.resolve()
        try:
            source.relative_to(resolved_root)
        except ValueError as error:
            raise VerificationError(f"source-lock evidence escapes version root: {relative}") from error
        if not source.is_file():
            raise VerificationError(f"source-lock evidence is not a regular file: {source}")
        destination = workspace / PurePosixPath(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def rebuild(
    *,
    docker: str,
    workspace: Path,
    archive: Path,
    signature: Path,
    version_root: Path,
) -> Path:
    source_lock_path = version_root / "source-lock.json"
    build_record_path = version_root / "build-record.json"
    expected_manifest_path = version_root / "oracle-manifest.json"
    try:
        container_version_root = version_root.resolve().relative_to(REPOSITORY_ROOT.resolve())
    except ValueError as error:
        raise VerificationError("version root must be inside the repository") from error

    expected_manifest = verify_oracle_manifest(expected_manifest_path)
    source_lock = load_and_validate_lock(source_lock_path)
    verify_source_release(source_lock_path, archive, signature)
    build_record = _load_json(build_record_path, "build record")
    validate_build_record(build_record, source_lock, _sha256(source_lock_path))

    container = build_record["environment"]["container"]
    digest = container["digest"]
    observed_digest = _run(
        [docker, "image", "inspect", "--format", "{{.Id}}", container["image"]],
        capture=True,
    )
    if observed_digest != digest:
        raise VerificationError(
            f"container image digest mismatch: expected {digest}, got {observed_digest}"
        )

    print("==> verifyBuildEnvironment", flush=True)
    _run(
        _container_arguments(
            docker,
            digest,
            container["platform"],
            build_record["environment"]["variables"],
            REPOSITORY_ROOT,
            "/oracle",
            [
                "/usr/bin/python3",
                "scripts/verify-gcc-oracle-build-record.py",
                "--source-lock",
                (container_version_root / "source-lock.json").as_posix(),
                "--build-record",
                (container_version_root / "build-record.json").as_posix(),
                "--container-digest",
                digest,
            ],
            read_only_mount=True,
        )
    )

    workspace = workspace.absolute()
    if workspace.exists():
        raise VerificationError(f"clean workspace already exists: {workspace}")
    workspace.mkdir(parents=True)
    for name in ("source", "build", "install", "artifacts"):
        (workspace / name).mkdir()

    source_root = source_lock["source"]["archiveRoot"]
    _safe_extract(archive, workspace / "source", source_root)
    expected_directories = {
        "source": f"/oracle/source/{source_root}",
        "build": "/oracle/build",
        "install": "/oracle/install",
    }
    if build_record["directories"] != expected_directories:
        raise VerificationError(
            f"build directories are unsupported by this runner: {build_record['directories']}"
        )

    variables = build_record["environment"]["variables"]
    platform_name = container["platform"]
    commands = build_record["commands"]
    for phase in ("configure", "compile", "install"):
        print(f"==> {phase}", flush=True)
        _run(
            _container_arguments(
                docker,
                digest,
                platform_name,
                variables,
                workspace,
                "/oracle/build",
                commands[phase],
            )
        )

    full_relative = build_record["outputs"]["full"]
    stripped_relative = build_record["outputs"]["stripped"]
    full_container = f"/oracle/{full_relative}"
    stripped_container = f"/oracle/{stripped_relative}"
    for phase, command in (
        ("stageFull", _replace_outputs(commands["stageFull"], full_container, stripped_container)),
        ("strip", _replace_outputs(commands["strip"], full_container, stripped_container)),
    ):
        print(f"==> {phase}", flush=True)
        _run(
            _container_arguments(
                docker,
                digest,
                platform_name,
                variables,
                workspace,
                "/oracle/build",
                command,
            )
        )

    shutil.copy2(source_lock_path, workspace / "source-lock.json")
    shutil.copy2(build_record_path, workspace / "build-record.json")
    _copy_source_lock_evidence(source_lock, version_root, workspace)
    generated_manifest_path = workspace / "oracle-manifest.json"
    create_oracle_manifest(
        generated_manifest_path,
        workspace / "source-lock.json",
        workspace / "build-record.json",
    )
    if generated_manifest_path.read_bytes() != expected_manifest_path.read_bytes():
        raise VerificationError("clean rebuild manifest differs from the checked-in manifest")

    full = expected_manifest["artifacts"]["full"]
    stripped = expected_manifest["artifacts"]["stripped"]
    print("reproduced checked-in benchmark artifacts and manifest")
    print(f"  full SHA-256:     {full['sha256']}")
    print(f"  stripped SHA-256: {stripped['sha256']}")
    return generated_manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild and byte-compare the pinned GCC benchmark artifacts."
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source-cache", required=True, type=Path)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--version-root", type=Path, default=DEFAULT_VERSION_ROOT)
    arguments = parser.parse_args()

    cache = arguments.source_cache.absolute()
    try:
        rebuild(
            docker=arguments.docker,
            workspace=arguments.workspace,
            archive=cache / "gcc-16.2.0.tar.xz",
            signature=cache / "gcc-16.2.0.tar.xz.sig",
            version_root=arguments.version_root.absolute(),
        )
    except (VerificationError, OSError) as error:
        print(f"rebuild failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
