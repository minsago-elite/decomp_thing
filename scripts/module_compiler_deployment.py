#!/usr/bin/env python3
"""Materialize and revalidate the bounded hosted module-worker JAR deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

MAXIMUM_ENTRIES = 128
MAXIMUM_MEMBER_BYTES = 256 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 256 * 1024 * 1024
MAXIMUM_MANIFEST_BYTES = 1024 * 1024
CHUNK_BYTES = 64 * 1024


class DeploymentError(ValueError):
    pass


def _fail(message: str) -> None:
    raise DeploymentError(message)


def _version(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _open_directory(path: Path) -> int:
    """Open an absolute directory by walking each component without following links."""
    if not path.is_absolute() or ".." in path.parts:
        _fail(f"deployment directory path is not a normalized absolute path: {path}")
    descriptor = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stat_path(path: Path) -> os.stat_result:
    parent_fd = _open_directory(path.parent)
    try:
        return os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)


def _open_regular(path: Path, expected_size: int | None = None) -> tuple[int, os.stat_result]:
    parent_fd = _open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            _fail(f"deployment input is not a private regular file: {path}")
        if expected_size is not None and info.st_size != expected_size:
            _fail(f"deployment input size changed: {path}")
        if _version(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) != _version(info):
            _fail(f"deployment input name changed while opening: {path}")
        return descriptor, info
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    finally:
        os.close(parent_fd)


def _hash_descriptor(descriptor: int, expected_size: int | None = None) -> tuple[int, str, os.stat_result]:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if expected_size is not None and total > expected_size:
            _fail("deployment input grew while hashing")
        digest.update(chunk)
    after = os.fstat(descriptor)
    if _version(after) != _version(before) or total != after.st_size:
        _fail("deployment input changed while hashing")
    if expected_size is not None and total != expected_size:
        _fail("deployment input ended before its pinned size")
    return total, digest.hexdigest(), after


def _source_pins(sources: list[Path]) -> list[dict[str, object]]:
    if not 1 <= len(sources) <= MAXIMUM_ENTRIES:
        _fail("module worker deployment entry count exceeds its fixed bound")
    result = []
    seen_paths: set[Path] = set()
    seen_names: set[str] = set()
    total = 0
    for source in sources:
        if not source.is_absolute() or source != source.resolve(strict=True) or source.suffix != ".jar":
            _fail(f"module worker deployment source is not a canonical JAR: {source}")
        if source in seen_paths or source.name in seen_names:
            _fail("module worker deployment sources contain a duplicate path or name")
        descriptor, before = _open_regular(source)
        try:
            if before.st_size > MAXIMUM_MEMBER_BYTES:
                _fail("module worker deployment member exceeds its fixed byte bound")
            size, digest, after = _hash_descriptor(descriptor, before.st_size)
            if _version(_stat_path(source)) != _version(after):
                _fail("module worker deployment source name changed while hashing")
        finally:
            os.close(descriptor)
        total += size
        if total > MAXIMUM_TOTAL_BYTES:
            _fail("module worker deployment exceeds its fixed aggregate byte bound")
        name = f"{len(result):03d}-{source.name}"
        result.append({"source": str(source), "name": name, "bytes": size, "sha256": digest})
        seen_paths.add(source)
        seen_names.add(source.name)
    return result


def _strict_manifest_bytes(value: bytes) -> dict[str, object]:
    if not 0 < len(value) <= MAXIMUM_MANIFEST_BYTES:
        _fail("worker classpath manifest exceeds its fixed byte bound")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                _fail("worker classpath manifest has duplicate fields")
            result[key] = item
        return result

    try:
        document = json.loads(value.decode("utf-8", "strict"), object_pairs_hook=unique,
                              parse_constant=lambda token: _fail(f"invalid JSON constant: {token}"))
    except (UnicodeError, json.JSONDecodeError) as failure:
        raise DeploymentError("worker classpath manifest is malformed") from failure
    if type(document) is not dict or set(document) != {"schemaVersion", "entries"} or document["schemaVersion"] != 1 or type(document["schemaVersion"]) is not int:
        _fail("worker classpath manifest differs from schema v1")
    entries = document["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= MAXIMUM_ENTRIES:
        _fail("worker classpath manifest entry count exceeds its bound")
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "bytes", "sha256"}:
            _fail("worker classpath entry differs from schema v1")
        if type(entry["bytes"]) is not int or not 0 < entry["bytes"] <= MAXIMUM_MEMBER_BYTES:
            _fail("worker classpath entry byte count is invalid")
        if type(entry["path"]) is not str or not entry["path"] or re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"])) is None:
            _fail("worker classpath entry path or digest is invalid")
    return document


def _read_manifest(parent_fd: int, name: str, display_path: Path) -> tuple[bytes, dict[str, object], tuple[int, int]]:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0 or
                _version(named) != _version(before)):
            _fail(f"deployment input is not a private regular file: {display_path}")
        if before.st_size > MAXIMUM_MANIFEST_BYTES:
            _fail("worker classpath manifest exceeds its fixed byte bound")
        if stat.S_IMODE(before.st_mode) != 0o444:
            _fail("worker classpath manifest is not read-only")
        owner = (before.st_uid, before.st_gid)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > MAXIMUM_MANIFEST_BYTES:
                _fail("worker classpath manifest exceeds its fixed byte bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (_version(after) != _version(before) or total != before.st_size or
                _version(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != _version(after)):
            _fail("worker classpath manifest changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    document = _strict_manifest_bytes(raw)
    canonical = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if raw != canonical:
        _fail("worker classpath manifest is not the exact published encoding")
    return raw, document, owner


def _stage_directory(parent_fd: int, name: str, display_path: Path, *,
                     expected_owner: tuple[int, int] | None = None,
                     allow_initial_mode: bool = False) -> tuple[int, os.stat_result]:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or
            _version(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != _version(info)):
        os.close(descriptor)
        _fail(f"worker deployment stage is not the expected real directory: {display_path}")
    if not allow_initial_mode and stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        _fail("published worker deployment stage is not owner-only")
    if expected_owner is not None and (info.st_uid, info.st_gid) != expected_owner:
        os.close(descriptor)
        _fail("published worker deployment stage owner differs from its manifest")
    return descriptor, info


def _verify_staged(parent_fd: int, stage_name: str, stage: Path, pins: list[dict[str, object]],
                   manifest: dict[str, object], expected_owner: tuple[int, int] | None = None) -> None:
    stage_fd, stage_before = _stage_directory(parent_fd, stage_name, stage, expected_owner=expected_owner)
    try:
        expected = []
        expected_manifest_entries = []
        for pin in pins:
            name = str(pin["name"])
            expected.append(name)
            expected_manifest_entries.append({
                "path": str(stage / name), "bytes": pin["bytes"], "sha256": pin["sha256"],
            })
        actual = sorted(os.listdir(stage_fd))
        if actual != sorted(expected):
            _fail("worker deployment stage names differ from the frozen exact set")
        if manifest != {"schemaVersion": 1, "entries": expected_manifest_entries}:
            _fail("worker classpath manifest differs from current prepared source identities")
        for pin in pins:
            name = str(pin["name"])
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage_fd)
            try:
                before = os.fstat(descriptor)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                        stat.S_IMODE(before.st_mode) != 0o444 or before.st_size != pin["bytes"]):
                    _fail(f"worker deployment member is not its exact private regular file: {name}")
                if (before.st_uid, before.st_gid) != (stage_before.st_uid, stage_before.st_gid):
                    _fail(f"worker deployment member owner differs from its frozen stage: {name}")
                size, digest, after = _hash_descriptor(descriptor, int(pin["bytes"]))
                named = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                if _version(after) != _version(named) or size != pin["bytes"] or digest != pin["sha256"]:
                    _fail(f"worker deployment member differs from its source pin: {name}")
            finally:
                os.close(descriptor)
        if sorted(os.listdir(stage_fd)) != sorted(expected) or _version(os.fstat(stage_fd)) != _version(stage_before):
            _fail("worker deployment stage changed during verification")
    finally:
        os.close(stage_fd)


def _publish_manifest(parent_fd: int, name: str, document: dict[str, object]) -> None:
    raw = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if len(raw) > MAXIMUM_MANIFEST_BYTES:
        _fail("worker classpath manifest exceeds its fixed byte bound")
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail("worker classpath manifest publication made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        os.chmod(name, 0o444, dir_fd=parent_fd, follow_symlinks=False)
        os.fsync(parent_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise
    os.unlink(temporary, dir_fd=parent_fd)


def materialize(manifest_path: Path, stage: Path, sources: list[Path]) -> bytes:
    manifest_path = manifest_path.absolute()
    stage = stage.absolute()
    if manifest_path.parent != stage.parent:
        _fail("worker deployment manifest and stage must share one exact output directory")
    pins = _source_pins(sources)
    parent_fd = _open_directory(manifest_path.parent)
    try:
        manifest_exists = _exists_at(parent_fd, manifest_path.name)
        stage_exists = _exists_at(parent_fd, stage.name)
        if manifest_exists:
            if not stage_exists:
                _fail("prepared worker deployment is incomplete; preserving existing state")
            manifest_bytes, manifest, manifest_owner = _read_manifest(parent_fd, manifest_path.name, manifest_path)
            _verify_staged(parent_fd, stage.name, stage, pins, manifest, manifest_owner)
            return manifest_bytes
        if stage_exists:
            empty_fd, _ = _stage_directory(parent_fd, stage.name, stage, allow_initial_mode=True)
            try:
                if os.listdir(empty_fd):
                    _fail("unpublished worker deployment stage is not empty; preserving existing state")
                os.fchmod(empty_fd, 0o700)
                os.fsync(empty_fd)
            finally:
                os.close(empty_fd)
        else:
            os.mkdir(stage.name, 0o700, dir_fd=parent_fd)
        stage_fd, stage_identity = _stage_directory(parent_fd, stage.name, stage)
        stage_owner = (stage_identity.st_uid, stage_identity.st_gid)
        manifest_entries = []
        try:
            for pin in pins:
                source = Path(str(pin["source"]))
                source_fd, source_before = _open_regular(source, int(pin["bytes"]))
                name = str(pin["name"])
                target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                                    0o600, dir_fd=stage_fd)
                digest = hashlib.sha256()
                count = 0
                try:
                    while True:
                        chunk = os.read(source_fd, CHUNK_BYTES)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > pin["bytes"]:
                            _fail("worker deployment source grew during copy")
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_fd, view)
                            if written <= 0:
                                _fail("worker deployment copy made no progress")
                            view = view[written:]
                    source_after = os.fstat(source_fd)
                    source_named = _stat_path(source)
                    if (count != pin["bytes"] or digest.hexdigest() != pin["sha256"] or
                            _version(source_after) != _version(source_before) or
                            _version(source_named) != _version(source_after)):
                        _fail("worker deployment source changed after preparation")
                    os.fsync(target_fd)
                    os.fchmod(target_fd, 0o444)
                finally:
                    os.close(target_fd)
                    os.close(source_fd)
                manifest_entries.append({"path": str(stage / name), "bytes": pin["bytes"], "sha256": pin["sha256"]})
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)

        document = {"schemaVersion": 1, "entries": manifest_entries}
        manifest_bytes = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        parsed = _strict_manifest_bytes(manifest_bytes)
        _verify_staged(parent_fd, stage.name, stage, pins, parsed, stage_owner)
        _publish_manifest(parent_fd, manifest_path.name, document)
        _, _, manifest_owner = _read_manifest(parent_fd, manifest_path.name, manifest_path)
        _verify_staged(parent_fd, stage.name, stage, pins, parsed, manifest_owner)
        return manifest_bytes
    finally:
        os.close(parent_fd)


def _exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    args = parser.parse_args(argv)
    try:
        materialize(args.manifest, args.stage, args.source)
    except (DeploymentError, OSError) as failure:
        print(f"module worker deployment refused: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
