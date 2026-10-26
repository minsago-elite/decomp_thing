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


def _version(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _open_regular(path: Path, expected_size: int | None = None) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            _fail(f"deployment input is not a private regular file: {path}")
        if expected_size is not None and info.st_size != expected_size:
            _fail(f"deployment input size changed: {path}")
        if _version(path.lstat()) != _version(info):
            _fail(f"deployment input name changed while opening: {path}")
        return descriptor, info
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


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
            if _version(source.lstat()) != _version(after):
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


def _read_manifest(path: Path) -> tuple[bytes, dict[str, object]]:
    descriptor, before = _open_regular(path)
    try:
        if before.st_size > MAXIMUM_MANIFEST_BYTES:
            _fail("worker classpath manifest exceeds its fixed byte bound")
        if stat.S_IMODE(before.st_mode) != 0o444:
            _fail("worker classpath manifest is not read-only")
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
        if _version(after) != _version(before) or total != before.st_size or _version(path.lstat()) != _version(after):
            _fail("worker classpath manifest changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    document = _strict_manifest_bytes(raw)
    canonical = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if raw != canonical:
        _fail("worker classpath manifest is not the exact published encoding")
    return raw, document


def _stage_directory(stage: Path) -> tuple[int, os.stat_result]:
    descriptor = os.open(stage, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or _version(stage.lstat()) != _version(info):
        os.close(descriptor)
        _fail("worker deployment stage is not the expected real directory")
    return descriptor, info


def _verify_staged(stage: Path, pins: list[dict[str, object]], manifest: dict[str, object]) -> None:
    stage_fd, stage_before = _stage_directory(stage)
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


def _publish_manifest(path: Path, document: dict[str, object]) -> None:
    raw = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if len(raw) > MAXIMUM_MANIFEST_BYTES:
        _fail("worker classpath manifest exceeds its fixed byte bound")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
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
        os.link(temporary, path, follow_symlinks=False)
        os.chmod(path, 0o444, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    temporary.unlink()


def materialize(manifest_path: Path, stage: Path, sources: list[Path]) -> bytes:
    manifest_path = manifest_path.absolute()
    stage = stage.absolute()
    pins = _source_pins(sources)
    manifest_exists = os.path.lexists(manifest_path)
    stage_exists = os.path.lexists(stage)
    if manifest_exists:
        if not stage_exists:
            _fail("prepared worker deployment is incomplete; preserving existing state")
        manifest_bytes, manifest = _read_manifest(manifest_path)
        _verify_staged(stage, pins, manifest)
        return manifest_bytes
    if stage_exists:
        empty_fd, _ = _stage_directory(stage)
        try:
            if os.listdir(empty_fd):
                _fail("unpublished worker deployment stage is not empty; preserving existing state")
        finally:
            os.close(empty_fd)
    else:
        os.mkdir(stage, 0o700)
    stage_fd, _ = _stage_directory(stage)
    try:
        manifest_entries = []
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
                source_named = os.stat(source, follow_symlinks=False)
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
    except BaseException:
        os.close(stage_fd)
        raise
    else:
        os.close(stage_fd)

    document = {"schemaVersion": 1, "entries": manifest_entries}
    manifest_bytes = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    parsed = _strict_manifest_bytes(manifest_bytes)
    _verify_staged(stage, pins, parsed)
    _publish_manifest(manifest_path, document)
    return manifest_bytes


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
