#!/usr/bin/env python3
"""Bounded, descriptor-relative excerpts from one admitted disposable CI tree."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import time


BUILD = Path(__file__).resolve().parent.parent / "build"
MAX_OUTPUT_BYTES = 262144
MAX_FILE_BYTES = 65536
MAX_LINES = 240
MAX_LINE_BYTES = 1024
MAX_ENTRIES = 4096
MAX_PATH_BYTES = 131072
MAX_DEPTH = 24
COLLECTION_SECONDS = 8
SUMMARY_RESERVE = 2048


class Refused(Exception):
    pass


def version(value):
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


@contextmanager
def admitted_root(root, expected):
    root = Path(root)
    if (root.parent != BUILD or re.fullmatch(r"decomp-archival-ci\.[A-Za-z0-9_-]{6,32}", root.name) is None
            or len(expected) != 2 or any(type(n) is not int or not 0 <= n < 1 << 64 for n in expected)):
        raise Refused("root-selection")
    parent = os.open(BUILD, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        selected = os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            held = os.fstat(descriptor)
            if (held.st_dev, held.st_ino) != tuple(expected) or version(held) != version(selected):
                raise Refused("root-identity")
            yield parent, descriptor, selected
            if (version(os.fstat(descriptor)) != version(selected)
                    or version(os.stat(root.name, dir_fd=parent, follow_symlinks=False)) != version(selected)):
                raise Refused("root-changed")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def selected_path(parts):
    return (parts[-2:] in (("reports", "build.log"), ("reports", "ghidra_stdout.log"),
                           ("reports", "ghidra_stderr.log"), ("reports", "ghidra_resource_usage.json"),
                           ("src", "main.c"))
            or (parts[-1].endswith(".log") and any(
                parts[i:i + 3] == ("reports", "build", "modules") for i in range(len(parts) - 3))))


def collect(root, expected, emit, clock=time.monotonic):
    deadline = clock() + COLLECTION_SECONDS
    written = entries = path_bytes = files = errors = 0

    def timely():
        if clock() >= deadline:
            raise Refused("collection-deadline")

    def write(record, *, summary=False):
        nonlocal written
        text = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        ceiling = MAX_OUTPUT_BYTES if summary else MAX_OUTPUT_BYTES - SUMMARY_RESERVE
        if written + len(text) > ceiling:
            raise Refused("diagnostic-byte-budget")
        timely()
        emit(text)
        written += len(text)
        timely()

    def names(descriptor, parts):
        nonlocal entries, path_bytes
        result = []
        with os.scandir(descriptor) as scan:
            while True:
                timely()
                entries += 1  # The advance which must observe EOF is charged too.
                if entries > MAX_ENTRIES:
                    raise Refused("diagnostic-entry-budget")
                try:
                    entry = next(scan)
                except StopIteration:
                    break
                name = entry.name
                relative = "/".join((*parts, name))
                length = len(os.fsencode(relative))
                path_bytes += length
                if length > 4096 or path_bytes > MAX_PATH_BYTES:
                    raise Refused("diagnostic-path-budget")
                result.append(name)
        timely()
        return sorted(result)

    def excerpt(descriptor, name, parts, original):
        nonlocal files
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
            raise Refused("diagnostic-not-unaliased-regular")
        header = {"kind": "file", "path": "/".join(parts), "uid": original.st_uid,
                  "gid": original.st_gid, "mode": stat.S_IMODE(original.st_mode),
                  "size": original.st_size, "truncated": False, "lines": []}
        if written + len(json.dumps(header, ensure_ascii=True, separators=(",", ":"))) + 1 > MAX_OUTPUT_BYTES - SUMMARY_RESERVE:
            raise Refused("diagnostic-byte-budget")
        timely()
        leaf = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        try:
            if (version(os.fstat(leaf)) != version(original)
                    or version(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != version(original)):
                raise Refused("diagnostic-changed-before-read")
            remaining = min(original.st_size, MAX_FILE_BYTES)
            chunks = []
            while remaining:
                timely()
                block = os.read(leaf, min(4096, remaining))
                timely()
                if not block:
                    raise Refused("diagnostic-truncated-during-read")
                chunks.append(block)
                remaining -= len(block)
            if original.st_size <= MAX_FILE_BYTES and os.read(leaf, 1):
                raise Refused("diagnostic-grew-during-read")
            timely()
            if (version(os.fstat(leaf)) != version(original)
                    or version(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != version(original)):
                raise Refused("diagnostic-changed-during-read")
        finally:
            os.close(leaf)
        raw = b"".join(chunks)
        lines = raw.split(b"\n", MAX_LINES)
        truncated = original.st_size > MAX_FILE_BYTES or len(lines) > MAX_LINES
        lines = lines[:MAX_LINES]
        truncated |= any(len(line) > MAX_LINE_BYTES for line in lines)
        previews = []
        for line in lines:
            encoded = line[:MAX_LINE_BYTES].decode("utf-8", "backslashreplace").encode("utf-8")
            truncated |= len(encoded) > MAX_LINE_BYTES
            previews.append(encoded[:MAX_LINE_BYTES].decode("utf-8", "ignore"))
        record = {"kind": "file", "path": "/".join(parts), "uid": original.st_uid,
                  "gid": original.st_gid, "mode": stat.S_IMODE(original.st_mode),
                  "size": original.st_size, "truncated": truncated,
                  "lines": previews}
        # JSON escaping and path bytes count toward the same aggregate ceiling.
        while record["lines"] and written + len(json.dumps(record, ensure_ascii=True, separators=(",", ":"))) + 1 > MAX_OUTPUT_BYTES - SUMMARY_RESERVE:
            record["lines"].pop()
            record["truncated"] = True
        write(record)
        files += 1

    def walk(descriptor, parts, device):
        nonlocal errors
        timely()
        original = os.fstat(descriptor)
        for name in names(descriptor, parts):
            child_parts = (*parts, name)
            try:
                timely()
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if metadata.st_dev != device:
                    raise Refused("diagnostic-foreign-device")
                if stat.S_ISDIR(metadata.st_mode):
                    if len(child_parts) > MAX_DEPTH:
                        raise Refused("diagnostic-depth-budget")
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                    try:
                        if version(os.fstat(child)) != version(metadata):
                            raise Refused("diagnostic-directory-changed")
                        walk(child, child_parts, device)
                        if version(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != version(metadata):
                            raise Refused("diagnostic-directory-changed")
                    finally:
                        os.close(child)
                elif selected_path(child_parts):
                    excerpt(descriptor, name, child_parts, metadata)
                elif not stat.S_ISREG(metadata.st_mode):
                    write({"kind": "omission", "path": "/".join(child_parts), "reason": "unselected-link-or-special-entry"})
            except (OSError, Refused) as failure:
                if isinstance(failure, Refused) and str(failure) in (
                        "collection-deadline", "diagnostic-entry-budget", "diagnostic-path-budget",
                        "diagnostic-depth-budget", "diagnostic-byte-budget"):
                    raise
                errors += 1
                write({"kind": "error", "path": "/".join(child_parts),
                       "reason": str(failure) if isinstance(failure, Refused) else "diagnostic-io-error",
                       "errno": failure.errno if isinstance(failure, OSError) else None})
        timely()
        if version(os.fstat(descriptor)) != version(original):
            raise Refused("diagnostic-directory-changed")

    try:
        timely()
        with admitted_root(root, expected) as (_, descriptor, original):
            write({"kind": "root", "name": Path(root).name, "device": original.st_dev,
                   "inode": original.st_ino, "uid": original.st_uid, "gid": original.st_gid,
                   "mode": stat.S_IMODE(original.st_mode)})
            output = os.open("output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                original_output = os.fstat(output)
                if original_output.st_dev != original.st_dev:
                    raise Refused("diagnostic-foreign-device")
                walk(output, ("output",), original.st_dev)
                if version(os.stat("output", dir_fd=descriptor, follow_symlinks=False)) != version(original_output):
                    raise Refused("diagnostic-output-changed")
            finally:
                os.close(output)
            if files == 0:
                raise Refused("diagnostic-files-missing")
    except (OSError, Refused) as failure:
        errors += 1
        # Reserve keeps the terminal omission explicit even after output exhaustion.
        record = {"kind": "error", "reason": str(failure) if isinstance(failure, Refused) else "diagnostic-io-error",
                  "errno": failure.errno if isinstance(failure, OSError) else None}
        text = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        if written + len(text) <= MAX_OUTPUT_BYTES - 512:
            emit(text)
            written += len(text)
    summary = {"kind": "summary", "status": "incomplete" if errors else "passed",
               "files": files, "entries": entries, "pathBytes": path_bytes, "bytesBeforeSummary": written}
    text = json.dumps(summary, separators=(",", ":")) + "\n"
    if written + len(text) > MAX_OUTPUT_BYTES:
        raise Refused("diagnostic-byte-budget")
    emit(text)
    return 2 if errors else 0


def main():
    # Bounds regular diagnostic-file writes too, including unexpected interpreter errors.
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    ceiling = min([MAX_OUTPUT_BYTES] + [n for n in (soft, hard) if n != resource.RLIM_INFINITY])
    resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("device", type=int)
    parser.add_argument("inode", type=int)
    parser.add_argument("--check-root", action="store_true")
    args = parser.parse_args()
    if args.check_root:
        try:
            with admitted_root(args.root, (args.device, args.inode)):
                return 0
        except (OSError, Refused):
            return 2
    return collect(args.root, (args.device, args.inode), sys.stdout.write)


if __name__ == "__main__":
    raise SystemExit(main())
