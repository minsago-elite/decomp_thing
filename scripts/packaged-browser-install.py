#!/usr/bin/env python3
"""Owned ZIP installation lifecycle for check-packaged-web-browser.mjs (stdlib only)."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

MARKER = ".packaged-browser-owned"
BYTE_RESERVE = 64 * 1024 * 1024
INODE_RESERVE = 1024


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def entries_and_budget(archive, destination):
    """Reject unsupported entries and check resources before creating the install."""
    entries = archive.infolist()
    names = set()
    paths = set()
    expanded_bytes = 0
    for entry in entries:
        name = entry.filename.rstrip("/")
        parts = PurePosixPath(name).parts
        if (not name or name.startswith("/") or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))):
            raise ValueError(f"Unsupported archive path: {entry.filename!r}")
        if name in names:
            raise ValueError(f"Duplicate archive path: {name}")
        names.add(name)
        mode = entry.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFDIR, stat.S_IFREG):
            raise ValueError(f"Unsupported archive entry type: {name}")
        paths.update(str(PurePosixPath(*parts[:length])) for length in range(1, len(parts) + 1))
        expanded_bytes += entry.file_size
    available = os.statvfs(destination)
    budget = {
        "expandedBytes": expanded_bytes,
        "requiredBytes": expanded_bytes + BYTE_RESERVE,
        "availableBytes": available.f_bavail * available.f_frsize,
        "requiredInodes": len(paths) + INODE_RESERVE,
        "availableInodes": available.f_favail,
    }
    if (budget["availableBytes"] < budget["requiredBytes"]
            or budget["availableInodes"] < budget["requiredInodes"]):
        raise RuntimeError("Insufficient extraction resources; choose --work-parent on a filesystem "
                           "with room for one installation. " + json.dumps(budget, sort_keys=True))
    return entries, budget


def prepare(archive_path, work, token):
    if work.is_symlink() or not work.is_dir() or any(work.iterdir()):
        raise ValueError("Preparation requires an empty, owned working directory")
    (work / MARKER).write_text(token, encoding="utf-8")
    with zipfile.ZipFile(archive_path) as archive:
        entries, budget = entries_and_budget(archive, work)
        unpack = work / "read only install"
        unpack.mkdir()
        for entry in entries:
            path = unpack.joinpath(*PurePosixPath(entry.filename).parts)
            if entry.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                # Preserve all archive execute bits, including nested native tools.
                path.chmod(0o444 | ((entry.external_attr >> 16) & 0o111))
        for directory in sorted((p for p in unpack.rglob("*") if p.is_dir()),
                                key=lambda p: len(p.parts), reverse=True):
            directory.chmod(0o555)
        unpack.chmod(0o555)
    applications = list(unpack.iterdir())
    if len(applications) != 1 or not applications[0].is_dir():
        raise ValueError("Expected one application directory in distribution ZIP")
    app = applications[0]
    jars = list((app / "lib").glob("llm-bin-patch-*.jar"))
    if len(jars) != 1:
        raise ValueError("Expected one application JAR")
    with zipfile.ZipFile(jars[0]) as jar:
        manifest = json.loads(jar.read("decompengine/web/ui/asset-manifest.json"))
    return {"app": str(app), "manifest": manifest, "jar": jars[0].name,
            "jarSha256": digest(jars[0]), "resourceBudget": budget}


def cleanup(work, token):
    """Remove only the unique directory initialized by this invocation."""
    marker = work / MARKER
    if work.is_symlink() or not work.is_dir() or marker.is_symlink():
        raise ValueError("Refusing cleanup without owned working directory")
    if marker.read_text(encoding="utf-8") != token:
        raise ValueError("Refusing cleanup: ownership token does not match")
    for directory, children, _files in os.walk(work, topdown=True, followlinks=False):
        Path(directory).chmod(0o700)
        for name in children:
            child = Path(directory) / name
            if not child.is_symlink():
                child.chmod(0o700)
    shutil.rmtree(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "cleanup"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--owner-token", required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if not args.work.is_absolute() or not args.owner_token:
        parser.error("An absolute --work and nonempty --owner-token are required")
    if args.action == "prepare":
        if args.archive is None:
            parser.error("prepare requires --archive")
        print(json.dumps(prepare(args.archive, args.work, args.owner_token)))
    else:
        cleanup(args.work, args.owner_token)


if __name__ == "__main__":
    main()
