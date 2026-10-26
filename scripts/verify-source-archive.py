#!/usr/bin/env python3
"""Independently verify a generated source archive's bytes against its own hash manifest.

Standard library only, and deliberately separate from the Kotlin ArchivalBundleVerifier: it reads
the ZIP in memory, refuses unsafe or duplicate members, requires ARCHIVE_MANIFEST.sha256 to cover
every other member exactly once, and checks every digest. Nothing is extracted, built or executed.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

MANIFEST = "ARCHIVE_MANIFEST.sha256"
MAXIMUM_ARCHIVE_BYTES = 256 * 1024 * 1024
MAXIMUM_MEMBERS = 100_000
MAXIMUM_MEMBER_BYTES = 128 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 1024 * 1024 * 1024


class VerificationError(Exception):
    pass


def member_name(name):
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\\" in name or name.endswith("/")
            or any(part in ("", ".", "..") for part in name.split("/")) or path.parts[0] == ".git"
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)):
        raise VerificationError(f"unsafe archive member name: {name!r}")
    return name


def verify(archive_path):
    if archive_path.is_symlink() or not archive_path.is_file():
        raise VerificationError("archive must be a regular file")
    if archive_path.stat().st_size > MAXIMUM_ARCHIVE_BYTES:
        raise VerificationError("archive exceeds its byte bound")
    raw = archive_path.read_bytes()
    files = {}
    folded = set()
    total = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if not members or len(members) > MAXIMUM_MEMBERS:
                raise VerificationError("archive member count is outside its bound")
            for info in members:
                name = member_name(info.filename)
                if name in files or name.casefold() in folded:
                    raise VerificationError(f"duplicate archive member: {name}")
                mode = (info.external_attr >> 16) & 0o170000
                if info.is_dir() or mode not in (0, stat.S_IFREG) or info.flag_bits & 0x1:
                    raise VerificationError(f"archive member is not a plain regular file: {name}")
                if info.file_size > MAXIMUM_MEMBER_BYTES:
                    raise VerificationError(f"archive member exceeds its bound: {name}")
                total += info.file_size
                if total > MAXIMUM_TOTAL_BYTES:
                    raise VerificationError("archive payload exceeds its total bound")
                content = archive.read(info)
                if len(content) != info.file_size:
                    raise VerificationError(f"archive member size differs: {name}")
                files[name] = content
                folded.add(name.casefold())
    except zipfile.BadZipFile as error:
        raise VerificationError(f"invalid ZIP archive: {error}") from error
    if MANIFEST not in files:
        raise VerificationError("archive hash manifest is missing")
    try:
        lines = files[MANIFEST].decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("archive hash manifest is not UTF-8") from error
    recorded = {}
    for line in lines:
        if not line:
            continue
        digest, separator, relative = line.partition("  ")
        if not separator or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise VerificationError("archive hash manifest contains an invalid line")
        member_name(relative)
        if relative == MANIFEST or relative in recorded:
            raise VerificationError(f"archive hash manifest repeats or references itself: {relative}")
        recorded[relative] = digest
    if set(recorded) != set(files) - {MANIFEST}:
        missing = sorted(set(files) - {MANIFEST} - set(recorded))
        extra = sorted(set(recorded) - set(files))
        raise VerificationError(f"archive hash manifest coverage differs: unlisted={missing[:5]} absent={extra[:5]}")
    for relative, digest in recorded.items():
        if hashlib.sha256(files[relative]).hexdigest() != digest:
            raise VerificationError(f"archive payload digest differs: {relative}")
    return {"archiveSha256": hashlib.sha256(raw).hexdigest(), "archiveBytes": len(raw),
            "manifestSha256": hashlib.sha256(files[MANIFEST]).hexdigest(), "files": dict(sorted(recorded.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    arguments = parser.parse_args()
    try:
        print(json.dumps(verify(arguments.archive), sort_keys=True))
    except (OSError, VerificationError) as error:
        print(f"source archive verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
