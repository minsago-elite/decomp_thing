#!/usr/bin/env python3
"""Stage a runner's Gradle dependency cache as the archival image build's read-only seed (#2013).

The destination becomes the `gradle-seed` BuildKit build context. It contains a copy of
SOURCE/caches/modules-2 without lock files or gc.properties, which is the layout Gradle
documents for GRADLE_RO_DEP_CACHE. Every artifact under files-2.1 is stored in a directory
named after its SHA-1; the copy is refused if any content disagrees with that name.
Without a source cache the destination is left empty and the image build resolves cold.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"


class Refused(Exception):
    pass


def sha1(path):
    digest = hashlib.sha1()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def excluded(name):
    return name.endswith(".lock") or name == "gc.properties"


def copy_tree(source, target):
    files = artifacts = size = 0
    for directory, subdirectories, names in os.walk(source):
        relative = Path(directory).relative_to(source)
        (target / relative).mkdir(exist_ok=True)
        for name in sorted(subdirectories + names):
            entry = Path(directory) / name
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise Refused(f"refusing non-regular cache entry {relative / name}")
        for name in names:
            if excluded(name):
                continue
            entry = Path(directory) / name
            parts = (relative / name).parts
            if parts[0] == "files-2.1":
                # files-2.1/<group>/<module>/<version>/<sha1>/<file>
                if len(parts) != 6:
                    raise Refused(f"unexpected artifact cache path {relative / name}")
                try:
                    expected = int(parts[4], 16)
                except ValueError:
                    raise Refused(f"artifact directory is not a SHA-1: {relative}") from None
                if int(sha1(entry), 16) != expected:
                    raise Refused(f"SHA-1 mismatch for cached artifact {relative / name}")
                artifacts += 1
            shutil.copyfile(entry, target / relative / name, follow_symlinks=False)
            files += 1
            size += entry.stat().st_size
    return files, artifacts, size


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="restored Gradle user home; empty for a cold build")
    parser.add_argument("destination", type=Path, help="seed directory beneath build/")
    args = parser.parse_args()
    destination = args.destination.absolute()
    if BUILD.resolve() not in destination.resolve().parents:
        raise Refused(f"seed destination must be beneath {BUILD}")
    if destination.is_symlink():
        raise Refused("seed destination must not be a symbolic link")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    modules = Path(args.source) / "caches" / "modules-2" if args.source else None
    if modules is None or not modules.is_dir():
        print("archival Gradle seed: no runner dependency cache; the image build resolves cold")
        return
    if modules.is_symlink():
        raise Refused("runner dependency cache must not be a symbolic link")
    partial = destination / "modules-2.partial"
    try:
        partial.mkdir()
        files, artifacts, size = copy_tree(modules, partial)
        partial.rename(destination / "modules-2")
    except BaseException:
        # Leave no partial seed: a refused cache must not reach the image build.
        shutil.rmtree(destination, ignore_errors=True)
        raise
    print(f"archival Gradle seed: staged {files} files ({size} bytes), "
          f"{artifacts} artifacts matched their SHA-1 directories")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError) as error:
        print(f"archival Gradle seed refused: {error}", file=sys.stderr)
        sys.exit(1)
