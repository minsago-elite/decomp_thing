#!/usr/bin/env python3
"""Print the canonical content inventory digest used by StructureAllocationDiagnostic.

Run this in a separate process before and after each diagnostic JVM. The digest
is SHA-256 over UTF-8 rows sorted by Java String ordering:
`<lowercase file SHA-256><two spaces><root-relative path><LF>`.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"not a regular file: {path}")
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if identity_before != identity_after:
        raise RuntimeError(f"file changed while pinning: {path}")
    return digest.hexdigest()


def java_string_key(value: str) -> bytes:
    # Java String.compareTo orders UTF-16 code units, including supplementary
    # characters; Python's default order is by Unicode scalar value.
    return value.encode("utf-16-be", errors="surrogatepass")


def inventory_digest(root: Path) -> tuple[str, int]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"not a directory: {root}")

    files: list[tuple[str, str]] = []
    def fail_walk(error: OSError) -> None:
        raise RuntimeError(f"could not enumerate fixture inventory: {error}") from error

    for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail_walk):
        dirnames.sort(key=java_string_key)
        filenames.sort(key=java_string_key)
        for filename in filenames:
            path = Path(directory, filename)
            # Match Files.isRegularFile's default follow-links behavior for
            # file entries. Files.walk does not descend through symlink dirs.
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            files.append((relative, sha256_file(path)))

    files.sort(key=lambda item: java_string_key(item[0]))
    commitment = hashlib.sha256()
    for relative, content_sha256 in files:
        commitment.update(content_sha256.encode("ascii"))
        commitment.update(b"  ")
        commitment.update(relative.encode("utf-8", errors="strict"))
        commitment.update(b"\n")
    return commitment.hexdigest(), len(files)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} FIXTURE_ROOT", file=sys.stderr)
        return 2
    digest, count = inventory_digest(Path(sys.argv[1]))
    print(f"{digest}  {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
