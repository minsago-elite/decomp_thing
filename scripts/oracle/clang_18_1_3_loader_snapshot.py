"""Finite loader compile snapshots. Syntax evidence only, never execution authority.

The qualified launcher remains unavailable until independently approved immutable
host inputs exist. This module does not approve a caller-selected classpath.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

SOURCE_PATHS = (
    "oracle/clang/18.1.3/Clang1813AProfileLoaderSmoke.java",
    "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt",
    "src/main/kotlin/decompengine/oracle/core/OracleArtifacts.kt",
    "src/main/kotlin/decompengine/oracle/core/OracleJson.kt",
)
MAX_FILES = 64
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class SnapshotError(ValueError):
    pass


def _read(path, remaining):
    path = Path(path)
    # Reject links in every component, not only the final filename.
    absolute = path.absolute()
    for parent in (*reversed(absolute.parents), absolute):
        if parent.is_symlink():
            raise SnapshotError("snapshot input contains a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        limit = min(MAX_FILE_BYTES, remaining)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise SnapshotError("snapshot input is not a bounded regular file")
        chunks = []
        count = 0
        while True:
            chunk = os.read(fd, min(65536, limit - count + 1))
            if not chunk:
                break
            count += len(chunk)
            if count > limit:
                raise SnapshotError("snapshot input grew beyond bound")
            chunks.append(chunk)
        after = os.fstat(fd)
        keys = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if keys(before) != keys(after) or keys(after) != keys(path.stat(follow_symlinks=False)):
            raise SnapshotError("snapshot input changed during capture")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def prepare(root, output, classpath, expected_sources):
    """Capture the exact closed source list and every declared dependency JAR.

    expected_sources is independently obtained from the selected recipe by the
    caller. This operation binds bytes; it does not authenticate that caller.
    """
    root, output = Path(root), Path(output)
    if set(expected_sources) != set(SOURCE_PATHS):
        raise SnapshotError("source closure differs from the fixed loader closure")
    if not classpath or len(classpath) + len(SOURCE_PATHS) > MAX_FILES:
        raise SnapshotError("dependency closure count outside bounds")
    paths = [Path(p).absolute() for p in classpath]
    if len(set(paths)) != len(paths) or any(p.suffix != ".jar" for p in paths):
        raise SnapshotError("dependency closure must contain unique regular JAR files")
    # Capture all inputs before creating output. No partial output on input refusal.
    captured = []
    remaining = MAX_TOTAL_BYTES
    for relative in SOURCE_PATHS:
        raw = _read(root / relative, remaining)
        remaining -= len(raw)
        if hashlib.sha256(raw).hexdigest() != expected_sources[relative]:
            raise SnapshotError("loader source differs from selected recipe")
        captured.append(("sources/" + relative, raw))
    for index, path in enumerate(paths):
        raw = _read(path, remaining)
        remaining -= len(raw)
        captured.append((f"classpath/{index:03d}.jar", raw))
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    rows = {}
    for name, raw in captured:
        dest = output / name
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(raw)
        dest.chmod(0o400)
        rows[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {"formatVersion": 1, "qualification": "compile-only-unqualified", "files": rows}
    with (output / "manifest.json").open("xb") as stream:
        stream.write(_json(manifest))
    (output / "manifest.json").chmod(0o400)
    return manifest


def verify(output, expected_manifest_sha256):
    output = Path(output)
    raw = _read(output / "manifest.json", 65536)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise SnapshotError("snapshot manifest differs from captured binding")
    manifest = json.loads(raw)
    if set(manifest) != {"formatVersion", "qualification", "files"} or manifest["formatVersion"] != 1 or manifest["qualification"] != "compile-only-unqualified":
        raise SnapshotError("invalid snapshot manifest")
    rows = manifest["files"]
    if type(rows) is not dict or not len(SOURCE_PATHS) < len(rows) <= MAX_FILES:
        raise SnapshotError("invalid snapshot file count")
    sources = {"sources/" + p for p in SOURCE_PATHS}
    jars = {f"classpath/{i:03d}.jar" for i in range(len(rows) - len(sources))}
    if set(rows) != sources | jars:
        raise SnapshotError("snapshot closure changed")
    remaining = MAX_TOTAL_BYTES
    for name, row in rows.items():
        data = _read(output / name, remaining)
        remaining -= len(data)
        if row != {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
            raise SnapshotError("snapshot bytes changed")
    # No additional classes/resources/JARs may become part of this input closure.
    actual = set()
    pending = [output]
    nodes = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                nodes += 1
                if nodes > MAX_FILES * 8:
                    raise SnapshotError("snapshot inventory exceeds bound")
                path = Path(entry.path)
                if entry.is_symlink():
                    raise SnapshotError("snapshot contains a symlink")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    actual.add(path.relative_to(output).as_posix())
                else:
                    raise SnapshotError("snapshot contains a special node")
    if actual != set(rows) | {"manifest.json"}:
        raise SnapshotError("snapshot contains undeclared files")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--classpath", action="append", default=[])
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    if args.action == "prepare":
        # Import only for the checked-in recipe; no subprocess or acquisition.
        import provision_clang_18_1_3 as provision
        recipe = provision.recipe_identity()
        expected = {p: recipe[k] for k, path in provision.RECIPE_FILES.items()
                    for p in SOURCE_PATHS if path == args.root / p}
        manifest = prepare(args.root, args.output, args.classpath, expected)
        digest = hashlib.sha256(_json(manifest)).hexdigest()
        verify(args.output, digest)
        print(digest)
    else:
        if args.manifest_sha256 is None:
            parser.error("verify requires captured --manifest-sha256")
        verify(args.output, args.manifest_sha256)


if __name__ == "__main__":
    main()
