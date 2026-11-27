"""Read a single-image docker save stream. Emit only a bounded descriptive report."""
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile

MIB = 1024 * 1024
EXPORT_LIMIT = 8 * 1024 * MIB
BLOB_LIMIT = 16 * MIB
CACHE_LIMIT = 96 * MIB
JSON_LIMIT = 256 * 1024
REPORT_LIMIT = 256 * 1024

LIB = "usr/lib/x86_64-linux-gnu"
DOC = "usr/share/doc"
NAMES = {
    ".", "etc", "usr", "usr/include", "usr/lib", LIB, "usr/share", DOC,
    "usr/include/mpc.h", "usr/include/mpf2mpfr.h", "usr/include/mpfr.h",
    *(f"{LIB}/{lib}" for lib in ("libmpc.so", "libmpc.so.3.3.1",
                                  "libmpfr.so", "libmpfr.so.6.2.2")),
}
for package in ("libmpc-dev", "libmpfr-dev"):
    NAMES.add(f"{DOC}/{package}")
    for notice in ("AUTHORS", "BUGS", "NEWS.gz", "README", "TODO", "changelog.gz",
                   "changelog.Debian.gz", "changelog.Debian.amd64.gz", "copyright"):
        NAMES.add(f"{DOC}/{package}/{notice}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode())


class LimitedReader:
    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit

    def read(self, size):
        data = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("export limit")
        return data


def selected_blobs(source):
    stream = LimitedReader(source, EXPORT_LIMIT)
    blobs = {}
    seen = set()
    total = 0
    with tarfile.open(fileobj=stream, mode="r|", bufsize=MIB) as archive:
        for index, member in enumerate(archive):
            if index >= 512 or member.size < 0:
                raise ValueError("export structure")
            name = member.name
            if not re.fullmatch(r"manifest\.json|blobs/sha256/[0-9a-f]{64}|"
                                r"[0-9a-f]{64}(?:\.json|/layer\.tar)", name):
                continue
            if name in seen or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                raise ValueError("ambiguous export")
            seen.add(name)
            if member.size > BLOB_LIMIT:
                continue  # Large base layers are streamed past without retention.
            total += member.size
            if total > CACHE_LIMIT:
                raise ValueError("cache limit")
            blobs[name] = archive.extractfile(member).read()
    # Consume the Docker producer through EOF, including tar padding.
    while stream.read(MIB):
        pass
    return blobs


def inventory(layer):
    rows = []
    other = 0
    with tarfile.open(fileobj=io.BytesIO(layer), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= 512 or not 0 <= member.size <= len(layer):
                raise ValueError("layer structure")
            name = member.name.removeprefix("./") or "."
            if name not in NAMES:
                other += 1
                continue
            row = {"name": name, "ordinal": index, "mode": member.mode,
                   "uid": member.uid, "gid": member.gid, "mtime": member.mtime,
                   "size": member.size, "paxSha256": canonical_hash(member.pax_headers)}
            if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                row.update(kind="file", sha256=sha(archive.extractfile(member).read()))
            elif member.issym() or member.islnk():
                row.update(kind="symlink" if member.issym() else "hardlink",
                           targetSha256=sha(member.linkname.encode("utf-8", "surrogateescape")))
            else:
                row["kind"] = "directory" if member.isdir() else "other"
            rows.append(row)
    return rows, other


def diagnose(source):
    blobs = selected_blobs(source)

    def metadata(name):
        data = blobs[name]
        if len(data) > JSON_LIMIT:
            raise ValueError("metadata limit")
        return json.loads(data)

    manifest, = metadata("manifest.json")
    config_name = manifest["Config"]
    config = metadata(config_name)
    layers = manifest["Layers"]
    diff_ids = config["rootfs"]["diff_ids"]
    if not (isinstance(layers, list) and isinstance(diff_ids, list)
            and len(layers) == len(diff_ids) == 9
            and all(re.fullmatch(r"sha256:[0-9a-f]{64}", d) for d in diff_ids)):
        raise ValueError("expected nine layer identities")
    layer = blobs[layers[-1]]
    if layer.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(layer)) as compressed:
            layer = compressed.read(BLOB_LIMIT + 1)
    if len(layer) > BLOB_LIMIT:
        raise ValueError("expanded layer limit")
    diff_id = "sha256:" + sha(layer)
    if diff_id != diff_ids[-1]:
        raise ValueError("final layer and config disagree")
    rows, other = inventory(layer)
    return {"schemaVersion": 1, "configBlobSha256": sha(blobs[config_name]),
            "historyCanonicalSha256": canonical_hash(config["history"]),
            "rootfsDiffIds": diff_ids, "uncompressedDiffId": diff_id,
            "uncompressedBytes": len(layer), "entries": rows, "unlistedEntries": other}


if __name__ == "__main__":
    try:
        output = json.dumps(diagnose(sys.stdin.buffer), allow_nan=False)
        if len(output) > REPORT_LIMIT:
            raise ValueError("report limit")
        print(output)
    except Exception:
        # Parsing errors can contain archive-controlled names or values.
        sys.exit("Final-layer diagnostic unavailable")
