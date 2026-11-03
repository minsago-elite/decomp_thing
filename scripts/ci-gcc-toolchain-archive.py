#!/usr/bin/env python3
"""Bounded, non-extracting diagnostics for the paired BuildKit Docker/OCI exports."""
from __future__ import annotations

import hashlib
import gzip
import json
import pathlib
import os
import stat
import sys
import tarfile


def refuse(message: str) -> None:
    raise SystemExit(f"archive refusal: {message}")


def read_member(tf: tarfile.TarFile, name: str, limit: int) -> bytes:
    matches = [m for m in tf.getmembers() if m.name == name]
    if len(matches) != 1 or not matches[0].isfile() or matches[0].size > limit:
        refuse(f"missing, duplicate, nonregular, or oversized member {name}")
    stream = tf.extractfile(matches[0])
    if stream is None:
        refuse(f"unreadable member {name}")
    value = stream.read(limit + 1)
    if len(value) != matches[0].size or len(value) > limit:
        refuse(f"truncated member {name}")
    return value


def member_stream(tf: tarfile.TarFile, descriptor: dict[str, object], cap: int):
    name = "blobs/sha256/" + str(descriptor["digest"]).removeprefix("sha256:")
    rows = [m for m in tf.getmembers() if m.name == name]
    if len(rows) != 1 or not rows[0].isfile() or rows[0].size != descriptor.get("size") or rows[0].size > cap:
        refuse(f"OCI blob descriptor mismatch: {name}")
    source = tf.extractfile(rows[0])
    if source is None:
        refuse(f"unreadable OCI blob: {name}")
    return source, name


def digest_stream(stream) -> tuple[str, int]:
    h=hashlib.sha256(); count=0
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(chunk); count += len(chunk)
    return "sha256:" + h.hexdigest(), count


def safe_name(name: str) -> None:
    p = pathlib.PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        refuse(f"unsafe tar member path {name!r}")


def validate_archive_members(tf: tarfile.TarFile, limit: int) -> None:
    count=0
    for member in tf:
        count += 1
        if count > limit:
            refuse("archive member-count budget exceeded")
        safe_name(member.name)


def validate_workers(path: pathlib.Path) -> None:
    data = json.loads(path.read_text())
    rows = data if isinstance(data, list) else data.get("workers", data.get("Workers", []))
    if len(rows) != 1:
        refuse("BuildKit must expose exactly one worker")
    worker = rows[0]
    labels = worker.get("labels", worker.get("Labels", {}))
    platforms = worker.get("platforms", worker.get("Platforms", []))
    snapshotter = worker.get("snapshotter", labels.get("org.mobyproject.buildkit.worker.snapshotter"))
    if snapshotter != "native":
        refuse("BuildKit worker snapshotter is not native")
    admitted = False
    for platform in platforms:
        if platform == "linux/amd64" or (isinstance(platform, dict) and
                platform.get("OS", platform.get("os")) == "linux" and
                platform.get("Architecture", platform.get("architecture")) == "amd64"):
            admitted = True
    if not admitted:
        refuse("BuildKit worker does not admit linux/amd64")
    for key, value in labels.items():
        lowered = str(key).lower() + "=" + str(value).lower()
        if "sandbox" in lowered and ("no-process" in lowered or "disabled" in lowered or value is True):
            refuse("BuildKit worker reports process sandbox disabled")


def validate_info(path: pathlib.Path) -> None:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        refuse("BuildKit daemon info must be structured JSON")
    text = json.dumps(data, sort_keys=True).lower()
    if "v0.20.2" not in text or "97437fdd7e32f29bb80288d800cd4ffcb34e1c15" not in text:
        refuse("BuildKit daemon version/revision mismatch")


def validate_docker_info(info_path: pathlib.Path, expected_root: pathlib.Path, socket_path: pathlib.Path) -> None:
    data=json.loads(info_path.read_text())
    if data.get("Driver") != "overlay2":
        refuse("rootless Docker storage driver is not overlay2")
    if pathlib.Path(data.get("DockerRootDir", "/")).resolve() != expected_root.resolve():
        refuse("rootless Docker data root mismatch")
    try:
        mode=socket_path.lstat().st_mode
    except OSError:
        refuse("owned rootless Unix socket is missing")
    if not stat.S_ISSOCK(mode):
        refuse("rootless Docker endpoint is not an owned Unix socket")
    if socket_path.stat().st_uid != os.getuid():
        refuse("rootless Docker socket owner mismatch")
    if socket_path.parent.resolve() != expected_root.resolve().parents[1]:
        refuse("rootless Docker socket escaped owned job root")


def bounded_stream(path: pathlib.Path, cap: int, source_path: pathlib.Path | None = None) -> None:
    used=0; overflow=False
    source = source_path.open("rb") if source_path else sys.stdin.buffer
    try:
        with path.open("wb") as out:
            while True:
                block=source.read(65536)
                if not block:
                    break
                amount=max(0, min(len(block), cap-used))
                if amount:
                    out.write(block[:amount]); out.flush(); used += amount
                if amount < len(block):
                    overflow=True
    finally:
        if source_path:
            source.close()
    if overflow:
        path.with_suffix(path.suffix + ".truncated").write_text("log exceeded byte budget; stream drained, job refused\n")
        refuse("bounded log writer exceeded its byte budget")


def tar_census(layer_path: pathlib.Path) -> list[dict[str, object]]:
    rows = []
    census_bytes = 0
    try:
        with tarfile.open(layer_path, mode="r:") as tf:
            for ordinal, m in enumerate(tf):
                if ordinal >= 100000:
                    refuse("final-layer member-count budget exceeded")
                safe_name(m.name)
                payload_sha = None
                if m.isfile():
                    src = tf.extractfile(m)
                    if src is None:
                        refuse("unreadable regular layer entry")
                    h = hashlib.sha256()
                    count = 0
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        count += len(chunk)
                        h.update(chunk)
                    if count != m.size:
                        refuse("truncated layer payload")
                    payload_sha = h.hexdigest()
                pax = dict(m.pax_headers)
                pax_size = len(json.dumps(pax, ensure_ascii=True, sort_keys=True).encode())
                if pax_size > 65536:
                    refuse("final-layer PAX/xattr metadata entry exceeds 64 KiB")
                row = {"ordinal": ordinal, "name": m.name, "type": m.type.decode("ascii", "replace"),
                    "linkname": m.linkname, "mode": m.mode, "uid": m.uid, "gid": m.gid,
                    "size": m.size, "mtime": m.mtime, "paxHeaders": pax, "payloadSha256": payload_sha}
                census_bytes += len(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode())
                if census_bytes > 67108864:
                    refuse("final-layer census exceeds 64 MiB artifact budget")
                rows.append(row)
    except (tarfile.TarError, OSError) as exc:
        refuse(f"invalid layer tar: {exc}")
    return rows


def inspect(docker_archive: pathlib.Path, oci_archive: pathlib.Path, out: pathlib.Path, cap: int) -> None:
    for path in (docker_archive, oci_archive):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > cap:
            refuse(f"missing, linked, or over-limit archive {path.name}")
    with tarfile.open(docker_archive, "r:") as tf:
        validate_archive_members(tf, 200000)
        manifest_raw = read_member(tf, "manifest.json", 1024 * 1024)
        manifest = json.loads(manifest_raw)
        if len(manifest) != 1:
            refuse("Docker archive must contain exactly one image")
        row = manifest[0]
        config_raw = read_member(tf, row["Config"], 16 * 1024 * 1024)
        config = json.loads(config_raw)
        if not isinstance(config.get("config"), dict):
            refuse("Docker image config lacks the Config object")
        config_object_sha = hashlib.sha256(json.dumps(config.get("config"), ensure_ascii=True,
            separators=(",", ":"), sort_keys=True).encode()).hexdigest()
        layers = row["Layers"]
        if len(layers) != 9 or len(config.get("rootfs", {}).get("diff_ids", [])) != 9:
            refuse("expected exactly nine ordered layer streams and diff IDs")
        inventory = []
        final_layer_path = out / "final-layer.tar"
        for i, name in enumerate(layers):
            matches = [m for m in tf.getmembers() if m.name == name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > cap:
                refuse(f"missing, duplicate, nonregular, or oversized layer {name}")
            source = tf.extractfile(matches[0])
            if source is None:
                refuse(f"unreadable layer {name}")
            h = hashlib.sha256()
            count = 0
            destination = final_layer_path.open("wb") if i == 8 else None
            try:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    h.update(chunk)
                    if destination is not None:
                        destination.write(chunk)
                if destination is not None:
                    destination.flush()
            finally:
                if destination is not None:
                    destination.close()
            if count != matches[0].size:
                refuse(f"truncated layer {name}")
            if i == 8 and count < 10240:
                refuse("final layer is truncated before tar end blocks")
            digest = "sha256:" + h.hexdigest()
            expected = config["rootfs"]["diff_ids"][i]
            if digest != expected:
                refuse(f"layer {i} bytes disagree with config diff ID")
            inventory.append({"ordinal": i, "path": name, "diffId": digest, "bytes": count})
    (out / "image-config.json").write_bytes(config_raw)
    (out / "docker-manifest.json").write_bytes(manifest_raw)
    (out / "ordered-layers.json").write_text(json.dumps(inventory, indent=2) + "\n")
    (out / "final-layer-census.json").write_text(json.dumps(tar_census(final_layer_path), indent=2) + "\n")

    with tarfile.open(oci_archive, "r:") as tf:
        validate_archive_members(tf, 200000)
        index_raw = read_member(tf, "index.json", 1024 * 1024)
        index = json.loads(index_raw)
        (out / "oci-manifests").mkdir(mode=0o700, exist_ok=True)
        (out / "oci-index.json").write_bytes(index_raw)
        manifests = []
        attestations = []
        for desc in index.get("manifests", []):
            name = "blobs/sha256/" + desc["digest"].removeprefix("sha256:")
            raw = read_member(tf, name, 64 * 1024 * 1024)
            if len(raw) != desc.get("size") or "sha256:" + hashlib.sha256(raw).hexdigest() != desc.get("digest"):
                refuse("OCI manifest descriptor digest/size mismatch")
            obj = json.loads(raw)
            (out / "oci-manifests" / (desc["digest"].removeprefix("sha256:") + ".json")).write_bytes(raw)
            annotations = desc.get("annotations", {})
            manifests.append({"descriptor": desc, "manifest": obj})
            if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
                attestations.append({"descriptor": desc, "manifest": obj})
        runtime = [item for item in manifests if not item["descriptor"].get("annotations", {}).get("vnd.docker.reference.type")]
        if len(runtime) != 1:
            refuse("OCI archive must contain exactly one runtime manifest")
        config_sha = hashlib.sha256(config_raw).hexdigest()
        joins = []
        for item in runtime:
            manifest = item["manifest"]
            cdesc = manifest.get("config", {})
            if cdesc.get("digest") == "sha256:" + config_sha:
                csource, _ = member_stream(tf, cdesc, 16 * 1024 * 1024)
                cdigest, _ = digest_stream(csource)
                if cdigest != cdesc.get("digest"):
                    refuse("OCI runtime config bytes disagree with descriptor")
                oci_layers = manifest.get("layers", [])
                if len(oci_layers) != len(inventory):
                    refuse("OCI runtime layer count differs from Docker archive")
                for i, desc in enumerate(oci_layers):
                    raw, _ = member_stream(tf, desc, cap)
                    raw_digest, _ = digest_stream(raw)
                    if raw_digest != desc.get("digest"):
                        refuse("OCI layer bytes disagree with descriptor")
                    raw, _ = member_stream(tf, desc, cap)
                    if "gzip" in str(desc.get("mediaType", "")):
                        raw = gzip.GzipFile(fileobj=raw)
                    uncompressed_digest, _ = digest_stream(raw)
                    if uncompressed_digest != inventory[i]["diffId"]:
                        refuse(f"OCI layer {i} does not join Docker archive diff ID")
                target = item["descriptor"]["digest"]
                for att in attestations:
                    annotation = att["descriptor"].get("annotations", {}).get("vnd.docker.reference.digest")
                    if annotation == target:
                        subject = att["manifest"].get("subject", {})
                        if subject.get("digest") != target:
                            refuse("OCI attestation manifest subject does not match runtime manifest")
                        statements=[]
                        (out / "provenance-statements").mkdir(mode=0o700, exist_ok=True)
                        for layer in att["manifest"].get("layers", []):
                            payload, _ = member_stream(tf, layer, 16 * 1024 * 1024)
                            payload_digest, _ = digest_stream(payload)
                            if payload_digest != layer.get("digest"):
                                refuse("provenance statement bytes disagree with descriptor")
                            payload, _ = member_stream(tf, layer, 16 * 1024 * 1024)
                            statement_raw=payload.read()
                            statement=json.loads(statement_raw)
                            if not str(statement.get("_type", "")).startswith("https://in-toto.io/Statement/") or \
                               not str(statement.get("predicateType", "")).startswith("https://slsa.dev/provenance/"):
                                refuse("OCI attestation payload is not an in-toto SLSA provenance statement")
                            subjects=statement.get("subject", [])
                            if not any(s.get("digest", {}).get("sha256") == target.removeprefix("sha256:") for s in subjects):
                                refuse("in-toto provenance statement subject does not match runtime manifest")
                            (out / "provenance-statements" / (layer["digest"].removeprefix("sha256:") + ".json")).write_bytes(statement_raw)
                            statements.append(statement)
                        if not statements:
                            refuse("OCI attestation has no provenance statement")
                        (out / "provenance-statements.json").write_text(json.dumps(statements, indent=2) + "\n")
                        joins.append({"runtimeManifestDigest": target, "runtimeConfigDigest": cdesc["digest"],
                            "attestationManifestDigest": att["descriptor"]["digest"], "statementSubjectsJoined": True})
        if not joins:
            refuse("OCI provenance attestation does not join runtime manifest/config")
    (out / "provenance-joins.json").write_text(json.dumps(joins, indent=2) + "\n")
    def file_hash(path: pathlib.Path) -> str:
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    (out / "archive-digests.json").write_text(json.dumps({
        "dockerArchiveSha256": file_hash(docker_archive),
        "ociArchiveSha256": file_hash(oci_archive),
        "rawImageConfigSha256": config_sha,
        "configObjectCanonicalSha256": config_object_sha,
    }, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "workers":
        validate_workers(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "info":
        validate_info(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 5 and sys.argv[1] == "docker-info":
        validate_docker_info(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]))
    elif len(sys.argv) == 4 and sys.argv[1] == "stream":
        bounded_stream(pathlib.Path(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) == 5 and sys.argv[1] == "stream-file":
        bounded_stream(pathlib.Path(sys.argv[3]), int(sys.argv[4]), pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 6 and sys.argv[1] == "inspect":
        inspect(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), int(sys.argv[5]))
    else:
        refuse("usage: ci-gcc-toolchain-archive.py {inspect DOCKER-TAR OCI-TAR EVIDENCE CAP|workers JSON|info JSON|docker-info JSON ROOT SOCKET}")
