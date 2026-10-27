#!/usr/bin/env python3
"""Capture a new, UNAPPROVED Python-compatibility executor generation; no targets.

The external controller owns one transient service/cgroup. Its worker may build
the fixed GCC runtime recipe, but never acquires or invokes a Clang artifact.
Neither a daemon response nor a matching historical digest approves a profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time

SCHEMA = "llvm-python-reference-runtime-capture-v1"
MAX_JSON = 2 * 1024 * 1024
MAX_STREAM = 1024 * 1024
MAX_IMAGE = 4 * 1024 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
OVERALL_SECONDS = 1500
BUILD_SECONDS = 1000
CONTROL_SECONDS = 15
DOCKER_ARCHIVE = "803d433f226db4776e1768fd319fc6c6e4935a456acf84fcc0080818b854bc8f"
EXTRAS_ARCHIVE = "15a5cb81f2c5cf15ea21427f2e8241eac0deb2221175f993b5e76926e705ec6a"
CLIENT_SHA = "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13"
CLIENT_BYTES = 42677472
CLIENT_VERSION = b"Docker version 29.7.2, build a7dcaa6\n"
ROOTLESSKIT_SHA = "98f07e783dd6b3cd236c7865d1dce7937e645ec74a0fe2971725449af074f466"
RECIPE = "oracle/gcc/16.2.0/build-toolchain.Dockerfile"
LOCK = "oracle/gcc/16.2.0/toolchain-reproduction.json"
RECORD = "oracle/gcc/16.2.0/build-record.json"
SOURCE_PINS = {
    RECIPE: "8b0af79ba3426f49ba599eb0c7eea433c62ac5bb6ab5e7797f7d09d978f43543",
    LOCK: "5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de",
    RECORD: "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637",
    "oracle/gcc/16.2.0/source-lock.json": "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
WORKFLOW = ".github/workflows/llvm-reference-runtime-capture.yml"
SCRIPT = "oracle/llvm/capture_reference_runtime.py"
INSPECT_WORKFLOW = ".github/workflows/llvm-oracle-model.yml"
INSPECT_SECONDS = 80  # Outer workflow timeout:88s TERM +2s KILL, at most90s.
INSPECT_READ_BUDGET = 128 * 1024 * 1024
PUBLIC_ENV = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
              "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_EVENT_NAME",
              "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")


class CaptureFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise CaptureFailure(code)


def strict_json(raw: bytes):
    require(len(raw) <= MAX_JSON, "JSON_LIMIT")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_FIELD")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(CaptureFailure("NONFINITE_JSON")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise CaptureFailure("MALFORMED_JSON") from error


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def text(value, code, maximum=4096, empty=False):
    require(type(value) is str and (empty or bool(value)) and len(value) <= maximum
            and not any(ord(c) < 32 for c in value), code)
    return value


def file_pin(path: Path, maximum=MAX_FILE):
    end = time.monotonic() + 60
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_size <= maximum, "FILE_KIND_OR_LIMIT")
        digest = hashlib.sha256()
        count = 0
        while True:
            require(time.monotonic() < end, "FILE_HASH_DEADLINE")
            block = os.read(fd, min(65536, maximum - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= maximum, "FILE_GROWTH_LIMIT")
            digest.update(block)
        last = os.fstat(fd)
        named = path.lstat()
        require(time.monotonic() < end, "FILE_HASH_DEADLINE")
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(count == first.st_size and key(first) == key(last) == key(named), "FILE_CHANGED")
        return {"path": str(path), "bytes": count, "sha256": digest.hexdigest(),
                "device": first.st_dev, "inode": first.st_ino, "mode": stat.S_IMODE(first.st_mode)}
    finally:
        os.close(fd)


def save(path: Path, value):
    raw = canonical(value)
    require(len(raw) <= MAX_JSON, "RECEIPT_LIMIT")
    pending = path.with_name(path.name + ".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    # Publish complete bytes without replacing any earlier generation.
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()


def command(argv, environment, directory, *, seconds=CONTROL_SECONDS, limit=MAX_STREAM,
            success_codes=(0,), stdout_path=None):
    """One child, bounded pipes and time. Children remain inside the service cgroup."""
    end = time.monotonic() + seconds
    process = subprocess.Popen(argv, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    sink = None
    sink_identity = None
    count = 0
    streamed_digest = hashlib.sha256()
    stdout_eof = False
    failure = None
    def streamed_stdout():
        if sink is None or sink_identity is None:
            return None
        verified = False
        try:
            current, named = os.fstat(sink), stdout_path.lstat()
            stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            verified = ((current.st_dev, current.st_ino, current.st_mode) ==
                        (sink_identity.st_dev, sink_identity.st_ino, sink_identity.st_mode)
                        and current.st_size == count and stable(current) == stable(named))
        except OSError:
            pass
        return {"path": str(stdout_path), "bytes": count, "sha256": streamed_digest.hexdigest(),
                "device": sink_identity.st_dev, "inode": sink_identity.st_ino,
                "mode": stat.S_IMODE(sink_identity.st_mode),
                "identityVerified": verified, "eofObserved": stdout_eof}
    try:
        if stdout_path is not None:
            sink = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            sink_identity = os.fstat(sink)
            require(stat.S_ISREG(sink_identity.st_mode) and sink_identity.st_size == 0, "COMMAND_STREAM_FILE")
        with selectors.DefaultSelector() as selector:
            for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            while selector.get_map():
                require(time.monotonic() < end, "COMMAND_DEADLINE")
                for key, _ in selector.select(min(0.1, max(0, end - time.monotonic()))):
                    bound = MAX_IMAGE if sink is not None and key.data == "stdout" else limit
                    used = count if sink is not None and key.data == "stdout" else len(streams[key.data])
                    block = os.read(key.fileobj.fileno(), min(8192, bound - used + 1))
                    if not block:
                        if key.data == "stdout":
                            stdout_eof = True
                        selector.unregister(key.fileobj)
                    else:
                        require(used + len(block) <= bound, "COMMAND_OUTPUT_LIMIT")
                        if sink is not None and key.data == "stdout":
                            position = 0
                            while position < len(block):
                                written = os.write(sink, memoryview(block)[position:])
                                require(written > 0, "COMMAND_STREAM_WRITE")
                                streamed_digest.update(block[position:position + written])
                                count += written
                                position += written
                        else:
                            streams[key.data].extend(block)
            require(time.monotonic() < end, "COMMAND_DEADLINE")
            code = process.wait(timeout=max(0.001, end - time.monotonic()))
            require(time.monotonic() < end, "COMMAND_DEADLINE")
        require(code in success_codes, "COMMAND_EXIT")
        stream = streamed_stdout()
        require(stream is None or stream["identityVerified"], "COMMAND_STREAM_CHANGED")
        return bytes(streams["stdout"]), bytes(streams["stderr"]), code, stream
    except (subprocess.TimeoutExpired, CaptureFailure, OSError) as error:
        failure = error if isinstance(error, CaptureFailure) else CaptureFailure(
            "COMMAND_DEADLINE" if isinstance(error, subprocess.TimeoutExpired) else "COMMAND_IO")
        failure.stdout = bytes(streams["stdout"])
        failure.stderr = bytes(streams["stderr"])
        failure.exit_code = process.returncode
        failure.stdout_stream = streamed_stdout()
        raise failure
    finally:
        # This is our unreleased Popen child, not a PID supplied by a file/daemon.
        if process.poll() is None:
            process.kill()
        try:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if failure is None:
                    raise CaptureFailure("COMMAND_REAP_DEADLINE")
        finally:
            process.stdout.close()
            process.stderr.close()
            if sink is not None:
                os.close(sink)


def control_command(client, env, root, raw, label, args, seconds=CONTROL_SECONDS,
                    limit=MAX_STREAM, stdout_path=None):
    """Retain actual pipe bytes or the actual streamed file, never an empty stand-in."""
    out = err = b""
    exit_code = failure_code = stream = None
    try:
        out, err, exit_code, stream = command([str(client), *args], env, root, seconds=seconds,
                                             limit=limit, stdout_path=stdout_path)
    except (CaptureFailure, OSError) as failure:
        out, err = getattr(failure, "stdout", b""), getattr(failure, "stderr", b"")
        failure_code, exit_code = getattr(failure, "code", "COMMAND_IO"), getattr(failure, "exit_code", None)
        stream = getattr(failure, "stdout_stream", None)
        raise
    finally:
        if stdout_path is None:
            (root / "raw" / (label + ".stdout")).write_bytes(out)
            output = {"stdoutCapture": "memory", "stdoutSha256": hashlib.sha256(out).hexdigest(),
                      "stdoutBytes": len(out)}
        else:
            output = {"stdoutCapture": "streamed-file", "stdoutArtifact": stream,
                      "stdoutSha256": stream["sha256"] if stream else None,
                      "stdoutBytes": stream["bytes"] if stream else None}
        (root / "raw" / (label + ".stderr")).write_bytes(err)
        raw[label] = {"argv": [str(client), *args], **output,
                      "stderrSha256": hashlib.sha256(err).hexdigest(), "stderrBytes": len(err),
                      "failureCode": failure_code, "exitCode": exit_code}
        save(root / "raw" / (label + ".json"), raw[label])
    return out


def components_hash(components):
    require(type(components) is list and 0 < len(components) <= 64, "ENGINE_COMPONENTS")
    normalized = []
    names = set()
    for component in components:
        require(type(component) is dict and type(component.get("Details")) is dict
                and len(component["Details"]) <= 64, "ENGINE_COMPONENT")
        name = text(component.get("Name"), "COMPONENT_NAME", 256)
        require(name not in names, "DUPLICATE_COMPONENT")
        names.add(name)
        details = {}
        for key, value in component["Details"].items():
            text(key, "COMPONENT_KEY", 256)
            text(value, "COMPONENT_VALUE", 4096, empty=True)
            if (name, key) not in {("Engine", "KernelVersion"), ("rootlesskit", "StateDir")}:
                details[key] = value
        normalized.append({"name": name, "version": text(component.get("Version"), "COMPONENT_VERSION", 256),
                           "details": details})
    return hashlib.sha256(canonical(sorted(normalized, key=lambda row: row["name"]))).hexdigest()


def engine_tuple(server, info, host_kernel):
    require(type(server) is dict and type(info) is list and len(info) == 6, "ENGINE_RECORD")
    security, cgroups, driver, storage, volumes, runtimes = info
    require(type(security) is list and len(security) <= 64 and all(type(x) is str for x in security), "SECURITY_RECORD")
    require({"name=cgroupns", "name=rootless", "name=seccomp,profile=builtin"}.issubset(security), "MISSING_SECURITY")
    require(str(cgroups) == "2" and driver == "systemd" and storage == "overlay2", "MISSING_RESOURCE_CAPABILITY")
    require(type(volumes) is list and len(volumes) <= 64 and "local" in volumes
            and all(type(v) is str for v in volumes) and type(runtimes) is dict and len(runtimes) <= 64
            and "runc" in runtimes, "RUNTIME_RECORD")
    require(server.get("Os") == "linux" and server.get("Arch") == "amd64", "ENGINE_PLATFORM")
    require(server.get("Version") == "29.7.2" and server.get("GitCommit") == "6a43e3d"
            and server.get("ApiVersion") == "1.55", "DISTRIBUTION_IDENTITY")
    require(server.get("KernelVersion") == host_kernel, "ENGINE_HOST_KERNEL")
    component_hash = components_hash(server.get("Components"))
    engines = [row for row in server["Components"] if row["Name"] == "Engine"]
    require(len(engines) == 1 and engines[0]["Details"].get("KernelVersion") == host_kernel, "ENGINE_COMPONENT_KERNEL")
    runtime_components = [row for row in server["Components"] if row["Name"] == "runc"]
    require(len(runtime_components) == 1, "RUNC_COMPONENT")
    runtime = runtime_components[0]
    require(type(server.get("Platform")) is dict and type(runtime.get("Details")) is dict, "ENGINE_RECORD")
    record = runtimes["runc"]
    require(type(record) is dict and type(record.get("status")) is dict, "RUNC_STATUS")
    features = text(record["status"].get("org.opencontainers.runtime-spec.features"), "RUNC_FEATURES", 65536)
    strict_json(features.encode())
    return {"product": text(server.get("Platform", {}).get("Name"), "ENGINE_PRODUCT"),
            "serverVersion": server["Version"], "serverCommit": server["GitCommit"], "apiVersion": server["ApiVersion"],
            "operatingSystem": "linux", "architecture": "amd64", "kernelVersion": text(host_kernel, "KERNEL"),
            "componentsSha256": component_hash, "cgroupVersion": 2,
            "cgroupDriver": driver, "storageDriver": storage, "securityOptions": sorted(security),
            "containerRuntime": "runc", "containerRuntimePath": text(record.get("path"), "RUNC_PATH"),
            "containerRuntimeVersion": text(runtime.get("Version"), "RUNC_VERSION", 256),
            "containerRuntimeCommit": text(runtime.get("Details", {}).get("GitCommit"), "RUNC_COMMIT", 256),
            "containerRuntimeFeaturesSha256": hashlib.sha256(features.encode()).hexdigest(), "volumePlugin": "local"}


def image_tuple(inspected, lock):
    require(type(inspected) is list and len(inspected) == 1 and type(inspected[0]) is dict, "IMAGE_RECORD")
    image = inspected[0]
    require(DIGEST.fullmatch(str(image.get("Id"))) and image.get("Os") == "linux"
            and image.get("Architecture") == "amd64", "IMAGE_IDENTITY")
    config = image.get("Config")
    require(type(config) is dict and config.get("Volumes") in (None, {}), "IMPLICIT_IMAGE_VOLUMES")
    environment = config.get("Env") or []
    require(type(environment) is list and len(environment) <= 128, "IMAGE_ENVIRONMENT")
    for entry in environment:
        text(entry, "IMAGE_ENVIRONMENT", 4096)
        require("=" in entry and bool(entry.partition("=")[0]), "IMAGE_ENVIRONMENT")
    require(type(image.get("RootFS")) is dict, "IMAGE_LAYERS")
    require(len({entry.partition("=")[0] for entry in environment}) == len(environment), "IMAGE_ENVIRONMENT_DUPLICATE")
    layers = image["RootFS"].get("Layers")
    require(type(layers) is list and 0 < len(layers) <= 128 and all(DIGEST.fullmatch(str(x)) for x in layers), "IMAGE_LAYERS")
    observed = {"imageDigest": image["Id"], "created": text(image.get("Created"), "IMAGE_CREATED"),
                # Existing reproduction lock hashes compact JSON WITHOUT a newline.
                "configSha256": hashlib.sha256(canonical(config)[:-1]).hexdigest(), "rootfsDiffIds": layers}
    differences = [key for key, value in observed.items() if value != lock["reproducedImage"][key]]
    # Drift is captured accurately as a draft, never mapped to the historical origin.
    return {"imageDigest": image["Id"], "platform": "linux/amd64", "imageEnvironment": environment}, observed, differences


def archive_inventory(archive: Path, destination: Path, expected):
    pin = file_pin(archive)
    require(pin["sha256"] == expected, "ARCHIVE_PIN")
    rows = []
    total = 0
    seen = set()
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            require(len(seen) < 64 and 0 <= member.size <= MAX_FILE, "DISTRIBUTION_LIMIT")
            parts = Path(member.name).parts
            require(parts and not member.name.startswith("/") and ".." not in parts and "\\" not in member.name
                    and str(Path(member.name)) not in seen, "DISTRIBUTION_PATH")
            seen.add(str(Path(member.name)))
            require(member.isdir() or member.isfile(), "DISTRIBUTION_KIND")
            if member.isdir():
                continue
            total += member.size
            require(total <= 512 * 1024 * 1024, "DISTRIBUTION_LIMIT")
            local = destination / member.name
            require(local.parent.resolve() == local.parent, "DISTRIBUTION_SYMLINK_PARENT")
            actual = file_pin(local)
            content = stream.extractfile(member)
            digest = hashlib.sha256()
            count = 0
            with content:
                while block := content.read(65536):
                    count += len(block)
                    require(count <= member.size, "DISTRIBUTION_GROWTH")
                    digest.update(block)
            require(count == member.size == actual["bytes"] and digest.hexdigest() == actual["sha256"], "DISTRIBUTION_CHANGED")
            rows.append(actual)
    require(rows and file_pin(archive) == pin, "ARCHIVE_CHANGED")
    return {"archive": pin, "members": rows}


def prepare_inputs(root):
    """Extract only authenticated, bounded regular members into a new directory."""
    require(not (root / "tools").exists(), "TOOLS_ALREADY_PRESENT")
    (root / "tools").mkdir(mode=0o700)
    for filename, expected in (("docker.tgz", DOCKER_ARCHIVE), ("extras.tgz", EXTRAS_ARCHIVE)):
        archive = root / "downloads" / filename
        require(file_pin(archive)["sha256"] == expected, "ARCHIVE_PIN")
        count = total = 0
        seen = set()
        with tarfile.open(archive, "r:gz") as stream:
            for member in stream:
                count += 1
                total += member.size
                parts = Path(member.name).parts
                require(count <= 64 and 0 <= member.size <= MAX_FILE and total <= 512 * 1024 * 1024,
                        "DISTRIBUTION_LIMIT")
                require(parts and not member.name.startswith("/") and ".." not in parts
                        and "\\" not in member.name and str(Path(member.name)) not in seen, "DISTRIBUTION_PATH")
                seen.add(str(Path(member.name)))
                require(member.isdir() or member.isfile(), "DISTRIBUTION_KIND")
                target = root / "tools" / member.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                require(target.parent.resolve() == target.parent, "DISTRIBUTION_SYMLINK_PARENT")
                if member.isdir():
                    target.mkdir(mode=0o700, exist_ok=True)
                    continue
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
                with os.fdopen(fd, "wb") as out, stream.extractfile(member) as source:
                    copied = 0
                    while block := source.read(65536):
                        copied += len(block)
                        require(copied <= member.size, "DISTRIBUTION_GROWTH")
                        out.write(block)
                    require(copied == member.size, "DISTRIBUTION_SIZE")
        archive_inventory(archive, root / "tools", expected)
    # Fixed system locations only; do not search caller homes/configuration.
    candidates = [Path(p) for p in ("/usr/libexec/docker/cli-plugins/docker-buildx",
        "/usr/lib/docker/cli-plugins/docker-buildx", "/usr/local/libexec/docker/cli-plugins/docker-buildx",
        "/usr/local/lib/docker/cli-plugins/docker-buildx") if Path(p).exists()]
    require(candidates, "BUILDER_MISSING")
    rows = [file_pin(path.resolve()) for path in candidates]
    require(len({row["sha256"] for row in rows}) == 1, "AMBIGUOUS_BUILDER")
    original = rows[0]
    destination = root / "home/.docker/cli-plugins/docker-buildx"
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(original["path"], "rb") as source, destination.open("xb") as out:
        shutil.copyfileobj(source, out, 65536)
    destination.chmod(0o700)
    copied = file_pin(destination)
    require(copied["sha256"] == original["sha256"] and file_pin(Path(original["path"])) == original,
            "BUILDER_CHANGED")
    save(root / "artifacts/builder-origin.json", {"approved": False, "candidates": rows, "copy": copied})


def directory_fd(path):
    """No symlink traversal while acquiring a retained directory authority."""
    require(path.is_absolute(), "DIRECTORY_PATH")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            require(part not in (".", ".."), "DIRECTORY_PATH")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def public_environment(*, inspect_host=False):
    result = {name: text(os.environ.get(name), "MISSING_RUNNER_PROVENANCE", 1024) for name in PUBLIC_ENV}
    require(result["GITHUB_EVENT_NAME"] == "workflow_dispatch" and result["RUNNER_OS"] == "Linux"
            and result["RUNNER_ARCH"] == "X64", "DISPATCH_PLATFORM")
    require(result["GITHUB_REPOSITORY"] == "minsago-elite/decomp_thing", "REPOSITORY")
    for name in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        require(re.fullmatch(r"[0-9a-f]{40}", result[name]), "SOURCE_REVISION")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", result[name]), "RUN_ID")
    workflow = INSPECT_WORKFLOW if inspect_host else WORKFLOW
    require(result["GITHUB_WORKFLOW_REF"].startswith(result["GITHUB_REPOSITORY"] + "/" + workflow + "@"),
            "WORKFLOW_IDENTITY")
    return result


def _inspect_read(path, budget, *, maximum=65536, retain=True):
    """Read only a fixed public metadata/tool file, under one aggregate budget."""
    fd = None
    try:
        require(time.monotonic() < budget["end"], "INSPECT_DEADLINE")
        require(budget["bytes"] <= INSPECT_READ_BUDGET, "INSPECT_READ_LIMIT")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_size <= maximum, "INSPECT_FILE_KIND_OR_LIMIT")
        digest, payload, count = hashlib.sha256(), bytearray(), 0
        while True:
            require(time.monotonic() < budget["end"], "INSPECT_DEADLINE")
            block = os.read(fd, min(65536, maximum - count + 1, INSPECT_READ_BUDGET - budget["bytes"] + 1))
            if not block:
                break
            count += len(block)
            budget["bytes"] += len(block)
            require(count <= maximum and budget["bytes"] <= INSPECT_READ_BUDGET, "INSPECT_READ_LIMIT")
            digest.update(block)
            if retain:
                payload.extend(block)
        current, named = os.fstat(fd), path.lstat()
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(key(first) == key(current) == key(named) and (retain or count == first.st_size), "INSPECT_FILE_CHANGED")
        require(time.monotonic() < budget["end"], "INSPECT_DEADLINE")
        return {"path": str(path), "status": "observed", "bytes": count, "sha256": digest.hexdigest(),
                "device": first.st_dev, "inode": first.st_ino, "uid": first.st_uid, "gid": first.st_gid,
                "mode": stat.S_IMODE(first.st_mode)}, bytes(payload)
    except (CaptureFailure, OSError) as failure:
        return {"path": str(path), "status": "unknown", "code": getattr(failure, "code", "INSPECT_IO"),
                "errno": getattr(failure, "errno", None)}, b""
    finally:
        if fd is not None:
            os.close(fd)


def _inspect_package_facts(out, err, code):
    """Recognize only complete package observations, including one optional absence.

    This describes installed metadata; it never approves the capture prerequisites.
    In particular, repository-pinned RootlessKit extras and the exact capture slirp
    version remain subject to the separate, unchanged capture preflight.
    """
    required = {"uidmap", "slirp4netns", "dbus-user-session", "systemd"}
    optional = "rootlesskit"
    require(code in (0, 1) and len(out) <= 8192 and len(err) <= 8192
            and out.endswith(b"\n"), "INSPECT_PACKAGE_RESULT_UNSUPPORTED")
    rows = {}
    for line in out.decode("ascii", errors="strict").split("\n")[:-1]:
        parts = line.split("\t")
        require(len(parts) == 3, "INSPECT_PACKAGE_RESULT_UNSUPPORTED")
        name, version, architecture = parts
        require(name in required | {optional} and name not in rows
                and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,255}", version)
                and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", architecture),
                "INSPECT_PACKAGE_RESULT_UNSUPPORTED")
        rows[name] = {"name": name, "version": version, "architecture": architecture}
    absent = code == 1
    require((not absent and set(rows) == required | {optional} and err == b"")
            or (absent and set(rows) == required
                and err == b"dpkg-query: no packages found matching rootlesskit\n"),
            "INSPECT_PACKAGE_RESULT_UNSUPPORTED")
    return {"status": "observed-unqualified", "installed": [rows[name] for name in sorted(rows)],
            "optionalAbsent": [optional] if absent else [], "capturePrerequisitesQualified": False}


def _inspect_query(label, uid, root, budget):
    # Closed read-only argv: never run a helper --version, service operation or shell.
    queries = {
        "packages": ["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n",
                     "uidmap", "slirp4netns", "rootlesskit", "dbus-user-session", "systemd"],
        "user-manager": ["/usr/bin/systemctl", "--user", "show", "--property=Version,ControlGroup"],
        "user-service": ["/usr/bin/systemctl", "show", "user@" + str(uid) + ".service",
                         "--property=Delegate,ControlGroup,User,ActiveState"],
    }
    require(label in queries, "INSPECT_QUERY")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
           "XDG_RUNTIME_DIR": str(root / "run"), "XDG_CACHE_HOME": str(root / "cache"),
           "XDG_CONFIG_HOME": str(root / "config"), "XDG_DATA_HOME": str(root / "share"),
           "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(uid) + "/bus", "LANG": "C", "LC_ALL": "C"}
    try:
        remaining = budget["end"] - time.monotonic()
        require(remaining > 0, "INSPECT_DEADLINE")
        out, err, code, _ = command(queries[label], env, root, seconds=min(8, remaining), limit=8192, success_codes=(0, 1))
        require(time.monotonic() < budget["end"], "INSPECT_DEADLINE")
        result = {"status": "observed" if code == 0 else "refused", "argv": queries[label], "exitCode": code,
                  "stdout": out.decode("utf-8", errors="strict"), "stdoutBytes": len(out),
                  "stdoutSha256": hashlib.sha256(out).hexdigest(), "stderrBytes": len(err),
                  "stderrSha256": hashlib.sha256(err).hexdigest()}
        if label == "packages":
            try:
                result["packageFacts"] = _inspect_package_facts(out, err, code)
                result["status"] = "observed"
            except (CaptureFailure, UnicodeError):
                result.update(status="refused", code="INSPECT_PACKAGE_RESULT_UNSUPPORTED")
        return result
    except (CaptureFailure, OSError, UnicodeError) as failure:
        out, err = getattr(failure, "stdout", b""), getattr(failure, "stderr", b"")
        return {"status": "unknown", "argv": queries[label], "code": getattr(failure, "code", "INSPECT_QUERY_IO"),
                "exitCode": getattr(failure, "exit_code", None), "stdoutBytes": len(out), "stderrBytes": len(err),
                "stdoutSha256": hashlib.sha256(out).hexdigest(), "stderrSha256": hashlib.sha256(err).hexdigest()}


def _inspect_fields(query, allowed):
    result = {}
    for line in query.get("stdout", "").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in allowed and key not in result and len(value) <= 4096, "INSPECT_PROPERTY_RECORD")
        result[key] = value
    return result


def _inspect_allocations(raw, uid):
    rows = []
    lines = raw.decode("ascii", errors="strict").splitlines()
    require(len(lines) <= 1024, "INSPECT_SUBID_LIMIT")
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        require(len(parts) == 3 and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", parts[0])
                and all(re.fullmatch(r"[0-9]{1,10}", value) for value in parts[1:]), "INSPECT_SUBID_RECORD")
        start, count = int(parts[1]), int(parts[2])
        require(0 < count <= 2**32 and start + count <= 2**32, "INSPECT_SUBID_RANGE")
        if parts[0] in (str(uid), "runner"):
            rows.append({"owner": parts[0], "start": start, "count": count,
                         "numericCallerUidMatch": parts[0] == str(uid)})
    return {"totalRows": len(lines), "selectedRows": rows,
            "selection": "numeric caller UID or literal hosted-image runner name; other owners not retained",
            "callerNameBindingVerified": False}


def inspect_host(workspace, root):
    """Observe an UNQUALIFIED host candidate. Never invoke the capture route."""
    budget = {"end": time.monotonic() + INSPECT_SECONDS, "bytes": 0}
    provenance = public_environment(inspect_host=True)
    uid = os.getuid()
    uname = os.uname()
    groups = os.getgroups()
    require(len(groups) <= 64, "INSPECT_CALLER_GROUP_LIMIT")
    facts = {"runner": provenance, "runnerCandidate": {"label": "ubuntu-22.04", "expires": "2027-04-17",
             "supportedBaseline": False}, "kernel": {key: text(getattr(uname, key), "INSPECT_UNAME", 1024)
             for key in ("sysname", "release", "version", "machine")},
             "caller": {"uid": uid, "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
                        "groups": groups, "pid": os.getpid()}, "metadata": {}, "tools": [], "queries": {}}
    refusals = []
    paths = {"os-release": "/usr/lib/os-release", "apparmor-userns": "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
             "unprivileged-userns": "/proc/sys/kernel/unprivileged_userns_clone", "max-userns": "/proc/sys/user/max_user_namespaces",
             "caller-cgroup": "/proc/self/cgroup", "subuid": "/etc/subuid", "subgid": "/etc/subgid"}
    metadata = {}
    for name, path in paths.items():
        row, raw = _inspect_read(Path(path), budget)
        if name in ("subuid", "subgid") and row["status"] == "observed":
            try:
                row["allocations"] = _inspect_allocations(raw, uid)
            except (CaptureFailure, UnicodeError) as failure:
                row.update(status="unknown", code=getattr(failure, "code", "INSPECT_SUBID_ENCODING"))
        elif row["status"] == "observed":
            try:
                row["text"] = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                row.update(status="unknown", code="INSPECT_METADATA_ENCODING")
        facts["metadata"][name], metadata[name] = row, raw
    for relative in (SCRIPT, INSPECT_WORKFLOW):
        row, _ = _inspect_read(workspace / relative, budget, maximum=MAX_JSON, retain=False)
        facts["metadata"][relative] = row
    for path in ("/usr/bin/python3", "/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/dpkg-query",
                 "/usr/bin/newuidmap", "/usr/bin/newgidmap", "/usr/bin/slirp4netns", "/usr/bin/rootlesskit"):
        try:
            resolved = Path(path).resolve(strict=True)
            require(str(resolved).startswith(("/usr/", "/bin/", "/sbin/", "/lib/")), "INSPECT_TOOL_PATH")
            row, _ = _inspect_read(resolved, budget, maximum=32 * 1024 * 1024, retain=False)
            row["requestedPath"] = path
        except (OSError, CaptureFailure) as failure:
            row = {"requestedPath": path, "status": "unknown", "code": getattr(failure, "code", "INSPECT_TOOL_MISSING")}
        facts["tools"].append(row)
    bus = Path("/run/user") / str(uid) / "bus"
    try:
        observed = bus.lstat()
        facts["bus"] = {"path": str(bus), "uid": observed.st_uid, "gid": observed.st_gid,
                        "mode": stat.S_IMODE(observed.st_mode), "device": observed.st_dev, "inode": observed.st_ino,
                        "socket": stat.S_ISSOCK(observed.st_mode), "callerUidOwner": observed.st_uid == uid}
    except OSError as failure:
        facts["bus"] = {"path": str(bus), "status": "unknown", "errno": failure.errno}
    for name in ("packages", "user-service", "user-manager"):
        if name == "user-manager" and not (facts["bus"].get("socket") and facts["bus"].get("callerUidOwner")):
            facts["queries"][name] = {"status": "refused", "code": "EXISTING_OWNED_USER_BUS_UNAVAILABLE"}
        else:
            facts["queries"][name] = _inspect_query(name, uid, root, budget)
    cgroups = []
    for line in metadata["caller-cgroup"].decode("ascii", errors="replace").splitlines():
        if line.startswith("0::"):
            cgroups.append(line[3:])
    if len(cgroups) != 1:
        refusals.append("INSPECT_CALLER_CGROUP_RECORD")
    try:
        manager = _inspect_fields(facts["queries"]["user-manager"], {"Version", "ControlGroup"})
        service = _inspect_fields(facts["queries"]["user-service"], {"Delegate", "ControlGroup", "User", "ActiveState"})
        facts["delegationProperties"] = service
        if service.get("Delegate") != "yes" or service.get("ActiveState") != "active":
            refusals.append("EXISTING_USER_DELEGATION_UNAVAILABLE")
        if manager.get("ControlGroup"):
            cgroups.append(manager["ControlGroup"])
        if service.get("ControlGroup"):
            cgroups.append(service["ControlGroup"])
    except CaptureFailure as failure:
        refusals.append(failure.code)
    facts["cgroups"] = []
    if len(set(cgroups)) > 3:
        refusals.append("INSPECT_CGROUP_COUNT")
    for path in sorted(set(cgroups))[:3]:
        valid = (path.startswith("/") and path == str(Path(path)) and ".." not in Path(path).parts and len(path) <= 4096)
        if not valid:
            refusals.append("INSPECT_CGROUP_PATH")
            continue
        base = Path("/sys/fs/cgroup") / path.lstrip("/")
        row = {"path": path, "files": {}}
        try:
            fd = directory_fd(base)
            try:
                observed = os.fstat(fd)
                row["directory"] = {"uid": observed.st_uid, "gid": observed.st_gid, "mode": stat.S_IMODE(observed.st_mode),
                                    "device": observed.st_dev, "inode": observed.st_ino}
            finally:
                os.close(fd)
        except OSError as failure:
            row["directory"] = {"status": "unknown", "errno": failure.errno}
        for filename in ("cgroup.controllers", "cgroup.subtree_control", "cgroup.type"):
            field, raw = _inspect_read(base / filename, budget, maximum=4096)
            if field["status"] == "observed":
                field["text"] = raw.decode("ascii", errors="replace")
            row["files"][filename] = field
        facts["cgroups"].append(row)
    for key in ("os-release", "caller-cgroup", "subuid", "subgid"):
        if facts["metadata"][key]["status"] != "observed":
            refusals.append("REQUIRED_METADATA_UNAVAILABLE:" + key)
    if metadata["apparmor-userns"].strip() not in (b"", b"0"):
        refusals.append("USERNS_POLICY_RESTRICTED")
    if metadata["unprivileged-userns"].strip() not in (b"", b"1") or metadata["max-userns"].strip() == b"0":
        refusals.append("USERNS_POLICY_RESTRICTED")
    if any(row["status"] != "observed" for row in facts["tools"] if row["requestedPath"] != "/usr/bin/rootlesskit"):
        refusals.append("REQUIRED_TOOL_UNAVAILABLE")
    if any(row["status"] != "observed" for row in facts["queries"].values()):
        refusals.append("READ_ONLY_QUERY_REFUSED_OR_UNKNOWN")
    if not facts["cgroups"]:
        refusals.append("CGROUP_V2_OBSERVATIONS_UNAVAILABLE")
    if any(field["status"] != "observed" for row in facts["cgroups"] for field in row["files"].values()):
        refusals.append("CGROUP_METADATA_UNAVAILABLE")
    if time.monotonic() >= budget["end"]:
        refusals.append("INSPECT_DEADLINE")
    receipt = {"schemaVersion": 1, "mode": "inspect-host", "status": "refused-unqualified" if refusals else "observed-unqualified",
               "approved": False, "supportedBaseline": False, "captureRouteAdmitted": False, "workerStarted": False,
               "targetExecuted": False, "referenceExecutionQualified": False, "facts": facts, "refusals": sorted(set(refusals)),
               "readBytes": budget["bytes"], "observationBudgetSeconds": INSPECT_SECONDS,
               "limitations": ["No helper version execution, namespaces, services, OCI, toolchain or target execution.",
                   "Systemd properties and file metadata do not prove writable delegation or containment.",
                   "ubuntu-22.04 is a temporary new-generation candidate, not a supported execution profile."]}
    save(root / "artifacts/host-inspection.json", receipt)
    return not refusals


def environment(root):
    result = {"PATH": str(root / "tools/docker") + ":" + str(root / "tools/docker-rootless-extras") + ":/usr/bin:/bin", "HOME": str(root / "home"),
              "TMPDIR": str(root / "tmp"), "XDG_CACHE_HOME": str(root / "cache"),
              "XDG_CONFIG_HOME": str(root / "config"), "XDG_DATA_HOME": str(root / "share"),
              "XDG_RUNTIME_DIR": str(root / "run"), "LANG": "C", "LC_ALL": "C",
              "DOCKER_HOST": "unix://" + str(root / "run/docker.sock"),
              "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(os.getuid()) + "/bus",
              "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": str(root / "state/rootlesskit"),
              "DOCKERD_ROOTLESS_ROOTLESSKIT_NET": "slirp4netns", "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "builtin",
              "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK": "true", "PYTHONDONTWRITEBYTECODE": "1",
              "BUILDX_CONFIG": str(root / "buildx"), "DOCKER_CONFIG": str(root / "home/.docker"),
              "BUILDX_METADATA_PROVENANCE": "max"}
    return result


def preflight(root):
    """Read-only capability admission; never install/start/configure host services."""
    env = environment(root)
    public_environment()
    policy = {}
    for name, expected in (("apparmor_restrict_unprivileged_userns", "0"),
                           ("unprivileged_userns_clone", "1")):
        path = Path("/proc/sys/kernel") / name
        if path.exists():
            with path.open("rb") as source:
                raw = source.read(65)
            require(len(raw) <= 64 and raw.strip() == expected.encode(), "HOST_USERNS_POLICY_UNSUPPORTED")
            policy[str(path)] = raw.decode("ascii").strip()
        else:
            policy[str(path)] = "not-exposed"
    bus = Path("/run/user") / str(os.getuid()) / "bus"
    try:
        bus_stat = bus.lstat()
    except FileNotFoundError as error:
        raise CaptureFailure("EXISTING_USER_BUS_REQUIRED") from error
    require(stat.S_ISSOCK(bus_stat.st_mode) and bus_stat.st_uid == os.getuid(), "USER_BUS_IDENTITY")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "CGROUP_V2_REQUIRED")
    tools = []
    for path in (sys.executable, "/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/slirp4netns",
                 "/usr/bin/newuidmap", "/usr/bin/newgidmap", "/usr/bin/dpkg-query", "/bin/bash"):
        try:
            tools.append(file_pin(Path(path).resolve(strict=True)))
        except FileNotFoundError as error:
            raise CaptureFailure("HOST_PREREQUISITE_MISSING") from error
    packages, _, _, _ = command(["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n", "slirp4netns"],
                             env, root, limit=4096)
    require(packages == b"slirp4netns\t1.2.1-1build2\n", "HOST_SLIRP_PACKAGE_UNSUPPORTED")
    # A read-only query verifies the existing user manager; no start/enable/linger.
    manager, _, _, _ = command(["/usr/bin/systemctl", "--user", "show", "--property=Version,ControlGroup"], env, root, limit=4096)
    require(b"Version=" in manager and b"ControlGroup=/user.slice/" in manager, "EXISTING_USER_MANAGER_REQUIRED")
    fields = {}
    for line in manager.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in {"Version", "ControlGroup"} and key not in fields, "USER_MANAGER_RECORD")
        fields[key] = value
    require(set(fields) == {"Version", "ControlGroup"} and fields["Version"]
            and fields["ControlGroup"].startswith("/user.slice/") and ".." not in Path(fields["ControlGroup"]).parts,
            "USER_MANAGER_RECORD")
    require((Path("/sys/fs/cgroup") / fields["ControlGroup"].lstrip("/") / "cgroup.kill").exists(),
            "CGROUP_V2_KILL_REQUIRED")
    save(root / "artifacts/bootstrap.json", {"schemaVersion": 1, "approved": False,
        "mode": "existing-host-prerequisites-read-only", "usernsPolicy": policy,
        "userBus": {"path": str(bus), "device": bus_stat.st_dev, "inode": bus_stat.st_ino,
                    "uid": bus_stat.st_uid, "mode": stat.S_IMODE(bus_stat.st_mode)},
        "hostTools": tools, "slirpPackage": packages.decode("ascii"), "userManager": manager.decode("ascii"),
        "limitation": "Host bytes/capabilities observed, not a hermetic closure or executor qualification; actual delegation tested only by owned-service admission."})


def worker(workspace, root):
    worker_end = time.monotonic() + OVERALL_SECONDS
    env = environment(root)
    provenance = public_environment()
    input_pins = []
    context_names = {path.name for path in (workspace / RECIPE).parent.iterdir()}
    require(context_names == {Path(path).name for path in SOURCE_PINS}, "BUILD_CONTEXT_INPUTS")
    for relative in [*SOURCE_PINS, WORKFLOW, SCRIPT]:
        row = file_pin(workspace / relative)
        if relative in SOURCE_PINS:
            require(row["sha256"] == SOURCE_PINS[relative], "SOURCE_INPUT_PIN")
        input_pins.append(row)
    lock = strict_json((workspace / LOCK).read_bytes())
    distributions = [archive_inventory(root / "downloads/docker.tgz", root / "tools", DOCKER_ARCHIVE),
                     archive_inventory(root / "downloads/extras.tgz", root / "tools", EXTRAS_ARCHIVE)]
    client = root / "tools/docker/docker"
    client_pin = file_pin(client)
    require(client_pin["sha256"] == CLIENT_SHA and client_pin["bytes"] == CLIENT_BYTES, "CLIENT_PIN")
    require(file_pin(root / "tools/docker-rootless-extras/rootlesskit")["sha256"] == ROOTLESSKIT_SHA, "ROOTLESSKIT_PIN")
    # The host builder plugin is retained as an observed input, not an approved lock.
    builder = file_pin(root / "home/.docker/cli-plugins/docker-buildx")
    builder_origin = strict_json((root / "artifacts/builder-origin.json").read_bytes())
    require(builder_origin.get("approved") is False and builder_origin.get("copy") == builder, "BUILDER_ORIGIN")
    bootstrap = file_pin(root / "artifacts/bootstrap.json", MAX_JSON)
    host_tools = [file_pin(Path(path).resolve()) for path in (
        sys.executable, "/usr/bin/systemctl", "/usr/bin/systemd-run",
        "/usr/bin/slirp4netns", "/usr/bin/newuidmap", "/usr/bin/newgidmap", "/bin/bash")]
    raw = {}
    def control(label, args, seconds=CONTROL_SECONDS, limit=MAX_STREAM, stdout_path=None):
        return control_command(client, env, root, raw, label, args, seconds, limit, stdout_path)
    require(control("client-version", ["--version"]) == CLIENT_VERSION, "CLIENT_VERSION")
    daemon_log = bytearray()
    daemon_overflow = threading.Event()
    daemon = subprocess.Popen([str(root / "tools/docker-rootless-extras/dockerd-rootless.sh"),
        "--data-root=" + str(root / "data"), "--exec-root=" + str(root / "exec"),
        "--pidfile=" + str(root / "state/dockerd.pid"), "--host=" + env["DOCKER_HOST"],
        "--storage-driver=overlay2", "--bridge=none", "--iptables=false", "--ip6tables=false",
        "--ip-forward=false", "--ip-masq=false", "--shutdown-timeout=10", "--log-level=error"],
        env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    def drain():
        with daemon.stdout:
            while block := daemon.stdout.read(8192):
                if len(daemon_log) + len(block) > MAX_STREAM:
                    daemon_overflow.set()
                    return
                daemon_log.extend(block)
    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    try:
        end = time.monotonic() + 60
        socket = root / "run/docker.sock"
        while not socket.exists():
            require(time.monotonic() < end and daemon.poll() is None and not daemon_overflow.is_set(), "DAEMON_START")
            time.sleep(0.2)
        socket_stat = socket.lstat()
        require(stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == os.getuid(), "DAEMON_SOCKET")
        control("builder-version", ["buildx", "version"])
        tag = "decomp-llvm-reference-capture:" + provenance["GITHUB_RUN_ID"] + "-" + provenance["GITHUB_RUN_ATTEMPT"]
        control("build", ["buildx", "build", "--builder", "default", "--no-cache", "--platform", "linux/amd64",
            "--build-arg", "SOURCE_DATE_EPOCH=1786060800", "--load", "--tag", tag,
            "--metadata-file", str(root / "build-metadata.json"), "--file", str(workspace / RECIPE),
            str((workspace / RECIPE).parent)], BUILD_SECONDS)
        inspected = strict_json(control("image-inspect", ["image", "inspect", tag]))
        image, observed, differences = image_tuple(inspected, lock)
        build_metadata_pin = file_pin(root / "build-metadata.json", MAX_JSON)
        build_metadata = strict_json((root / "build-metadata.json").read_bytes())
        require(type(build_metadata) is dict and type(build_metadata.get("buildx.build.provenance")) is dict
                and bool(build_metadata["buildx.build.provenance"].get("materials")), "BUILD_PROVENANCE_MISSING")
        server = strict_json(control("server", ["version", "--format", "{{json .Server}}"] ))
        fmt = "{{json .SecurityOptions}}\n{{json .CgroupVersion}}\n{{json .CgroupDriver}}\n{{json .Driver}}\n{{json .Plugins.Volume}}\n{{json .Runtimes}}"
        info = [strict_json(line) for line in control("engine-info", ["info", "--format", fmt]).splitlines()]
        engine = engine_tuple(server, info, platform.release())
        require(not daemon_overflow.is_set(), "DAEMON_OUTPUT_LIMIT")
        archive = root / "artifacts/runtime-image.tar"
        control("image-save", ["image", "save", image["imageDigest"]], 180, stdout_path=archive)
        image_archive = file_pin(archive, MAX_IMAGE)
        stream = raw["image-save"]["stdoutArtifact"]
        require(stream["identityVerified"] and stream["eofObserved"]
                and all(stream[key] == image_archive[key] for key in ("path", "bytes", "sha256", "device", "inode", "mode")),
                "IMAGE_STREAM_ARCHIVE_CHANGED")
        require(file_pin(client) == client_pin and file_pin(root / "home/.docker/cli-plugins/docker-buildx") == builder,
                "CONTROL_INPUT_CHANGED")
        for row in input_pins:
            require(file_pin(Path(row["path"])) == row, "SOURCE_INPUT_CHANGED")
        for distribution in distributions:
            require(file_pin(Path(distribution["archive"]["path"])) == distribution["archive"], "ARCHIVE_CHANGED")
            for row in distribution["members"]:
                require(file_pin(Path(row["path"])) == row, "DISTRIBUTION_CHANGED")
        (root / "raw/daemon.log").write_bytes(bytes(daemon_log))
        retained = root / "artifacts/capture-inputs"
        retained.mkdir(mode=0o700)
        for source, name in [(root / "downloads/docker.tgz", "docker.tgz"),
                             (root / "downloads/extras.tgz", "extras.tgz"),
                             (root / "home/.docker/cli-plugins/docker-buildx", "docker-buildx"),
                             *[(workspace / path, Path(path).name) for path in SOURCE_PINS],
                             (workspace / WORKFLOW, "llvm-reference-runtime-capture.yml"),
                             (workspace / SCRIPT, Path(SCRIPT).name)]:
            before = file_pin(source)
            with source.open("rb") as incoming, (retained / name).open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, 65536)
            copied = file_pin(retained / name)
            require(before == file_pin(source) and copied["sha256"] == before["sha256"]
                    and copied["bytes"] == before["bytes"], "RETAINED_INPUT_CHANGED")
        retained_inputs = [file_pin(path) for path in sorted(retained.iterdir())]
        require(not daemon_overflow.is_set() and time.monotonic() < worker_end, "CAPTURE_PUBLICATION_LIMIT")
        save(root / "artifacts/draft-runtime.json", {
            "schema": SCHEMA, "schemaVersion": 1, "status": "captured-draft-not-approved",
            "approved": False, "referenceExecutionQualified": False, "nativeKotlinQualified": False,
            "candidateAuthority": False, "releaseAuthority": False, "clangAcquiredOrExecuted": False,
            "producedProgramExecuted": False, "runner": provenance, "sourceInputs": input_pins,
            "distributions": distributions, "builderInput": builder, "rawCommands": raw,
            "builderOrigin": builder_origin, "bootstrapReceipt": bootstrap, "hostTools": host_tools,
            "retainedInputs": retained_inputs,
            "buildMetadata": build_metadata, "buildMetadataPin": build_metadata_pin,
            "draftRuntime": {**image, "controlClient": {"bytes": CLIENT_BYTES, "sha256": CLIENT_SHA,
                "version": CLIENT_VERSION.decode()}, "engineProfile": engine},
            "imageClosure": observed, "imageArchive": image_archive,
            "historicalReproductionMatches": not differences, "historicalReproductionDifferences": differences,
            "historicalReproductionExpected": lock["reproducedImage"],
            "limitations": ["No profile approval: root must review/freeze before any target run.",
                "Host buildx bytes are observed provenance, not a preapproved builder pin.",
                "The Actions host/kernel is a declared trusted executor, not a hermetic host closure.",
                "No Clang pair, helpers, produced-program or candidate qualification occurred."]})
        # Keep the owning main process alive until the controller kills its exact
        # admitted cgroup. A complete draft is a publication signal, not success
        # inferred from a wrapper PID or an automatically approved engine query.
        while time.monotonic() < worker_end:
            time.sleep(0.2)
        raise CaptureFailure("CONTROLLER_DID_NOT_RELEASE_WORKER")
    finally:
        # The outer owner cleans the entire admitted service cgroup, including this daemon.
        (root / "raw/daemon.log").write_bytes(bytes(daemon_log))


def service_properties(unit, env, root):
    out, _, code, _ = command(["/usr/bin/systemctl", "--user", "show", unit,
        "--property=LoadState,InvocationID,ControlGroup,ActiveState,ExecMainCode,ExecMainStatus"],
        env, root, success_codes=(0, 1))
    rows = {}
    for line in out.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key not in rows, "SERVICE_RECORD")
        rows[key] = value
    require(set(rows) <= {"LoadState", "InvocationID", "ControlGroup", "ActiveState", "ExecMainCode", "ExecMainStatus"}
            and "LoadState" in rows and all(len(value) <= 4096 for value in rows.values()), "SERVICE_RECORD")
    require(code == 0 or rows.get("LoadState") == "not-found", "SERVICE_QUERY_EXIT")
    return rows


def controller(workspace, root):
    provenance = public_environment()
    env = {**environment(root), **provenance, "GITHUB_WORKSPACE": str(workspace)}
    unit = "i97-capture-" + provenance["GITHUB_RUN_ID"] + "-" + provenance["GITHUB_RUN_ATTEMPT"] + ".service"
    # --unit creation fails if that exact generation already exists; no reuse/fallback.
    end = time.monotonic() + OVERALL_SECONDS
    command(["/usr/bin/systemd-run", "--user", "--collect", "--unit=" + unit, "--service-type=exec",
        "--property=RuntimeMaxSec=" + str(OVERALL_SECONDS), "--property=TimeoutStopSec=10",
        "--property=KillMode=control-group", "--property=Delegate=yes", "--property=MemoryMax=6G",
        "--property=MemorySwapMax=0", "--property=TasksMax=512", "--property=CPUQuota=400%",
        "--property=WorkingDirectory=" + str(root), "--property=StandardOutput=null", "--property=StandardError=null",
        *["--setenv=" + key + "=" + value for key, value in env.items()],
        sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(root / "cache/python"),
        str(workspace / SCRIPT), "--root", str(root), "--internal-worker"], env, root)
    admitted = service_properties(unit, env, root)
    require(re.fullmatch(r"[0-9a-f]{32}", admitted.get("InvocationID", "")), "SERVICE_INVOCATION")
    group = admitted.get("ControlGroup", "")
    require(group.startswith("/user.slice/") and group.endswith("/" + unit) and ".." not in Path(group).parts, "SERVICE_CGROUP")
    fd = directory_fd(Path("/sys/fs/cgroup") / group.lstrip("/"))
    identity = os.fstat(fd)
    primary = None
    cleanup = False
    authority_admitted = False
    try:
        confirmed = service_properties(unit, env, root)
        require(confirmed.get("InvocationID") == admitted["InvocationID"] and confirmed.get("ControlGroup") == group,
                "SERVICE_ADMISSION_CHANGED")
        named = (Path("/sys/fs/cgroup") / group.lstrip("/")).lstat()
        require((named.st_dev, named.st_ino) == (identity.st_dev, identity.st_ino), "CGROUP_ADMISSION_CHANGED")
        authority_admitted = True
        while True:
            require(time.monotonic() < end, "CAPTURE_DEADLINE")
            current = service_properties(unit, env, root)
            require(time.monotonic() < end, "CAPTURE_DEADLINE")
            require(current.get("InvocationID") == admitted["InvocationID"] and current.get("ControlGroup") == group,
                    "SERVICE_IDENTITY_CHANGED")
            require(not (root / "artifacts/worker-failure.json").exists(), "WORKER_FAILED")
            if (root / "artifacts/draft-runtime.json").is_file():
                draft = strict_json((root / "artifacts/draft-runtime.json").read_bytes())
                require(draft.get("status") == "captured-draft-not-approved" and draft.get("approved") is False,
                        "DRAFT_PUBLICATION")
                break
            require(current.get("ActiveState") == "active", "WORKER_EXIT")
            time.sleep(0.5)
    except BaseException as failure:
        primary = failure
    finally:
        try:
            require(authority_admitted, "CGROUP_KILL_AUTHORITY_UNADMITTED")
            require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (identity.st_dev, identity.st_ino), "CGROUP_IDENTITY")
            event = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            try:
                kill = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(os.write(kill, b"1") == 1, "CGROUP_KILL_WRITE")
                finally:
                    os.close(kill)
                cleanup_end = time.monotonic() + 10
                while time.monotonic() < cleanup_end:
                    os.lseek(event, 0, os.SEEK_SET)
                    events = os.read(event, 4096)
                    current = service_properties(unit, env, root)
                    gone = current.get("LoadState") == "not-found"
                    terminal = (current.get("InvocationID") == admitted["InvocationID"]
                                and current.get("ActiveState") in ("inactive", "failed"))
                    if b"populated 0\n" in events and (gone or terminal):
                        cleanup = time.monotonic() < cleanup_end
                        break
                    time.sleep(0.05)
            finally:
                os.close(event)
        except (OSError, CaptureFailure):
            cleanup = False
        finally:
            os.close(fd)
    save(root / "artifacts/controller-result.json", {"schema": SCHEMA, "status": "captured-draft-not-approved" if primary is None and cleanup else "failed",
        "approved": False, "unit": unit, "invocationId": admitted["InvocationID"], "controlGroup": group,
        "cgroupDevice": identity.st_dev, "cgroupInode": identity.st_ino,
        "scopeAdmitted": authority_admitted, "cleanupVerified": cleanup,
        "failureCode": getattr(primary, "code", type(primary).__name__) if primary else None})
    if primary:
        raise primary
    require(cleanup, "CAPTURE_CLEANUP_UNVERIFIED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--internal-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--prepare-inputs", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--inspect-host", action="store_true", help="Observe unqualified host facts only; never provision or execute a target")
    args = parser.parse_args()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    root = args.root
    expected = "build/issue97-host-inspect" if args.inspect_host else "build/r97"
    require(workspace.is_absolute() and workspace == workspace.resolve() and root == workspace / expected
            and root == root.resolve() and stat.S_IMODE(root.stat().st_mode) == 0o700, "OWNED_WORKSPACE")
    if not args.inspect_host:
        require(len(os.fsencode(root / "run/docker.sock")) < 100, "SOCKET_PATH_LIMIT")
    directories = (("home", "tmp", "cache", "config", "share", "run", "artifacts") if args.inspect_host else
                   ("home", "tmp", "cache", "config", "share", "run", "state", "raw", "data", "exec", "artifacts", "buildx"))
    for name in directories:
        (root / name).mkdir(mode=0o700, exist_ok=True)
        require((root / name).resolve() == root / name and stat.S_IMODE((root / name).stat().st_mode) == 0o700,
                "OWNED_DIRECTORY")
    try:
        require(sum((args.internal_worker, args.prepare_inputs, args.preflight, args.inspect_host)) <= 1, "ARGUMENT_MODE")
        if args.inspect_host:
            return 0 if inspect_host(workspace, root) else 78
        elif args.preflight:
            preflight(root)
        elif args.prepare_inputs:
            prepare_inputs(root)
        elif args.internal_worker:
            worker(workspace, root)
        else:
            save(root / "state/capture-claim.json", {"schema": SCHEMA, "attempt": public_environment()})
            controller(workspace, root)
        return 0
    except Exception as failure:
        failure_path = ("artifacts/host-inspection-failure.json" if args.inspect_host else
                        "artifacts/worker-failure.json" if args.internal_worker else "artifacts/capture-failure.json")
        receipt = {"schema": SCHEMA, "status": "failed", "approved": False,
                   "failureCode": getattr(failure, "code", type(failure).__name__)}
        if args.inspect_host:
            receipt.update(mode="inspect-host", status="refused-unqualified", supportedBaseline=False,
                           captureRouteAdmitted=False, workerStarted=False, targetExecuted=False)
        save(root / failure_path, receipt)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
