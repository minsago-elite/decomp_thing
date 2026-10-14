"""Approval and immutable execution protocol for the Clang 18.1.3 worker.

The checkout cannot install approvals or authorize itself. Production execution
requires an independently installed root-owned launcher/store and a real isolated
backend. The protocol tests use inert approval stores and runtime fixtures only.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time
from types import MappingProxyType

APPROVAL_STORE = Path("/etc/decomp-thing/approved-actions/v1")
INSTALLED_LAUNCHER = Path("/usr/libexec/decomp-thing/clang1813-worker")
RUNTIME_SOCKET = Path("/run/decomp-thing/clang1813-docker.sock")
ACTIONS = frozenset(("provision-rootfs-v1", "verify-rootfs-v1", "loader-smoke-v1"))
MAX_METADATA = 1024 * 1024
MAX_INPUT = 16 * 1024 * 1024
MAX_INPUT_TOTAL = 64 * 1024 * 1024
MAX_INPUT_FILES = 512
MAX_OUTPUT = 1024 * 1024
MAX_SECONDS = 2100
WORKER_UID = 65532
ATTEMPT_LABEL = "org.decomp-thing.clang1813.attempt"
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


class WorkerRefusal(RuntimeError):
    pass


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def parse(payload: bytes) -> dict:
    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise WorkerRefusal("nonfinite worker metadata")
        return value

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkerRefusal("duplicate worker metadata key")
            result[key] = value
        return result
    try:
        value = json.loads(payload, object_pairs_hook=unique,
                           parse_float=finite_float,
                           parse_constant=lambda _: (_ for _ in ()).throw(WorkerRefusal("nonfinite worker metadata")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise WorkerRefusal("invalid bounded worker metadata") from error
    if not isinstance(value, dict):
        raise WorkerRefusal("worker metadata must be an object")
    return value


def exact(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise WorkerRefusal(f"invalid {label} shape")
    return value


def sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise WorkerRefusal("invalid approved SHA256")
    return value


def image_digest(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise WorkerRefusal("invalid approved image digest")
    sha(value[7:])
    return value


def root_owned(metadata: os.stat_result, *, directory: bool = False) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise WorkerRefusal("approval path must be root-owned and protected from caller writes")


@contextlib.contextmanager
def protected_directory(path: Path):
    """Walk every component without links; root-owned ancestors prevent swaps."""
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise WorkerRefusal("approval path must be canonical and absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        root_owned(os.fstat(descriptor), directory=True)
        for component in path.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
            root_owned(os.fstat(descriptor), directory=True)
        yield descriptor
    except OSError as error:
        raise WorkerRefusal("independently installed root-owned approval store is unavailable") from error
    finally:
        os.close(descriptor)


def read_descriptor(descriptor: int, maximum: int) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 0 or metadata.st_size > maximum:
        raise WorkerRefusal("worker input is not a bounded regular file")
    chunks = []
    offset = 0
    while offset <= maximum:
        block = os.pread(descriptor, min(64 * 1024, maximum + 1 - offset), offset)
        if not block:
            break
        chunks.append(block)
        offset += len(block)
    payload = b"".join(chunks)
    if len(payload) > maximum or len(payload) != metadata.st_size:
        raise WorkerRefusal("worker input changed length or exceeded its budget")
    return payload


def read_approved(directory: int, name: str) -> bytes:
    if not name or "/" in name or name in (".", ".."):
        raise WorkerRefusal("invalid approval metadata name")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        root_owned(os.fstat(descriptor))
        return read_descriptor(descriptor, MAX_METADATA)
    finally:
        os.close(descriptor)


def approved_bytes(directory: int, digest_value: str, suffix: str) -> bytes:
    payload = read_approved(directory, sha(digest_value) + suffix)
    if digest(payload) != digest_value:
        raise WorkerRefusal("root-owned approved metadata digest mismatch")
    return payload


def load_approved_action(action: str, requested_lock: str) -> tuple[dict, dict, dict]:
    """Trust flows from administrator-installed anchor, never the request/record."""
    if action not in ACTIONS:
        raise WorkerRefusal("unapproved fixed worker action")
    with protected_directory(APPROVAL_STORE) as directory:
        anchor = exact(parse(read_approved(directory, "approval-anchor.json")),
                       {"formatVersion", "authorityKeyFingerprint", "approvedIndexSha256", "launcherSha256"}, "approval anchor")
        if (type(anchor["formatVersion"]) is not int or anchor["formatVersion"] != 1 or
                not isinstance(anchor["authorityKeyFingerprint"], str) or
                re.fullmatch(r"[0-9A-F]{40}", anchor["authorityKeyFingerprint"]) is None):
            raise WorkerRefusal("invalid administrator-installed approval authority")
        # The root-installed anchor pins the reviewed index bytes. Independent
        # signature/key approval happens at administrator installation, outside
        # this untrusted checkout and protocol. No client-provided key authorizes it.
        index = exact(parse(approved_bytes(directory, anchor["approvedIndexSha256"], ".index.json")),
                      {"formatVersion", "actions"}, "approval index")
        if type(index["formatVersion"]) is not int or index["formatVersion"] != 1 or not isinstance(index["actions"], dict):
            raise WorkerRefusal("invalid approval index")
        if index["actions"].get(action) != sha(requested_lock):
            raise WorkerRefusal("requested lock is not independently approved for this action")
        lock = exact(parse(approved_bytes(directory, requested_lock, ".lock.json")),
                     {"formatVersion", "manifestDigest", "configDigest", "rootfsDiffIds", "platform",
                      "inputRecipeSha256", "packageManifestSha256", "runtimeCli"}, "environment lock")
        if type(lock["formatVersion"]) is not int or lock["formatVersion"] != 1 or lock["platform"] != {"os": "linux", "architecture": "amd64"}:
            raise WorkerRefusal("unapproved worker platform")
        image_digest(lock["manifestDigest"])
        image_digest(lock["configDigest"])
        if not isinstance(lock["rootfsDiffIds"], list) or not lock["rootfsDiffIds"] or len(lock["rootfsDiffIds"]) > 128:
            raise WorkerRefusal("invalid approved rootfs layer closure")
        for layer in lock["rootfsDiffIds"]:
            image_digest(layer)
        sha(lock["packageManifestSha256"])
        cli = exact(lock["runtimeCli"], {"path", "sha256", "bytes"}, "approved runtime CLI")
        if cli["path"] != "/usr/bin/docker" or type(cli["bytes"]) is not int or not 0 < cli["bytes"] <= 128 * MAX_METADATA:
            raise WorkerRefusal("invalid approved runtime CLI path/size")
        sha(cli["sha256"])
        manifest = exact(parse(approved_bytes(directory, lock["inputRecipeSha256"], ".action.json")),
                         {"formatVersion", "action", "inputs", "argv", "environment", "limits"}, "action manifest")
        if type(manifest["formatVersion"]) is not int or manifest["formatVersion"] != 1 or manifest["action"] != action:
            raise WorkerRefusal("approved action source closure mismatch")
        validate_action(manifest)
        return anchor, lock, manifest


def validate_action(manifest: dict) -> None:
    inputs = manifest["inputs"]
    if not isinstance(inputs, list) or not 0 < len(inputs) <= MAX_INPUT_FILES:
        raise WorkerRefusal("invalid approved input closure")
    names = []
    total = 0
    for row in inputs:
        exact(row, {"name", "bytes", "sha256"}, "approved input")
        name = row["name"]
        if (not isinstance(name, str) or not name or len(name) > 4096 or "\0" in name or
                name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/"))):
            raise WorkerRefusal("unsafe approved input name")
        if type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_INPUT:
            raise WorkerRefusal("approved input exceeds its byte budget")
        sha(row["sha256"])
        names.append(name)
        total += row["bytes"]
    if names != sorted(set(names)) or total > MAX_INPUT_TOTAL:
        raise WorkerRefusal("approved input closure is duplicated, unordered or oversized")
    argv = manifest["argv"]
    if (not isinstance(argv, list) or not argv or len(argv) > 128 or
            any(not isinstance(arg, str) or "\0" in arg or len(arg) > 8192 for arg in argv) or
            not argv[0].startswith("/usr/") or ".." in PurePosixPath(argv[0]).parts):
        raise WorkerRefusal("invalid approved absolute action command")
    env = exact(manifest["environment"], {"PATH", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH"}, "approved environment")
    if (env["PATH"] != "/usr/sbin:/usr/bin:/sbin:/bin" or env["LC_ALL"] != "C" or env["TZ"] != "UTC" or
            not isinstance(env["SOURCE_DATE_EPOCH"], str) or re.fullmatch(r"0|[1-9][0-9]*", env["SOURCE_DATE_EPOCH"]) is None):
        raise WorkerRefusal("unapproved action environment")
    limits = exact(manifest["limits"], {"seconds", "memoryBytes", "cpus", "pids", "diskBytes", "outputBytes"}, "action limits")
    maxima = {"seconds": MAX_SECONDS, "memoryBytes": 2 * 1024**3, "cpus": 2,
              "pids": 128, "diskBytes": 2 * 1024**3, "outputBytes": MAX_OUTPUT}
    if any(type(limits[key]) is not int or not 0 < limits[key] <= maximum for key, maximum in maxima.items()):
        raise WorkerRefusal("action limits exceed the fixed worker boundary")


@contextlib.contextmanager
def sealed_snapshot(payload: bytes, *, executable: bool = False):
    descriptor = os.memfd_create("clang1813-approved-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor, 0o500 if executable else 0o400)
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(payload)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & SEALS != SEALS:
            raise WorkerRefusal("worker input could not be sealed")
        yield descriptor
    finally:
        os.close(descriptor)


def expected_image(lock: dict) -> dict:
    return {key: lock[key] for key in ("manifestDigest", "configDigest", "rootfsDiffIds", "platform")}


@dataclass(frozen=True)
class ApprovedResult:
    stdout: bytes
    lock_sha256: str
    action_sha256: str
    execution_sha256: str


def _execute_approved_protocol(action: str, requested_lock: str, input_fds: dict[str, int], backend) -> ApprovedResult:
    """Internal root-installed launcher entry point; backend is never request data.

    The production launcher constructs DockerBackend itself from approved bytes.
    Dependency injection here supports inert tests, not a caller-selected backend.
    """
    _, lock, manifest = load_approved_action(action, requested_lock)
    expected = {row["name"]: row for row in manifest["inputs"]}
    if set(input_fds) != set(expected):
        raise WorkerRefusal("client inputs differ from the complete approved source closure")
    with contextlib.ExitStack() as snapshots:
        captured = {}
        for name, row in expected.items():
            payload = read_descriptor(input_fds[name], row["bytes"])
            if len(payload) != row["bytes"] or digest(payload) != row["sha256"]:
                raise WorkerRefusal("client source/recipe bytes are not independently approved")
            captured[name] = snapshots.enter_context(sealed_snapshot(payload))
        measured = parse(canonical(backend.inspect_image(parse(canonical(lock)))))
        if measured != expected_image(lock):
            raise WorkerRefusal("actual runtime-selected image differs from the approved environment")
        spec = {"action": action, "image": measured, "argv": manifest["argv"],
                "environment": manifest["environment"], "limits": manifest["limits"],
                "uid": WORKER_UID, "gid": WORKER_UID, "network": "none", "readOnly": True,
                "capabilities": [], "noNewPrivileges": True,
                "inputRecipeSha256": lock["inputRecipeSha256"]}
        spec_payload = canonical(spec)
        result = backend.execute(parse(spec_payload), MappingProxyType(captured))
        # execute() measures the actual container after creation through the
        # administrator-trusted runtime socket. Child stdout cannot supply this.
        exact(result, {"executionSha256", "image", "exitCode", "stdout"}, "runtime result")
        if result["executionSha256"] != digest(spec_payload) or result["image"] != measured:
            raise WorkerRefusal("runtime execution identity changed after approved selection")
        if type(result["exitCode"]) is not int or result["exitCode"] != 0:
            raise WorkerRefusal("approved isolated action failed")
        if not isinstance(result["stdout"], bytes) or len(result["stdout"]) > manifest["limits"]["outputBytes"]:
            raise WorkerRefusal("approved isolated action output exceeded its budget")
        return ApprovedResult(result["stdout"], requested_lock, lock["inputRecipeSha256"], digest(spec_payload))


class DockerBackend:
    """Fixed runtime backend for the independently installed privileged launcher.

    The root-only daemon socket is the measurement authority. No client/backend
    receipt from the unprivileged child is accepted as container configuration.
    Actual deployment and Docker integration qualification remain unavailable.
    """
    def __init__(self, lock: dict, stage_parent: int | None):
        self.lock = lock
        self.stage_parent = stage_parent
        self.stack = contextlib.ExitStack()
        self.cli_fd = -1
        self.config_fd = -1
        # Retained until daemon-authenticated removal succeeds. The future
        # production supervisor must persist/reconcile these across its crashes.
        self.pending_attempts: dict[str, str] = {}

    def __enter__(self):
        try:
            if os.geteuid() != 0:
                raise WorkerRefusal("immutable runtime backend requires the installed root launcher")
            cli = self.lock["runtimeCli"]
            with protected_directory(Path(cli["path"]).parent) as parent:
                descriptor = os.open(Path(cli["path"]).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    root_owned(os.fstat(descriptor))
                    if not os.fstat(descriptor).st_mode & 0o111:
                        raise WorkerRefusal("approved runtime CLI is not executable")
                    payload = read_descriptor(descriptor, 128 * MAX_METADATA)
                    if len(payload) != cli["bytes"] or digest(payload) != cli["sha256"]:
                        raise WorkerRefusal("installed runtime CLI differs from approved bytes")
                    self.cli_fd = self.stack.enter_context(sealed_snapshot(payload, executable=True))
                finally:
                    os.close(descriptor)
            self.config_fd = self.stack.enter_context(protected_directory(APPROVAL_STORE / "docker"))
            if parse(read_approved(self.config_fd, "config.json")) != {}:
                raise WorkerRefusal("runtime client configuration must be empty and root-owned")
            with protected_directory(RUNTIME_SOCKET.parent) as parent:
                socket = os.stat(RUNTIME_SOCKET.name, dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0 or socket.st_gid != 0 or
                        stat.S_IMODE(socket.st_mode) != 0o600):
                    raise WorkerRefusal("runtime measurement socket is not exclusively root-controlled")
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *exc):
        return self.stack.__exit__(*exc)

    def command(self, arguments: list[str], *, maximum: int = MAX_METADATA, seconds: int = 30) -> bytes:
        """Bound stdout/stderr as they arrive; timeout kills the CLI process group."""
        if self.cli_fd < 0 or self.config_fd < 0:
            raise WorkerRefusal("approved runtime backend is not initialized")
        argv = ["docker", f"--host=unix://{RUNTIME_SOCKET}",
                f"--config=/proc/self/fd/{self.config_fd}", *arguments]
        with subprocess.Popen(argv, executable=f"/proc/self/fd/{self.cli_fd}",
                              pass_fds=(self.cli_fd, self.config_fd), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={}, cwd="/",
                              start_new_session=True) as process:
            deadline = time.monotonic() + seconds
            output = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise WorkerRefusal("runtime command exceeded its wall-time limit")
                        ready = selector.select(min(remaining, 0.1))
                        for key, _ in ready:
                            block = os.read(key.fileobj.fileno(), min(64 * 1024, maximum + 1 - len(output)))
                            if not block:
                                selector.unregister(key.fileobj)
                            else:
                                output.extend(block)
                                if len(output) > maximum:
                                    raise WorkerRefusal("runtime command exceeded its output limit")
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0:
                    raise WorkerRefusal("approved runtime command failed")
                return bytes(output)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise

    def inspect_image(self, lock: dict) -> dict:
        # Content-addressed local selection only. No registry request or pull.
        raw = parse(self.command(["image", "inspect", lock["configDigest"], "--format", "{{json .}} "]))
        repo_digests = raw.get("RepoDigests")
        if (not isinstance(repo_digests, list) or
                not any(isinstance(row, str) and row.endswith("@" + lock["manifestDigest"]) for row in repo_digests)):
            raise WorkerRefusal("actual local image lacks its approved OCI manifest identity")
        return {"manifestDigest": lock["manifestDigest"], "configDigest": raw.get("Id"),
                "rootfsDiffIds": raw.get("RootFS", {}).get("Layers"),
                "platform": {"os": raw.get("Os"), "architecture": raw.get("Architecture")}}

    @contextlib.contextmanager
    def stage_inputs(self, inputs):
        """Materialize sealed inputs under root-owned held directory authority.

        The daemon binds the held /proc descriptor, so renaming the caller-owned
        stage parent cannot redirect the mount. Cleanup only unlinks known files
        via held FDs and checks the parent name before removing the empty root.
        """
        if type(self.stage_parent) is not int:
            raise WorkerRefusal("runtime staging requires the trusted supervisor's held parent descriptor")
        parent = os.dup(self.stage_parent)
        root = -1
        name = ".clang1813-worker-" + os.urandom(16).hex()
        created_directories = []
        created_files = []
        try:
            # The supervisor provides an already authenticated held directory.
            # Its root ownership prevents caller replacement between mkdir/open,
            # even if a caller can rename one of its pathname ancestors.
            root_owned(os.fstat(parent), directory=True)
            os.mkdir(name, 0o700, dir_fd=parent)
            os.chmod(name, 0o700, dir_fd=parent, follow_symlinks=False)
            root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            identity = os.fstat(root)
            root_owned(identity, directory=True)
            os.fchmod(root, 0o700)
            for logical, source in sorted(inputs.items()):
                if fcntl.fcntl(source, fcntl.F_GET_SEALS) & SEALS != SEALS:
                    raise WorkerRefusal("runtime staging requires immutable sealed source snapshots")
                components = logical.split("/")
                if any(component in ("", ".", "..") for component in components):
                    raise WorkerRefusal("unsafe immutable stage input name")
                directory = os.dup(root)
                prefix = []
                try:
                    for component in components[:-1]:
                        prefix.append(component)
                        try:
                            os.mkdir(component, 0o755, dir_fd=directory)
                            created_directories.append(tuple(prefix))
                            os.chmod(component, 0o755, dir_fd=directory, follow_symlinks=False)
                        except FileExistsError:
                            pass
                        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=directory)
                        os.close(directory)
                        directory = child
                        root_owned(os.fstat(directory), directory=True)
                        os.fchmod(directory, 0o755)
                    output = os.open(components[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o444, dir_fd=directory)
                    created_files.append(tuple(components))
                    with os.fdopen(output, "wb") as stream:
                        os.fchmod(stream.fileno(), 0o444)
                        stream.write(read_descriptor(source, MAX_INPUT))
                finally:
                    os.close(directory)
            os.fchmod(root, 0o555)
            yield f"/proc/{os.getpid()}/fd/{root}"
        finally:
            try:
                if root >= 0:
                    try:
                        os.fchmod(root, 0o700)
                        for parts in reversed(created_files):
                            self.unlink_staged(root, parts, directory=False)
                        for parts in reversed(created_directories):
                            self.unlink_staged(root, parts, directory=True)
                        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino):
                            raise WorkerRefusal("immutable stage pathname changed; refusing foreign cleanup")
                        os.rmdir(name, dir_fd=parent)
                    finally:
                        os.close(root)
            finally:
                os.close(parent)

    @staticmethod
    def unlink_staged(root: int, parts: tuple[str, ...], *, directory: bool):
        held = os.dup(root)
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
                os.close(held)
                held = child
            (os.rmdir if directory else os.unlink)(parts[-1], dir_fd=held)
        finally:
            os.close(held)

    @staticmethod
    def container_environment(spec: dict) -> dict:
        # /usr/bin/env itself starts before -i takes effect, so the daemon's
        # initial environment must also exclude loader/tool injection state.
        cleared = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GLIBC_TUNABLES", "PYTHONPATH", "PYTHONHOME",
                   "PYTHONSTARTUP", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "GRADLE_OPTS",
                   "CLASSPATH", "BASH_ENV", "ENV")
        return {**spec["environment"], **{key: "" for key in cleared}, "HOME": "/nonexistent"}

    @staticmethod
    def create_arguments(spec: dict, source: str) -> list[str]:
        limits = spec["limits"]
        return ["create", "--pull=never", "--read-only", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges=true", f"--user={WORKER_UID}:{WORKER_UID}",
                f"--memory={limits['memoryBytes']}", f"--memory-swap={limits['memoryBytes']}",
                f"--cpus={limits['cpus']}", f"--pids-limit={limits['pids']}",
                "--ulimit=core=0:0", f"--ulimit=fsize={limits['diskBytes']}:{limits['diskBytes']}",
                "--mount", f"type=bind,src={source},dst=/inputs,readonly,bind-propagation=rprivate",
                "--tmpfs", f"/work:rw,noexec,nosuid,nodev,size={limits['diskBytes']},uid={WORKER_UID},gid={WORKER_UID},mode=0700",
                "--workdir=/work", "--entrypoint=/usr/bin/env",
                *[f"--env={key}={value}" for key, value in sorted(DockerBackend.container_environment(spec).items())],
                spec["image"]["configDigest"], "-i",
                *[f"{key}={value}" for key, value in sorted(spec["environment"].items())], *spec["argv"]]

    @staticmethod
    def verify_container(raw: dict, spec: dict, source: str) -> None:
        config = raw.get("Config", {})
        host = raw.get("HostConfig", {})
        mounts = raw.get("Mounts")
        limits = spec["limits"]
        raw_env = config.get("Env")
        valid_env = (isinstance(raw_env, list) and all(isinstance(item, str) and "=" in item for item in raw_env) and
                     len({item.split("=", 1)[0] for item in raw_env}) == len(raw_env) and
                     dict(item.split("=", 1) for item in raw_env) == DockerBackend.container_environment(spec))
        expected_command = ["-i", *[f"{key}={value}" for key, value in sorted(spec["environment"].items())], *spec["argv"]]
        expected_tmpfs = f"rw,noexec,nosuid,nodev,size={limits['diskBytes']},uid={WORKER_UID},gid={WORKER_UID},mode=0700"
        bind_mounts = [row for row in mounts if isinstance(row, dict) and row.get("Type") == "bind"] if isinstance(mounts, list) else []
        tmpfs_mounts = [row for row in mounts if isinstance(row, dict) and row.get("Type") == "tmpfs"] if isinstance(mounts, list) else []
        valid_mounts = (isinstance(mounts, list) and len(bind_mounts) == 1 and len(tmpfs_mounts) <= 1 and
                        len(mounts) == len(bind_mounts) + len(tmpfs_mounts) and
                        (not tmpfs_mounts or (tmpfs_mounts[0].get("Destination") == "/work" and tmpfs_mounts[0].get("RW") is True)))
        expected_ulimits = {("core", 0, 0), ("fsize", limits["diskBytes"], limits["diskBytes"])}
        ulimits = host.get("Ulimits")
        valid_ulimits = (isinstance(ulimits, list) and len(ulimits) == 2 and
                          all(isinstance(row, dict) and set(row) == {"Name", "Soft", "Hard"} for row in ulimits) and
                          {(row["Name"], row["Soft"], row["Hard"]) for row in ulimits} == expected_ulimits)
        if (raw.get("Image") != spec["image"]["configDigest"] or config.get("User") != f"{WORKER_UID}:{WORKER_UID}" or
                config.get("Entrypoint") != ["/usr/bin/env"] or config.get("Cmd") != expected_command or
                config.get("WorkingDir") != "/work" or not valid_env or host.get("ReadonlyRootfs") is not True or
                host.get("Privileged") is not False or host.get("NetworkMode") != "none" or
                host.get("CapDrop") != ["ALL"] or host.get("CapAdd") not in (None, []) or
                host.get("SecurityOpt") != ["no-new-privileges=true"] or
                host.get("Memory") != limits["memoryBytes"] or host.get("MemorySwap") != limits["memoryBytes"] or
                host.get("NanoCpus") != limits["cpus"] * 1_000_000_000 or host.get("PidsLimit") != limits["pids"] or
                host.get("Tmpfs") != {"/work": expected_tmpfs} or not valid_ulimits or
                host.get("PidMode") not in (None, "") or host.get("IpcMode") != "private" or
                host.get("UTSMode") not in (None, "") or host.get("UsernsMode") not in (None, "") or
                host.get("VolumesFrom") not in (None, []) or host.get("PortBindings") not in (None, {}) or
                host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, []) or
                host.get("DeviceCgroupRules") not in (None, []) or host.get("Binds") not in (None, []) or
                not valid_mounts or bind_mounts[0].get("Source") != source or
                bind_mounts[0].get("Destination") != "/inputs" or bind_mounts[0].get("RW") is not False or
                bind_mounts[0].get("Propagation") != "rprivate"):
            raise WorkerRefusal("actual daemon-measured container violates the fixed isolation spec")

    @staticmethod
    def verify_attempt(raw: dict, name: str, token: str, expected_id: str | None = None) -> str:
        identity = raw.get("Id")
        labels = raw.get("Config", {}).get("Labels")
        if (not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None or
                raw.get("Name") != "/" + name or not isinstance(labels, dict) or labels.get(ATTEMPT_LABEL) != token or
                (expected_id is not None and identity != expected_id)):
            raise WorkerRefusal("container attempt ownership changed; refusing foreign cleanup/execution")
        return identity

    def cleanup_attempt(self, name: str, token: str, expected_id: str | None) -> None:
        # Inspect through the trusted daemon even if create stdout never arrived.
        # Remove only its authenticated immutable ID, never the mutable name.
        try:
            raw = parse(self.command(["container", "inspect", expected_id or name, "--format", "{{json .}} "]))
            identity = self.verify_attempt(raw, name, token, expected_id)
            self.command(["rm", "--force", identity])
        except BaseException as error:
            raise WorkerRefusal(f"container attempt {name} could not be safely reconciled; ownership remains pending") from error
        self.pending_attempts.pop(name, None)

    def execute(self, spec: dict, inputs) -> dict:
        # Establish attempt correlation before sending create. A lost, timed-out,
        # oversized or malformed CLI reply does not mean the daemon did not create.
        name = "clang1813-" + os.urandom(32).hex()
        token = os.urandom(32).hex()
        container = None
        attempted = False
        with self.stage_inputs(inputs) as source:
            try:
                arguments = self.create_arguments(spec, source)
                arguments[1:1] = ["--name=" + name, "--label=" + ATTEMPT_LABEL + "=" + token]
                self.pending_attempts[name] = token
                attempted = True
                created = self.command(arguments).decode("ascii").strip()
                if re.fullmatch(r"[0-9a-f]{64}", created) is None:
                    raise WorkerRefusal("runtime returned an invalid container identity")
                container = created
                raw = parse(self.command(["container", "inspect", container, "--format", "{{json .}} "]))
                self.verify_attempt(raw, name, token, container)
                self.verify_container(raw, spec, source)
                output = self.command(["start", "--attach", container],
                                      maximum=spec["limits"]["outputBytes"], seconds=spec["limits"]["seconds"])
                final = parse(self.command(["container", "inspect", container, "--format", "{{json .}} "]))
                self.verify_attempt(final, name, token, container)
                self.verify_container(final, spec, source)
                state = final.get("State", {})
                if (state.get("Running") is not False or state.get("OOMKilled") is not False or
                        type(state.get("ExitCode")) is not int or state["ExitCode"] != 0):
                    raise WorkerRefusal("approved isolated action did not exit successfully")
                return {"executionSha256": digest(canonical(spec)), "image": spec["image"], "exitCode": 0, "stdout": output}
            finally:
                if attempted:
                    self.cleanup_attempt(name, token, container)


def require_production_worker(action: str) -> None:
    """No caller-installed policy or environment variable can enable qualification.

    A real root-installed approval store/launcher and the artifact request/return
    integration must both exist. This checkout provides neither approval values
    nor a direct mutable-host execution fallback.
    """
    if action not in ACTIONS:
        raise WorkerRefusal("unapproved fixed worker action")
    try:
        with protected_directory(APPROVAL_STORE) as directory:
            anchor = parse(read_approved(directory, "approval-anchor.json"))
            expected_launcher = sha(anchor.get("launcherSha256"))
        with protected_directory(INSTALLED_LAUNCHER.parent) as parent:
            payload = read_approved(parent, INSTALLED_LAUNCHER.name)
            if digest(payload) != expected_launcher:
                raise WorkerRefusal("installed launcher is not administrator-approved")
    except (OSError, WorkerRefusal) as error:
        raise WorkerRefusal("immutable host execution unavailable: no independently approved root-owned launcher/environment") from error
    # Transporting rootfs/acquisition/artifact descriptors through this launcher
    # and revalidating the returned receipts is a distinct unfinished checkpoint.
    # A successful approval lookup must never resume the old host commands.
    raise WorkerRefusal("immutable host execution unavailable: production artifact/launcher integration is unfinished")


def execute_installed_action(action: str, requested_lock: str, input_fds: dict[str, int],
                             trusted_stage_parent: int) -> ApprovedResult:
    """Concrete backend entry for the independently installed root launcher only.

    Artifact request framing/FD transport is intentionally not exposed by this
    checkout; trusted_stage_parent is a directory FD authenticated and held by
    the root supervisor during service deployment, never a client pathname/FD.
    """
    if os.geteuid() != 0 or Path(__file__) != INSTALLED_LAUNCHER:
        raise WorkerRefusal("action execution requires the independently installed root launcher")
    anchor, lock, _ = load_approved_action(action, requested_lock)
    with protected_directory(INSTALLED_LAUNCHER.parent) as parent:
        payload = read_approved(parent, INSTALLED_LAUNCHER.name)
        if digest(payload) != sha(anchor["launcherSha256"]):
            raise WorkerRefusal("executing launcher bytes are not administrator-approved")
    with DockerBackend(lock, trusted_stage_parent) as backend:
        return _execute_approved_protocol(action, requested_lock, input_fds, backend)
