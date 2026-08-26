"""Deterministic, program-agnostic executable behavior-corpus runner.

The runner treats an executable as an opaque byte artifact. Benchmark-specific
adapters may authenticate that artifact against stronger provenance metadata,
but process execution, normalization, observations, and pass/fail semantics do
not depend on a toolchain, file format, or program identity.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, BinaryIO, Callable, Iterable, Mapping, Sequence, cast


_ORIGINAL_GETSIGNAL = signal.getsignal
_ORIGINAL_SIGNAL = signal.signal


MAX_CORPUS_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_CASES = 256
MAX_INPUTS_PER_CASE = 256
MAX_ARTIFACTS_PER_CASE = 256
MAX_ARGUMENTS = 4096
MAX_HELPER_ARGUMENT_CHARACTERS = 8192
MAX_ENVIRONMENT_VARIABLES = 256
MAX_TEXT_CHARACTERS = 16_384
MAX_INPUT_BYTES_PER_CASE = 16 * 1024 * 1024
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RETAINED_BINARY_BYTES = 32 * 1024 * 1024
MAX_WORKSPACE_BYTES = 64 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 4096
MAX_CATEGORIES = 256
CONTROL_CAPTURE_BYTES = 64 * 1024
CONTROL_OPERATION_TIMEOUT_MILLISECONDS = 30_000
CONTROL_UNCERTAINTY_SECONDS = CONTROL_OPERATION_TIMEOUT_MILLISECONDS / 1000
CREATE_PUBLICATION_SETTLEMENT_SECONDS = (
    CONTROL_OPERATION_TIMEOUT_MILLISECONDS / 1000 + CONTROL_UNCERTAINTY_SECONDS
)
MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT = 8
CPU_PERIOD_MICROSECONDS = 100_000
CPU_QUOTA_MICROSECONDS = 100_000
OOM_SCORE_ADJUSTMENT = 500
_PREEXEC_FRAME_MAGIC = b"\x00behavior-preexec-v1:"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PLATFORM = re.compile(r"[a-z0-9]+/[a-z0-9_]+")
_API_VERSION = re.compile(r"[0-9]+\.[0-9]+")
_MODE = re.compile(r"0o[0-7]{3}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_RUNTIME_PATHS = {"workspace", "oracle"}
_STREAM_FIELDS = {"stdout", "stderr"}
_FORBIDDEN_PRELAUNCH_NAMES = {
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "GCONV_PATH",
    "IFS",
    "LOCPATH",
    "NLSPATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
    "SHELLOPTS",
}
_FORBIDDEN_PRELAUNCH_PREFIXES = ("GLIBC_", "LD_", "MALLOC_", "PERL5")
_COMPONENT_DETAIL_EXCLUSIONS = {
    ("Engine", "KernelVersion"),
    ("rootlesskit", "StateDir"),
}

# Versioned alongside PYTHON_PREEXEC_ENFORCER_V1.  These are the canonical
# resource controls which Docker's HostConfig API exposes for this profile but
# which the create command intentionally leaves at their non-constraining
# defaults.  The main requested bounds are checked separately below.
OCI_HOST_RESOURCE_POLICY_VERSION = 1
_HOST_RESOURCE_DEFAULTS_V1: dict[str, Any] = {
    "CgroupParent": "",
    "CpuShares": 0,
    "CpuRealtimePeriod": 0,
    "CpuRealtimeRuntime": 0,
    "CpusetCpus": "",
    "CpusetMems": "",
    "MemoryReservation": 0,
    "MemorySwappiness": None,
    "BlkioWeight": 0,
    "BlkioWeightDevice": [],
    "BlkioDeviceReadBps": [],
    "BlkioDeviceWriteBps": [],
    "BlkioDeviceReadIOps": [],
    "BlkioDeviceWriteIOps": [],
    "DeviceCgroupRules": None,
    "Devices": [],
    "DeviceRequests": None,
    "CpuCount": 0,
    "CpuPercent": 0,
    "IOMaximumIOps": 0,
    "IOMaximumBandwidth": 0,
}
# Older/newer API versions may omit these deprecated or platform-specific
# fields.  If advertised, however, they remain part of the closed policy.
_OPTIONAL_HOST_RESOURCE_DEFAULTS_V1: dict[str, Any] = {
    "Annotations": None,
    "CpuBurst": 0,
    "KernelMemory": 0,
    "KernelMemoryTCP": 0,
    "CpuWeight": 0,
}

PYTHON_PREEXEC_ENFORCER_V1 = r'''import errno, os, resource, sys
arguments = sys.argv[1:]
if len(arguments) < 14 or arguments[0] != "behavior-preexec-v1" or arguments[12] != "--":
    raise RuntimeError("invalid pre-exec contract")
role = arguments[1]
nonce = arguments[2]
if role not in {"keeper", "setup", "target", "collector"}:
    raise RuntimeError("invalid pre-exec role")
if len(nonce) != 32 or any(character not in "0123456789abcdef" for character in nonce):
    raise RuntimeError("invalid pre-exec nonce")
memory_max, pids_max, cpu_quota, cpu_period, file_size, open_files, processes, cpu_seconds, oom_score_adjustment = map(int, arguments[3:12])
command = arguments[13:]
if not command or not command[0].startswith("/"):
    raise RuntimeError("invalid pre-exec command")
if open("/proc/self/cgroup", encoding="ascii").read() != "0::/\n":
    raise RuntimeError("process is not at a private cgroup namespace root")
mounts = [line.split() for line in open("/proc/self/mountinfo", encoding="ascii") if " /sys/fs/cgroup " in line]
if len(mounts) != 1:
    raise RuntimeError("ambiguous cgroup mount")
mount = mounts[0]
separator = mount.index("-")
if mount[3] != "/" or mount[separator + 1] != "cgroup2" or "ro" not in set(mount[5].split(",")):
    raise RuntimeError("cgroup2 namespace root is not read-only")
cgroup = "/sys/fs/cgroup"
def control(name):
    with open(cgroup + "/" + name, encoding="ascii") as stream:
        return stream.read().strip()
expected = {
    "memory.max": str(memory_max),
    "memory.swap.max": "0",
    "memory.high": "max",
    "memory.low": "0",
    "memory.min": "0",
    "memory.oom.group": "0",
    "pids.max": str(pids_max),
    "cpu.max": str(cpu_quota) + " " + str(cpu_period),
    "cpu.weight": "100",
    "cgroup.subtree_control": "",
    "cgroup.type": "domain",
    "cgroup.procs": "1",
}
for name, value in expected.items():
    if control(name) != value:
        raise RuntimeError("cgroup control mismatch: " + name)
burst = cgroup + "/cpu.max.burst"
if os.path.exists(burst) and control("cpu.max.burst") != "0":
    raise RuntimeError("cgroup CPU burst is not zero")
optional_defaults = {
    "cpu.idle": "0",
    "cpu.weight.nice": "0",
    "cpu.uclamp.min": "0.00",
    "cpu.uclamp.max": "max",
    "memory.swap.high": "max",
    "memory.zswap.max": "max",
    "memory.zswap.writeback": "1",
    "io.max": "",
    "io.weight": "default 100",
}
for name, value in optional_defaults.items():
    if os.path.exists(cgroup + "/" + name) and control(name) != value:
        raise RuntimeError("cgroup default control mismatch: " + name)
for configured, effective in (("cpuset.cpus", "cpuset.cpus.effective"), ("cpuset.mems", "cpuset.mems.effective")):
    configured_exists = os.path.exists(cgroup + "/" + configured)
    effective_exists = os.path.exists(cgroup + "/" + effective)
    if configured_exists != effective_exists:
        raise RuntimeError("incomplete cgroup cpuset controls")
    if configured_exists and (control(configured) != "" or control(effective) == ""):
        raise RuntimeError("cgroup cpuset is explicitly constrained or ineffective: " + configured)
if not {"cpu", "memory", "pids"}.issubset(set(control("cgroup.controllers").split())):
    raise RuntimeError("required cgroup controllers are unavailable")
if any(entry.is_dir(follow_symlinks=False) for entry in os.scandir(cgroup)):
    raise RuntimeError("cgroup namespace root contains delegated children")
if os.access(cgroup, os.W_OK):
    raise RuntimeError("cgroup namespace root is writable")
for name in (*expected, "cgroup.threads"):
    path = cgroup + "/" + name
    if os.access(path, os.W_OK):
        raise RuntimeError("cgroup control is writable: " + name)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    except OSError as error:
        if error.errno not in {errno.EACCES, errno.EPERM, errno.EROFS}:
            raise
    else:
        os.close(descriptor)
        raise RuntimeError("cgroup control opened writable: " + name)
if open("/proc/self/oom_score_adj", encoding="ascii").read().strip() != str(oom_score_adjustment):
    raise RuntimeError("process OOM score adjustment mismatch")
rlimits = {
    resource.RLIMIT_CORE: (0, 0),
    resource.RLIMIT_FSIZE: (file_size, file_size),
    resource.RLIMIT_NOFILE: (open_files, open_files),
    resource.RLIMIT_NPROC: (processes, processes),
    resource.RLIMIT_CPU: (cpu_seconds, cpu_seconds),
}
for identifier, value in rlimits.items():
    if resource.getrlimit(identifier) != value:
        raise RuntimeError("process rlimit mismatch")
marker = b"\x00behavior-preexec-v1:" + role.encode("ascii") + b":" + nonce.encode("ascii") + b"\n"
if os.write(1, marker) != len(marker):
    raise RuntimeError("incomplete pre-exec control frame")
os.execv(command[0], command)
'''


class BehaviorCorpusError(ValueError):
    """Raised when a corpus is invalid or an execution cannot be verified."""


class ExactExecutorProfileMismatch(BehaviorCorpusError):
    """A well-formed executor differs from a checked exact profile."""


class _ControlOperationUncertain(BehaviorCorpusError):
    """A spawned control client failed before command settlement was known."""


def _add_exception_note(error: BaseException, note: str) -> None:
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(note)
        return
    existing = getattr(error, "_behavior_corpus_notes", ())
    setattr(error, "_behavior_corpus_notes", (*existing, note))


def behavior_error_notes(error: BaseException) -> tuple[str, ...]:
    """Return deterministic secondary diagnostics without changing the primary text."""

    result: list[str] = []
    for source in (
        getattr(error, "__notes__", ()),
        getattr(error, "_behavior_corpus_notes", ()),
    ):
        if isinstance(source, (list, tuple)):
            result.extend(note for note in source if isinstance(note, str))
    return tuple(result)


def _add_exception_note_no_throw(error: BaseException, note: str) -> None:
    """Best-effort bounded note attachment which never replaces *error*."""

    bounded = note[:16_384]
    try:
        _add_exception_note(error, bounded)
        return
    except BaseException:
        pass
    try:
        existing = getattr(error, "__notes__", ())
        if isinstance(existing, list) and bounded in existing:
            return
        BaseException.add_note(error, bounded)
        return
    except BaseException:
        pass
    try:
        existing_fallback = getattr(error, "_behavior_corpus_notes", ())
        object.__setattr__(
            error,
            "_behavior_corpus_notes",
            (*existing_fallback[:31], bounded),
        )
    except BaseException:
        pass


def _safe_exception_description(error: BaseException) -> str:
    try:
        detail = str(error)[:4096]
    except BaseException:
        detail = "<detail unavailable>"
    try:
        name = type(error).__name__
    except BaseException:
        name = "BaseException"
    return f"{name}: {detail}" if detail else name


@dataclass(frozen=True)
class _Limits:
    timeout_milliseconds: int
    stdout_bytes: int
    stderr_bytes: int
    artifact_bytes: int
    memory_bytes: int
    file_bytes: int
    open_files: int
    processes: int
    cpu_seconds: int
    workspace_bytes: int
    workspace_entries: int


@dataclass
class _RetentionBudget:
    remaining: int = MAX_RETAINED_BINARY_BYTES

    def retain(self, amount: int, label: str) -> None:
        if amount < 0 or amount > self.remaining:
            raise BehaviorCorpusError(
                f"{label} exceeds the aggregate retained-evidence byte limit"
            )
        self.remaining -= amount


@dataclass(frozen=True)
class _Normalization:
    identifier: str
    field: str
    runtime_path: str
    replacement: bytes


@dataclass(frozen=True)
class _Mount:
    kind: str
    source: str
    destination: str
    read_only: bool
    volume_nocopy: bool = False
    runtime_source: str | None = None


@dataclass
class _PreexecFrameReader:
    role: str
    nonce: str
    payload: bytearray

    def __init__(self, role: str, nonce: str) -> None:
        self.role = role
        self.nonce = nonce
        self.payload = bytearray()

    def feed(self, chunk: bytes) -> bool:
        if not chunk:
            return len(self.payload) == len(_preexec_frame(self.role, self.nonce))
        expected = _preexec_frame(self.role, self.nonce)
        self.payload.extend(chunk)
        if len(self.payload) > len(expected) or not expected.startswith(self.payload):
            raise BehaviorCorpusError(
                f"sandbox {self.role} emitted an invalid pre-exec frame"
            )
        return len(self.payload) == len(expected)


def _object(value: Any, path: str, fields: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BehaviorCorpusError(f"{path} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        details: list[str] = []
        if missing := sorted(expected - actual):
            details.append(f"missing {missing}")
        if unexpected := sorted(actual - expected):
            details.append(f"unexpected {unexpected}")
        raise BehaviorCorpusError(f"{path} has invalid fields: {', '.join(details)}")
    return value


def _array(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    maximum: int,
) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty array" if nonempty else "an array"
        raise BehaviorCorpusError(f"{path} must be {qualifier}")
    if len(value) > maximum:
        raise BehaviorCorpusError(f"{path} exceeds the limit of {maximum} entries")
    return value


def _string(
    value: Any,
    path: str,
    *,
    allow_empty: bool = False,
    maximum: int = MAX_TEXT_CHARACTERS,
) -> str:
    if (
        not isinstance(value, str)
        or "\x00" in value
        or (not allow_empty and not value)
        or len(value) > maximum
    ):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise BehaviorCorpusError(
            f"{path} must be {qualifier} without NUL bytes and at most "
            f"{maximum} characters"
        )
    return value


def _integer(value: Any, path: str, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise BehaviorCorpusError(
            f"{path} must be an integer between {minimum} and {maximum}"
        )
    return value


def _identifier(value: Any, path: str) -> str:
    text = _string(value, path, maximum=128)
    if _IDENTIFIER.fullmatch(text) is None:
        raise BehaviorCorpusError(f"{path} must be a lowercase kebab-case identifier")
    return text


def _sha256(value: Any, path: str) -> str:
    text = _string(value, path, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise BehaviorCorpusError(f"{path} must be a lowercase SHA-256 digest")
    return text


def _mode(value: Any, path: str) -> str:
    text = _string(value, path, maximum=5)
    if _MODE.fullmatch(text) is None:
        raise BehaviorCorpusError(
            f"{path} must be an exact three-digit permission mode without special bits"
        )
    return text


def _relative_path(value: Any, path: str) -> str:
    text = _string(value, path, maximum=4096)
    candidate = PurePosixPath(text)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or str(candidate) != text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise BehaviorCorpusError(f"{path} must be a normalized relative POSIX path")
    return text


def _absolute_path(value: Any, path: str) -> str:
    text = _string(value, path, maximum=4096)
    candidate = PurePosixPath(text)
    if (
        not candidate.is_absolute()
        or candidate == PurePosixPath("/")
        or text.startswith("//")
        or str(candidate) != text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise BehaviorCorpusError(f"{path} must be a normalized non-root absolute path")
    return text


def _decode_base64(value: Any, path: str, *, maximum: int) -> bytes:
    text = _string(value, path, allow_empty=True, maximum=(maximum * 4 // 3) + 8)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise BehaviorCorpusError(f"{path} must be canonical base64") from error
    if len(decoded) > maximum:
        raise BehaviorCorpusError(f"{path} exceeds the {maximum}-byte decoded limit")
    if base64.b64encode(decoded).decode("ascii") != text:
        raise BehaviorCorpusError(f"{path} must be canonical padded base64")
    return decoded


def _validate_blob(
    value: Any,
    path: str,
    *,
    maximum: int,
    extra_fields: Iterable[str] = (),
) -> tuple[dict[str, Any], bytes]:
    record = _object(value, path, {"bytes", "sha256", "base64", *extra_fields})
    expected_bytes = _integer(record["bytes"], f"{path}.bytes", minimum=0, maximum=maximum)
    expected_sha256 = _sha256(record["sha256"], f"{path}.sha256")
    payload = _decode_base64(record["base64"], f"{path}.base64", maximum=maximum)
    if len(payload) != expected_bytes:
        raise BehaviorCorpusError(f"{path}.bytes does not match decoded content")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BehaviorCorpusError(f"{path}.sha256 does not match decoded content")
    return record, payload


def _validate_placeholders(value: str, path: str) -> None:
    for match in _PLACEHOLDER.finditer(value):
        if match.group(1) not in _RUNTIME_PATHS:
            raise BehaviorCorpusError(
                f"{path} contains unknown runtime placeholder {{{match.group(1)}}}"
            )
    remainder = _PLACEHOLDER.sub("", value)
    if "{" in remainder or "}" in remainder:
        raise BehaviorCorpusError(f"{path} contains malformed runtime placeholders")


def _validate_environment(value: Any, path: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BehaviorCorpusError(f"{path} must be an object")
    if len(value) > MAX_ENVIRONMENT_VARIABLES:
        raise BehaviorCorpusError(
            f"{path} exceeds the limit of {MAX_ENVIRONMENT_VARIABLES} variables"
        )
    result: dict[str, str] = {}
    for name, raw_value in value.items():
        if not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None:
            raise BehaviorCorpusError(f"{path} contains an invalid variable name")
        text = _string(raw_value, f"{path}.{name}", allow_empty=True, maximum=4096)
        _validate_placeholders(text, f"{path}.{name}")
        result[name] = text
    if list(result) != sorted(result):
        raise BehaviorCorpusError(f"{path} keys must be sorted")
    return result


def _decode_json(payload: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BehaviorCorpusError(f"duplicate JSON object key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError as error:
        raise BehaviorCorpusError(f"{label} is not valid UTF-8: {error}") from error
    except json.JSONDecodeError as error:
        raise BehaviorCorpusError(f"{label} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise BehaviorCorpusError(f"{label} root must be an object")
    return value


def _validate_argv(value: Any, path: str) -> list[str]:
    arguments = _array(value, path, nonempty=True, maximum=MAX_ARGUMENTS)
    validated = [
        _string(
            argument,
            f"{path}[{index}]",
            allow_empty=True,
            maximum=MAX_HELPER_ARGUMENT_CHARACTERS,
        )
        for index, argument in enumerate(arguments)
    ]
    _absolute_path(validated[0], f"{path}[0]")
    return validated


def _validate_image_environment(value: Any, path: str) -> list[str]:
    entries = _array(
        value,
        path,
        maximum=MAX_ENVIRONMENT_VARIABLES,
    )
    names: list[str] = []
    for index, raw in enumerate(entries):
        entry_path = f"{path}[{index}]"
        entry = _string(raw, entry_path, maximum=MAX_TEXT_CHARACTERS)
        name, separator, _ = entry.partition("=")
        if not separator or _ENVIRONMENT_NAME.fullmatch(name) is None:
            raise BehaviorCorpusError(
                f"{entry_path} must be a NAME=value environment entry"
            )
        if name in _FORBIDDEN_PRELAUNCH_NAMES or name.startswith(
            _FORBIDDEN_PRELAUNCH_PREFIXES
        ):
            raise BehaviorCorpusError(
                f"{entry_path} uses forbidden prelaunch environment name {name}"
            )
        names.append(name)
    if len(names) != len(set(names)):
        raise BehaviorCorpusError(f"{path} contains duplicate variable names")
    return [str(entry) for entry in entries]


def _numeric_user(value: Any, path: str) -> tuple[int, int]:
    text = _string(value, path, maximum=32)
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", text)
    if match is None:
        raise BehaviorCorpusError(f"{path} must be a non-root numeric UID:GID")
    uid, gid = (int(part) for part in match.groups())
    if uid > 2_147_483_647 or gid > 2_147_483_647:
        raise BehaviorCorpusError(f"{path} UID and GID exceed the supported range")
    return uid, gid


def _read_regular_snapshot(
    path: Path,
    label: str,
    maximum: int,
    *,
    require_executable: bool = False,
) -> bytes:
    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BehaviorCorpusError(f"{label} is not a non-symlink regular file: {path}")
        if require_executable and not (before.st_mode & 0o111):
            raise BehaviorCorpusError(f"{label} is not executable: {path}")
        if before.st_size > maximum:
            raise BehaviorCorpusError(f"{label} exceeds the {maximum}-byte limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        grew = bool(os.read(descriptor, 1))
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or remaining or grew:
            raise BehaviorCorpusError(f"{label} changed while it was read")
        return b"".join(chunks)
    except BehaviorCorpusError:
        raise
    except OSError as error:
        raise BehaviorCorpusError(f"cannot read {label} {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _limits(value: Any) -> _Limits:
    path = "corpus.limits"
    record = _object(
        value,
        path,
        {
            "timeoutMilliseconds",
            "stdoutBytes",
            "stderrBytes",
            "artifactBytes",
            "memoryBytes",
            "fileBytes",
            "openFiles",
            "processes",
            "cpuSeconds",
            "workspaceBytes",
            "workspaceEntries",
        },
    )
    limits = _Limits(
        timeout_milliseconds=_integer(
            record["timeoutMilliseconds"],
            f"{path}.timeoutMilliseconds",
            minimum=1,
            maximum=30_000,
        ),
        stdout_bytes=_integer(
            record["stdoutBytes"], f"{path}.stdoutBytes", minimum=0, maximum=MAX_CAPTURE_BYTES
        ),
        stderr_bytes=_integer(
            record["stderrBytes"], f"{path}.stderrBytes", minimum=0, maximum=MAX_CAPTURE_BYTES
        ),
        artifact_bytes=_integer(
            record["artifactBytes"], f"{path}.artifactBytes", minimum=0, maximum=MAX_CAPTURE_BYTES
        ),
        memory_bytes=_integer(
            record["memoryBytes"],
            f"{path}.memoryBytes",
            minimum=64 * 1024 * 1024,
            maximum=8 * 1024 * 1024 * 1024,
        ),
        file_bytes=_integer(
            record["fileBytes"], f"{path}.fileBytes", minimum=1, maximum=MAX_CAPTURE_BYTES
        ),
        open_files=_integer(record["openFiles"], f"{path}.openFiles", minimum=16, maximum=4096),
        processes=_integer(record["processes"], f"{path}.processes", minimum=1, maximum=4096),
        cpu_seconds=_integer(record["cpuSeconds"], f"{path}.cpuSeconds", minimum=1, maximum=30),
        workspace_bytes=_integer(
            record["workspaceBytes"],
            f"{path}.workspaceBytes",
            minimum=1,
            maximum=MAX_WORKSPACE_BYTES,
        ),
        workspace_entries=_integer(
            record["workspaceEntries"],
            f"{path}.workspaceEntries",
            minimum=1,
            maximum=MAX_WORKSPACE_ENTRIES,
        ),
    )
    if limits.workspace_bytes > limits.memory_bytes:
        raise BehaviorCorpusError(
            "corpus.limits.workspaceBytes must not exceed memoryBytes"
        )
    if limits.file_bytes > limits.workspace_bytes:
        raise BehaviorCorpusError(
            "corpus.limits.fileBytes must not exceed workspaceBytes"
        )
    if limits.artifact_bytes > limits.workspace_bytes:
        raise BehaviorCorpusError(
            "corpus.limits.artifactBytes must not exceed workspaceBytes"
        )
    if limits.artifact_bytes > limits.file_bytes:
        raise BehaviorCorpusError(
            "corpus.limits.artifactBytes must not exceed fileBytes"
        )
    return limits


def validate_corpus(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the closed v1 format and all cross-record invariants."""

    root = _object(
        value,
        "corpus",
        {
            "schemaVersion",
            "scope",
            "id",
            "executable",
            "sandbox",
            "environment",
            "limits",
            "directories",
            "normalizations",
            "cases",
        },
    )
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise BehaviorCorpusError("corpus.schemaVersion must be the integer 1")
    if root["scope"] not in {"fixture", "production"}:
        raise BehaviorCorpusError("corpus.scope must be fixture or production")
    _identifier(root["id"], "corpus.id")
    executable = _object(root["executable"], "corpus.executable", {"bytes", "sha256"})
    _integer(
        executable["bytes"],
        "corpus.executable.bytes",
        minimum=1,
        maximum=MAX_EXECUTABLE_BYTES,
    )
    _sha256(executable["sha256"], "corpus.executable.sha256")
    sandbox = _object(
        root["sandbox"],
        "corpus.sandbox",
        {
            "backend",
            "resourcePolicyVersion",
            "oomScoreAdjustment",
            "imageDigest",
            "platform",
            "isolation",
            "imageEnvironment",
            "preExecArgv",
            "environmentLauncher",
            "keeperArgv",
            "setupArgv",
            "collectorArgv",
            "targetUser",
            "controlClient",
            "engineProfile",
        },
    )
    if sandbox["backend"] != "oci-container-v1":
        raise BehaviorCorpusError(
            "corpus.sandbox.backend must be oci-container-v1"
        )
    if (
        isinstance(sandbox["resourcePolicyVersion"], bool)
        or sandbox["resourcePolicyVersion"] != OCI_HOST_RESOURCE_POLICY_VERSION
    ):
        raise BehaviorCorpusError(
            "corpus.sandbox.resourcePolicyVersion must select HostConfig/cgroup "
            f"policy v{OCI_HOST_RESOURCE_POLICY_VERSION}"
        )
    if (
        isinstance(sandbox["oomScoreAdjustment"], bool)
        or sandbox["oomScoreAdjustment"] != OOM_SCORE_ADJUSTMENT
    ):
        raise BehaviorCorpusError(
            "corpus.sandbox.oomScoreAdjustment must select the exact "
            f"policy value {OOM_SCORE_ADJUSTMENT}"
        )
    image_digest = _string(
        sandbox["imageDigest"], "corpus.sandbox.imageDigest", maximum=71
    )
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise BehaviorCorpusError(
            "corpus.sandbox.imageDigest must be an immutable SHA-256 image ID"
        )
    platform_name = _string(
        sandbox["platform"], "corpus.sandbox.platform", maximum=64
    )
    if _PLATFORM.fullmatch(platform_name) is None:
        raise BehaviorCorpusError(
            "corpus.sandbox.platform must be a normalized os/architecture pair"
        )
    if sandbox["isolation"] != (
        "network-none-readonly-root-cap-drop-all-no-new-privileges-"
        "pid-ipc-private-cgroup-bounds"
    ):
        raise BehaviorCorpusError(
            "corpus.sandbox.isolation must select the complete v1 isolation profile"
        )
    _absolute_path(
        sandbox["environmentLauncher"], "corpus.sandbox.environmentLauncher"
    )
    _validate_image_environment(
        sandbox["imageEnvironment"], "corpus.sandbox.imageEnvironment"
    )
    _validate_argv(sandbox["preExecArgv"], "corpus.sandbox.preExecArgv")
    _validate_argv(sandbox["keeperArgv"], "corpus.sandbox.keeperArgv")
    _validate_argv(sandbox["setupArgv"], "corpus.sandbox.setupArgv")
    _validate_argv(sandbox["collectorArgv"], "corpus.sandbox.collectorArgv")
    _numeric_user(sandbox["targetUser"], "corpus.sandbox.targetUser")
    control_client = _object(
        sandbox["controlClient"],
        "corpus.sandbox.controlClient",
        {"bytes", "sha256", "version"},
    )
    _integer(
        control_client["bytes"],
        "corpus.sandbox.controlClient.bytes",
        minimum=1,
        maximum=MAX_EXECUTABLE_BYTES,
    )
    _sha256(
        control_client["sha256"], "corpus.sandbox.controlClient.sha256"
    )
    _string(
        control_client["version"],
        "corpus.sandbox.controlClient.version",
        maximum=512,
    )
    engine_path = "corpus.sandbox.engineProfile"
    engine = _object(
        sandbox["engineProfile"],
        engine_path,
        {
            "product",
            "serverVersion",
            "serverCommit",
            "apiVersion",
            "operatingSystem",
            "architecture",
            "kernelVersion",
            "componentsSha256",
            "cgroupVersion",
            "cgroupDriver",
            "storageDriver",
            "securityOptions",
            "containerRuntime",
            "containerRuntimePath",
            "containerRuntimeVersion",
            "containerRuntimeCommit",
            "containerRuntimeFeaturesSha256",
            "volumePlugin",
        },
    )
    for field in (
        "product",
        "serverVersion",
        "serverCommit",
        "kernelVersion",
        "cgroupDriver",
        "storageDriver",
        "containerRuntime",
        "containerRuntimePath",
        "containerRuntimeVersion",
        "containerRuntimeCommit",
        "volumePlugin",
    ):
        _string(engine[field], f"{engine_path}.{field}", maximum=256)
    api_version = _string(
        engine["apiVersion"], f"{engine_path}.apiVersion", maximum=16
    )
    if _API_VERSION.fullmatch(api_version) is None:
        raise BehaviorCorpusError(f"{engine_path}.apiVersion is invalid")
    if engine["operatingSystem"] != "linux":
        raise BehaviorCorpusError(
            f"{engine_path}.operatingSystem must be linux"
        )
    _string(
        engine["architecture"], f"{engine_path}.architecture", maximum=64
    )
    _integer(
        engine["cgroupVersion"],
        f"{engine_path}.cgroupVersion",
        minimum=2,
        maximum=2,
    )
    _sha256(
        engine["componentsSha256"],
        f"{engine_path}.componentsSha256",
    )
    _sha256(
        engine["containerRuntimeFeaturesSha256"],
        f"{engine_path}.containerRuntimeFeaturesSha256",
    )
    options = _array(
        engine["securityOptions"],
        f"{engine_path}.securityOptions",
        nonempty=True,
        maximum=32,
    )
    option_names = [
        _string(
            option,
            f"{engine_path}.securityOptions[{index}]",
            maximum=256,
        )
        for index, option in enumerate(options)
    ]
    if option_names != sorted(set(option_names)):
        raise BehaviorCorpusError(
            f"{engine_path}.securityOptions must be sorted and unique"
        )
    required_options = {
        "name=cgroupns",
        "name=rootless",
        "name=seccomp,profile=builtin",
    }
    if not required_options.issubset(option_names):
        raise BehaviorCorpusError(
            f"{engine_path}.securityOptions omits a mandatory isolation option"
        )
    if engine["volumePlugin"] != "local":
        raise BehaviorCorpusError(f"{engine_path}.volumePlugin must be local")
    environment = _object(
        root["environment"], "corpus.environment", {"clearInherited", "variables"}
    )
    if environment["clearInherited"] is not True:
        raise BehaviorCorpusError("corpus.environment.clearInherited must be true")
    _validate_environment(environment["variables"], "corpus.environment.variables")
    limits = _limits(root["limits"])

    directories = _array(
        root["directories"], "corpus.directories", maximum=MAX_INPUTS_PER_CASE
    )
    normalized_directories = [
        _relative_path(item, f"corpus.directories[{index}]")
        for index, item in enumerate(directories)
    ]
    if normalized_directories != sorted(set(normalized_directories)):
        raise BehaviorCorpusError("corpus.directories must be sorted and unique")
    required_directories = set(normalized_directories)
    for relative in normalized_directories:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            required_directories.add(parent.as_posix())
            parent = parent.parent

    normalizations = _array(
        root["normalizations"], "corpus.normalizations", maximum=64
    )
    normalization_fields: dict[str, str] = {}
    for index, raw in enumerate(normalizations):
        path = f"corpus.normalizations[{index}]"
        record = _object(
            raw,
            path,
            {"id", "field", "operation", "runtimePath", "replacement"},
        )
        identifier = _identifier(record["id"], f"{path}.id")
        if identifier in normalization_fields:
            raise BehaviorCorpusError(f"duplicate normalization id: {identifier}")
        if record["field"] not in _STREAM_FIELDS:
            raise BehaviorCorpusError(f"{path}.field must be stdout or stderr")
        if record["operation"] != "replace-runtime-path":
            raise BehaviorCorpusError(f"{path}.operation must be replace-runtime-path")
        if record["runtimePath"] not in _RUNTIME_PATHS:
            raise BehaviorCorpusError(f"{path}.runtimePath must be workspace or oracle")
        replacement = _string(
            record["replacement"], f"{path}.replacement", maximum=256
        ).encode("utf-8")
        if b"\x00" in replacement:
            raise BehaviorCorpusError(f"{path}.replacement must not contain NUL")
        normalization_fields[identifier] = record["field"]

    cases = _array(root["cases"], "corpus.cases", nonempty=True, maximum=MAX_CASES)
    case_ids: list[str] = []
    all_categories: set[str] = set()
    for case_index, raw_case in enumerate(cases):
        case_path = f"corpus.cases[{case_index}]"
        case = _object(
            raw_case,
            case_path,
            {
                "id",
                "categories",
                "arguments",
                "environment",
                "stdin",
                "inputs",
                "expected",
            },
        )
        case_id = _identifier(case["id"], f"{case_path}.id")
        case_ids.append(case_id)
        categories = _array(
            case["categories"], f"{case_path}.categories", nonempty=True, maximum=32
        )
        category_names = [
            _identifier(item, f"{case_path}.categories[{index}]")
            for index, item in enumerate(categories)
        ]
        if category_names != sorted(set(category_names)):
            raise BehaviorCorpusError(f"{case_path}.categories must be sorted and unique")
        all_categories.update(category_names)
        if len(all_categories) > MAX_CATEGORIES:
            raise BehaviorCorpusError(
                f"corpus categories exceed the global limit of {MAX_CATEGORIES}"
            )
        arguments = _array(
            case["arguments"], f"{case_path}.arguments", maximum=MAX_ARGUMENTS
        )
        for argument_index, argument in enumerate(arguments):
            argument_path = f"{case_path}.arguments[{argument_index}]"
            text = _string(argument, argument_path, allow_empty=True, maximum=4096)
            _validate_placeholders(text, argument_path)
        _validate_environment(case["environment"], f"{case_path}.environment")
        _validate_blob(
            case["stdin"], f"{case_path}.stdin", maximum=MAX_INPUT_BYTES_PER_CASE
        )

        inputs = _array(
            case["inputs"], f"{case_path}.inputs", maximum=MAX_INPUTS_PER_CASE
        )
        input_paths: list[str] = []
        total_input_bytes = 0
        for input_index, raw_input in enumerate(inputs):
            input_path = f"{case_path}.inputs[{input_index}]"
            record, payload = _validate_blob(
                raw_input,
                input_path,
                maximum=MAX_INPUT_BYTES_PER_CASE,
                extra_fields={"path", "executable"},
            )
            relative = _relative_path(record["path"], f"{input_path}.path")
            if not isinstance(record["executable"], bool):
                raise BehaviorCorpusError(f"{input_path}.executable must be boolean")
            if len(payload) > limits.file_bytes:
                raise BehaviorCorpusError(
                    f"{input_path} exceeds corpus.limits.fileBytes"
                )
            input_paths.append(relative)
            total_input_bytes += len(payload)
        if total_input_bytes > MAX_INPUT_BYTES_PER_CASE:
            raise BehaviorCorpusError(
                f"{case_path}.inputs exceed the {MAX_INPUT_BYTES_PER_CASE}-byte case limit"
            )
        if total_input_bytes > limits.workspace_bytes:
            raise BehaviorCorpusError(
                f"{case_path}.inputs exceed corpus.limits.workspaceBytes"
            )
        if input_paths != sorted(set(input_paths)):
            raise BehaviorCorpusError(f"{case_path}.inputs paths must be sorted and unique")
        case_directories = set(required_directories)
        for relative in input_paths:
            parent = PurePosixPath(relative).parent
            while str(parent) != ".":
                case_directories.add(parent.as_posix())
                parent = parent.parent
        if set(input_paths) & case_directories:
            raise BehaviorCorpusError(
                f"{case_path}.inputs conflict with required directories"
            )
        if len(case_directories) + len(input_paths) > limits.workspace_entries:
            raise BehaviorCorpusError(
                f"{case_path}.inputs exceed corpus.limits.workspaceEntries"
            )

        expected = _object(
            case["expected"],
            f"{case_path}.expected",
            {"exitCode", "stdout", "stderr", "artifacts"},
        )
        _integer(
            expected["exitCode"],
            f"{case_path}.expected.exitCode",
            minimum=0,
            maximum=255,
        )
        for field in ("stdout", "stderr"):
            stream_path = f"{case_path}.expected.{field}"
            record, _ = _validate_blob(
                expected[field],
                stream_path,
                maximum=(
                    limits.stdout_bytes
                    if field == "stdout"
                    else limits.stderr_bytes
                ),
                extra_fields={"normalizations"},
            )
            applied = _array(
                record["normalizations"],
                f"{stream_path}.normalizations",
                maximum=64,
            )
            applied_ids = [
                _identifier(item, f"{stream_path}.normalizations[{index}]")
                for index, item in enumerate(applied)
            ]
            if len(applied_ids) != len(set(applied_ids)):
                raise BehaviorCorpusError(
                    f"{stream_path}.normalizations must be unique"
                )
            for normalization_id in applied_ids:
                if normalization_fields.get(normalization_id) != field:
                    raise BehaviorCorpusError(
                        f"{stream_path} references an unknown or wrong-field "
                        f"normalization: {normalization_id}"
                    )

        artifacts = _array(
            expected["artifacts"],
            f"{case_path}.expected.artifacts",
            maximum=MAX_ARTIFACTS_PER_CASE,
        )
        artifact_paths: list[str] = []
        for artifact_index, raw_artifact in enumerate(artifacts):
            artifact_path = f"{case_path}.expected.artifacts[{artifact_index}]"
            artifact = _object(
                raw_artifact,
                artifact_path,
                {"path", "present", "bytes", "sha256", "base64", "mode"},
            )
            relative = _relative_path(artifact["path"], f"{artifact_path}.path")
            if not isinstance(artifact["present"], bool):
                raise BehaviorCorpusError(f"{artifact_path}.present must be boolean")
            artifact_paths.append(relative)
            if artifact["present"]:
                _, _ = _validate_blob(
                    {
                        "bytes": artifact["bytes"],
                        "sha256": artifact["sha256"],
                        "base64": artifact["base64"],
                    },
                    artifact_path,
                    maximum=limits.artifact_bytes,
                )
                observed_mode = _mode(artifact["mode"], f"{artifact_path}.mode")
                if int(observed_mode, 8) & 0o400 == 0:
                    raise BehaviorCorpusError(
                        f"{artifact_path}.mode must keep the owner-readable bit"
                    )
            elif any(
                artifact[field] is not None
                for field in ("bytes", "sha256", "base64", "mode")
            ):
                raise BehaviorCorpusError(
                    f"{artifact_path} absent observations must use null data fields"
                )
        if artifact_paths != sorted(set(artifact_paths)):
            raise BehaviorCorpusError(
                f"{case_path}.expected.artifacts paths must be sorted and unique"
            )
        overlap = set(input_paths) & set(artifact_paths)
        if overlap:
            raise BehaviorCorpusError(
                f"{case_path} input and artifact paths overlap: {sorted(overlap)}"
            )
        if set(artifact_paths) & case_directories:
            raise BehaviorCorpusError(
                f"{case_path}.expected artifacts conflict with required directories"
            )

    if case_ids != sorted(set(case_ids)):
        raise BehaviorCorpusError("corpus.cases ids must be sorted and unique")
    return root


def load_corpus(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_snapshot(path, "behavior corpus", MAX_CORPUS_BYTES)
    corpus = validate_corpus(_decode_json(payload, "behavior corpus"))
    if payload != corpus_json_bytes(corpus):
        raise BehaviorCorpusError(
            "behavior corpus must use canonical sorted, indented JSON with one final newline"
        )
    return corpus, payload


def _expand(value: str, runtime_paths: Mapping[str, Path]) -> str:
    result = value
    for name in sorted(runtime_paths):
        result = result.replace("{" + name + "}", os.fspath(runtime_paths[name]))
    return result


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
        view = memoryview(payload)
        offset = 0
        try:
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise BehaviorCorpusError(f"could not finish staging {path.name}")
                offset += written
        finally:
            view.release()
    except OSError as error:
        raise BehaviorCorpusError(f"cannot stage {path.name}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _resource_limiter(limits: _Limits) -> Any:
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(
            resource.RLIMIT_AS,
            (limits.memory_bytes, limits.memory_bytes),
        )
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.file_bytes, limits.file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
        resource.setrlimit(resource.RLIMIT_NPROC, (limits.processes, limits.processes))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))

    return apply


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as final_error:
            raise BehaviorCorpusError(
                "child process did not terminate after SIGKILL"
            ) from final_error


def _execute_bounded(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    stdin: bytes,
    limits: _Limits,
    apply_process_limits: bool = True,
) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=_resource_limiter(limits) if apply_process_limits else None,
        )
    except OSError as error:
        raise BehaviorCorpusError(f"cannot start corpus case: {error}") from error
    selector: selectors.BaseSelector | None = None
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    capture_limits = {"stdout": limits.stdout_bytes, "stderr": limits.stderr_bytes}
    stdin_offset = 0
    deadline = time.monotonic() + (limits.timeout_milliseconds / 1000)
    reaped = False
    primary_error: BaseException | None = None
    try:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise BehaviorCorpusError("corpus case did not expose all requested pipes")
        descriptors = {
            process.stdin.fileno(): "stdin",
            process.stdout.fileno(): "stdout",
            process.stderr.fileno(): "stderr",
        }
        for descriptor in descriptors:
            os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        if stdin:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BehaviorCorpusError(
                    f"corpus case exceeded {limits.timeout_milliseconds} ms"
                )
            events = selector.select(remaining)
            if not events:
                raise BehaviorCorpusError(
                    f"corpus case exceeded {limits.timeout_milliseconds} ms"
                )
            for key, _ in events:
                field = key.data
                event_pipe = cast(BinaryIO, key.fileobj)
                descriptor = event_pipe.fileno()
                if field == "stdin":
                    try:
                        written = os.write(descriptor, stdin[stdin_offset : stdin_offset + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                        stdin_offset = len(stdin)
                    stdin_offset += written
                    if stdin_offset >= len(stdin):
                        selector.unregister(event_pipe)
                        event_pipe.close()
                    continue
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(event_pipe)
                    event_pipe.close()
                    continue
                captures[field].extend(chunk)
                if len(captures[field]) > capture_limits[field]:
                    raise BehaviorCorpusError(
                        f"corpus case {field} exceeded {capture_limits[field]} bytes"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BehaviorCorpusError(
                f"corpus case exceeded {limits.timeout_milliseconds} ms"
            )
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise BehaviorCorpusError(
                "corpus case exceeded a configured process resource bound"
            ) from error
        reaped = True
    except BaseException as error:
        if isinstance(error, (BehaviorCorpusError, KeyboardInterrupt, SystemExit)):
            primary_error = error
            raise
        primary_error = BehaviorCorpusError(f"corpus case I/O failed: {error}")
        raise primary_error from error
    finally:
        cleanup_errors: list[str] = []
        if not reaped:
            try:
                _terminate_group(process)
                reaped = True
            except BaseException as error:
                cleanup_errors.append(f"could not terminate child process: {error}")
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                cleanup_errors.append(f"could not close selector: {error}")
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except BaseException as error:
                    cleanup_errors.append(f"could not close child pipe: {error}")
        if cleanup_errors:
            detail = "; ".join(cleanup_errors)
            if primary_error is not None:
                note = f"child process cleanup also failed: {detail}"
                _add_exception_note(primary_error, note)
            else:
                raise BehaviorCorpusError(detail)
    if return_code < 0:
        raise BehaviorCorpusError(f"corpus case terminated by signal {-return_code}")
    return return_code, bytes(captures["stdout"]), bytes(captures["stderr"])


def _container_runtime_environment(
    value: Mapping[str, str] | None,
) -> dict[str, str]:
    supplied = {} if value is None else dict(value)
    if set(supplied) - {"DOCKER_HOST"}:
        raise BehaviorCorpusError(
            "container runtime environment may contain only DOCKER_HOST"
        )
    result = {
        "DOCKER_CONFIG": "/nonexistent",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if "DOCKER_HOST" in supplied:
        host = _string(
            supplied["DOCKER_HOST"], "container runtime DOCKER_HOST", maximum=4096
        )
        if not host.startswith("unix://") or not Path(host[7:]).is_absolute():
            raise BehaviorCorpusError(
                "container runtime DOCKER_HOST must be an absolute unix:// socket"
            )
        result["DOCKER_HOST"] = host
    return result


def _control_limits() -> _Limits:
    return _Limits(
        timeout_milliseconds=CONTROL_OPERATION_TIMEOUT_MILLISECONDS,
        stdout_bytes=CONTROL_CAPTURE_BYTES,
        stderr_bytes=CONTROL_CAPTURE_BYTES,
        artifact_bytes=0,
        memory_bytes=512 * 1024 * 1024,
        file_bytes=CONTROL_CAPTURE_BYTES,
        open_files=128,
        processes=64,
        cpu_seconds=30,
        workspace_bytes=1,
        workspace_entries=1,
    )


def _run_control_command_result(
    arguments: Sequence[str],
    environment: Mapping[str, str],
    label: str,
) -> tuple[int, bytes, bytes]:
    try:
        return _execute_bounded(
            arguments,
            cwd=Path("/"),
            environment=environment,
            stdin=b"",
            limits=_control_limits(),
            apply_process_limits=False,
        )
    except BehaviorCorpusError as error:
        raise _ControlOperationUncertain(f"cannot run {label}: {error}") from error


def _run_control_command(
    arguments: Sequence[str],
    environment: Mapping[str, str],
    label: str,
) -> bytes:
    return_code, stdout, stderr = _run_control_command_result(
        arguments, environment, label
    )
    if return_code != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        raise BehaviorCorpusError(f"{label} failed: {detail}")
    return stdout


def _snapshot_control_client(runtime: Path) -> bytes:
    if not runtime.is_absolute() or Path(os.path.normpath(runtime)) != runtime:
        raise BehaviorCorpusError(
            "container runtime client path must be normalized and absolute"
        )
    return _read_regular_snapshot(
        runtime,
        "container runtime client",
        MAX_EXECUTABLE_BYTES,
        require_executable=True,
    )


def _engine_components_sha256(value: Any) -> str:
    components = _array(
        value, "container engine components", nonempty=True, maximum=64
    )
    normalized: list[dict[str, Any]] = []
    names: list[str] = []
    for index, raw_component in enumerate(components):
        path = f"container engine components[{index}]"
        if not isinstance(raw_component, dict):
            raise BehaviorCorpusError(f"{path} must be an object")
        name = _string(raw_component.get("Name"), f"{path}.Name", maximum=256)
        version = _string(
            raw_component.get("Version"), f"{path}.Version", maximum=256
        )
        details = raw_component.get("Details")
        if not isinstance(details, dict) or len(details) > 64:
            raise BehaviorCorpusError(f"{path}.Details must be an object")
        stable_details: dict[str, str] = {}
        for key, raw_detail in details.items():
            detail_name = _string(key, f"{path}.Details key", maximum=256)
            detail_value = _string(
                raw_detail,
                f"{path}.Details.{detail_name}",
                allow_empty=True,
                maximum=4096,
            )
            if (name, detail_name) not in _COMPONENT_DETAIL_EXCLUSIONS:
                stable_details[detail_name] = detail_value
        names.append(name)
        normalized.append(
            {
                "name": name,
                "version": version,
                "details": dict(sorted(stable_details.items())),
            }
        )
    if len(names) != len(set(names)):
        raise BehaviorCorpusError("container engine components contain duplicate names")
    normalized.sort(key=lambda component: component["name"])
    payload = (
        json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _verify_oci_runtime(
    runtime: Path,
    environment: Mapping[str, str],
    sandbox: Mapping[str, Any],
) -> None:
    runtime_payload = _read_regular_snapshot(
        runtime, "container runtime client", MAX_EXECUTABLE_BYTES
    )
    client = sandbox["controlClient"]
    if (
        len(runtime_payload) != client["bytes"]
        or hashlib.sha256(runtime_payload).hexdigest() != client["sha256"]
    ):
        raise BehaviorCorpusError(
            "container runtime client identity does not match the sandbox profile"
        )
    version = _run_control_command(
        [os.fspath(runtime), "--version"],
        environment,
        "container runtime client version inspection",
    )
    try:
        version_text = version.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BehaviorCorpusError("container runtime client version is not UTF-8") from error
    if version_text != client["version"]:
        raise BehaviorCorpusError(
            "container runtime client version does not match the sandbox profile"
        )

    engine_output = _run_control_command(
        [
            os.fspath(runtime),
            "version",
            "--format",
            "{{json .Server}}",
        ],
        environment,
        "container engine identity inspection",
    )
    try:
        engine_identity = json.loads(engine_output.decode("utf-8"))
        components = engine_identity["Components"]
        components_sha256 = _engine_components_sha256(components)
        engine_components = [
            component for component in components if component.get("Name") == "Engine"
        ]
        if len(engine_components) != 1:
            raise BehaviorCorpusError(
                "container engine identity must contain exactly one Engine component"
            )
        top_level_kernel = _string(
            engine_identity["KernelVersion"],
            "container engine KernelVersion",
            maximum=4096,
        )
        component_kernel = _string(
            engine_components[0]["Details"].get("KernelVersion"),
            "container engine Engine.Details.KernelVersion",
            maximum=4096,
        )
        if component_kernel != top_level_kernel:
            raise BehaviorCorpusError(
                "container engine KernelVersion disagrees with the Engine component"
            )
        runtime_components = [
            component
            for component in components
            if component.get("Name") == sandbox["engineProfile"]["containerRuntime"]
        ]
        if len(runtime_components) != 1:
            raise ValueError("expected one configured runtime component")
        runtime_component = runtime_components[0]
        actual_identity = {
            "product": engine_identity["Platform"]["Name"],
            "serverVersion": engine_identity["Version"],
            "serverCommit": engine_identity["GitCommit"],
            "apiVersion": engine_identity["ApiVersion"],
            "operatingSystem": engine_identity["Os"],
            "architecture": engine_identity["Arch"],
            "kernelVersion": top_level_kernel,
            "componentsSha256": components_sha256,
            "containerRuntimeVersion": runtime_component["Version"],
            "containerRuntimeCommit": runtime_component["Details"]["GitCommit"],
        }
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise BehaviorCorpusError(
            "container engine returned malformed identity information"
        ) from error
    if actual_identity["operatingSystem"] != "linux":
        raise BehaviorCorpusError(
            "container engine does not provide the required Linux isolation"
        )
    engine = sandbox["engineProfile"]
    for field, observed in actual_identity.items():
        if observed != engine[field]:
            raise ExactExecutorProfileMismatch(
                f"container engine {field} does not match the exact sandbox profile"
            )
    security_output = _run_control_command(
        [
            os.fspath(runtime),
            "info",
            "--format",
            (
                "{{json .SecurityOptions}}\n"
                "{{.CgroupVersion}}\n"
                "{{.CgroupDriver}}\n"
                "{{.Driver}}\n"
                "{{json .Plugins.Volume}}\n"
                "{{json .Runtimes}}"
            ),
        ],
        environment,
        "container engine security inspection",
    )
    try:
        (
            options_text,
            cgroup_text,
            cgroup_driver,
            storage_driver,
            volume_plugins_text,
            runtimes_text,
        ) = security_output.decode("utf-8").strip().splitlines()
        cgroup_version = int(cgroup_text)
        security_options = json.loads(options_text)
        volume_plugins = json.loads(volume_plugins_text)
        runtimes = json.loads(runtimes_text)
        runtime_record = runtimes[engine["containerRuntime"]]
        runtime_path = runtime_record["path"]
        runtime_status = runtime_record["status"]
        runtime_features = runtime_status[
            "org.opencontainers.runtime-spec.features"
        ]
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as error:
        raise BehaviorCorpusError(
            "container engine returned malformed security information"
        ) from error
    if (
        not isinstance(security_options, list)
        or not all(isinstance(option, str) for option in security_options)
        or not isinstance(volume_plugins, list)
        or not all(isinstance(plugin, str) for plugin in volume_plugins)
        or not isinstance(runtime_path, str)
        or not isinstance(runtime_features, str)
    ):
        raise BehaviorCorpusError("container engine security information is malformed")
    mandatory_security_options = {
        "name=cgroupns",
        "name=rootless",
        "name=seccomp,profile=builtin",
    }
    if cgroup_version != 2:
        raise BehaviorCorpusError("container engine does not provide the required cgroup v2 isolation")
    if not mandatory_security_options.issubset(security_options):
        raise BehaviorCorpusError(
            "container engine omits a mandatory sandbox security capability"
        )
    if engine["volumePlugin"] not in volume_plugins:
        raise BehaviorCorpusError(
            "container engine lacks the required authenticated workspace volume plugin"
        )
    actual_security = {
        "cgroupVersion": cgroup_version,
        "cgroupDriver": cgroup_driver,
        "storageDriver": storage_driver,
        "securityOptions": sorted(security_options),
        "containerRuntimePath": runtime_path,
        "containerRuntimeFeaturesSha256": hashlib.sha256(
            runtime_features.encode("utf-8")
        ).hexdigest(),
    }
    for field, observed in actual_security.items():
        if observed != engine[field]:
            raise ExactExecutorProfileMismatch(
                f"container engine {field} does not match the exact sandbox profile"
            )

    output = _run_control_command(
        [
            os.fspath(runtime),
            "image",
            "inspect",
            sandbox["imageDigest"],
        ],
        environment,
        "immutable sandbox image inspection",
    )
    try:
        image_records = json.loads(output.decode("utf-8"))
        if not isinstance(image_records, list) or len(image_records) != 1:
            raise ValueError("expected one image")
        image = image_records[0]
        image_id = image["Id"]
        platform_name = f"{image['Os']}/{image['Architecture']}"
        image_config = image["Config"]
        volumes = image_config.get("Volumes")
        image_environment = image_config.get("Env") or []
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise BehaviorCorpusError(
            "container runtime returned malformed sandbox image identity"
        ) from error
    if image_id != sandbox["imageDigest"]:
        raise BehaviorCorpusError(
            "local sandbox image ID does not match the corpus image digest"
        )
    if platform_name != sandbox["platform"]:
        raise BehaviorCorpusError(
            "local sandbox image platform does not match the corpus platform"
        )
    if image_environment != sandbox["imageEnvironment"]:
        raise BehaviorCorpusError(
            "sandbox image prelaunch environment does not match the corpus profile"
        )
    if volumes not in (None, {}):
        raise BehaviorCorpusError(
            "sandbox image declares implicit volumes outside the closed mount set"
        )


_MISSING_CONTAINER_MARKERS = (b"No such container", b"No such object")
_MISSING_VOLUME_MARKERS = (b"No such volume", b"no such volume")
_REQUIRED_MASKED_PATHS = {
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/timer_list",
    "/sys/firmware",
}
_REQUIRED_READONLY_PATHS = {"/proc/sys", "/proc/sysrq-trigger"}


def _verify_host_resource_defaults_v1(host: Mapping[str, Any]) -> None:
    for field, expected in _HOST_RESOURCE_DEFAULTS_V1.items():
        if (
            field not in host
            or type(host[field]) is not type(expected)
            or host[field] != expected
        ):
            raise BehaviorCorpusError(
                "container runtime changed canonical HostConfig resource field "
                f"{field} (policy v{OCI_HOST_RESOURCE_POLICY_VERSION})"
            )
    for field, expected in _OPTIONAL_HOST_RESOURCE_DEFAULTS_V1.items():
        if field in host and (
            type(host[field]) is not type(expected) or host[field] != expected
        ):
            raise BehaviorCorpusError(
                "container runtime changed canonical optional HostConfig resource field "
                f"{field} (policy v{OCI_HOST_RESOURCE_POLICY_VERSION})"
            )


def _is_missing(stderr: bytes, markers: Sequence[bytes]) -> bool:
    return any(marker in stderr for marker in markers)


def _remember_cleanup_error(errors: list[str], error: object) -> None:
    if len(errors) < 8:
        errors.append(str(error)[:4096])


def _remove_container(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str | None,
    container_name: str,
    *,
    settle_until: float | None = None,
) -> None:
    references = list(dict.fromkeys(filter(None, (container_id, container_name))))
    errors: list[str] = []
    consecutive_post_settlement_absent = 0
    settlement = time.monotonic() if settle_until is None else settle_until
    required_absent = 2 if container_id is None else 1
    post_settlement_attempts = 0
    while post_settlement_attempts < 5:
        for reference in references:
            try:
                return_code, _, stderr = _run_control_command_result(
                    [os.fspath(runtime), "rm", "--force", reference],
                    environment,
                    "sandbox container cleanup",
                )
                if return_code != 0 and not _is_missing(
                    stderr, _MISSING_CONTAINER_MARKERS
                ):
                    _remember_cleanup_error(
                        errors, stderr.decode("utf-8", "replace").strip()
                    )
            except BehaviorCorpusError as error:
                _remember_cleanup_error(errors, error)
        absent = True
        for reference in references:
            try:
                return_code, _, stderr = _run_control_command_result(
                    [os.fspath(runtime), "container", "inspect", reference],
                    environment,
                    "sandbox container cleanup inspection",
                )
            except BehaviorCorpusError as error:
                _remember_cleanup_error(errors, error)
                absent = False
                continue
            if return_code == 0 or not _is_missing(
                stderr, _MISSING_CONTAINER_MARKERS
            ):
                absent = False
        if absent:
            if time.monotonic() >= settlement:
                consecutive_post_settlement_absent += 1
            if consecutive_post_settlement_absent >= required_absent:
                return
        else:
            consecutive_post_settlement_absent = 0
        if time.monotonic() >= settlement:
            post_settlement_attempts += 1
        time.sleep(0.25 if time.monotonic() < settlement else 0.05)
    detail = "; ".join(item for item in errors if item)
    raise BehaviorCorpusError(
        "container runtime did not prove the sandbox container is absent"
        + (f": {detail}" if detail else "")
    )


def _remove_volume(
    runtime: Path,
    environment: Mapping[str, str],
    volume_name: str,
    *,
    settle_until: float | None = None,
) -> None:
    errors: list[str] = []
    consecutive_post_settlement_absent = 0
    settlement = time.monotonic() if settle_until is None else settle_until
    post_settlement_attempts = 0
    while post_settlement_attempts < 5:
        try:
            return_code, _, stderr = _run_control_command_result(
                [os.fspath(runtime), "volume", "rm", "--force", volume_name],
                environment,
                "sandbox volume cleanup",
            )
            if return_code != 0 and not _is_missing(stderr, _MISSING_VOLUME_MARKERS):
                _remember_cleanup_error(
                    errors, stderr.decode("utf-8", "replace").strip()
                )
        except BehaviorCorpusError as error:
            _remember_cleanup_error(errors, error)
        inspected_absent = False
        try:
            return_code, _, stderr = _run_control_command_result(
                [os.fspath(runtime), "volume", "inspect", volume_name],
                environment,
                "sandbox volume cleanup inspection",
            )
        except BehaviorCorpusError as error:
            _remember_cleanup_error(errors, error)
        else:
            inspected_absent = return_code != 0 and _is_missing(
                stderr, _MISSING_VOLUME_MARKERS
            )
        if inspected_absent:
            if time.monotonic() >= settlement:
                consecutive_post_settlement_absent += 1
            if consecutive_post_settlement_absent >= 2:
                return
        else:
            consecutive_post_settlement_absent = 0
        if time.monotonic() >= settlement:
            post_settlement_attempts += 1
        time.sleep(0.25 if time.monotonic() < settlement else 0.05)
    detail = "; ".join(item for item in errors if item)
    raise BehaviorCorpusError(
        "container runtime did not prove the sandbox volume is absent"
        + (f": {detail}" if detail else "")
    )


def _create_workspace_volume(
    runtime: Path,
    environment: Mapping[str, str],
    volume_name: str,
    limits: _Limits,
    target_uid: int,
    target_gid: int,
    *,
    publication_settled: Callable[[], None] | None = None,
) -> str:
    option = (
        f"size={limits.workspace_bytes},nr_inodes={limits.workspace_entries},"
        f"nosuid,nodev,uid={target_uid},gid={target_gid},mode=0700"
    )
    output = _run_control_command(
        [
            os.fspath(runtime),
            "volume",
            "create",
            "--driver=local",
            "--opt=type=tmpfs",
            "--opt=device=tmpfs",
            f"--opt=o={option}",
            volume_name,
        ],
        environment,
        "bounded workspace volume creation",
    )
    if publication_settled is not None:
        publication_settled()
    try:
        returned_name = output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BehaviorCorpusError("container runtime returned a malformed volume name") from error
    if returned_name != volume_name:
        raise BehaviorCorpusError("container runtime changed the workspace volume name")
    payload = _run_control_command(
        [os.fspath(runtime), "volume", "inspect", volume_name],
        environment,
        "bounded workspace volume inspection",
    )
    try:
        records = json.loads(payload.decode("utf-8"))
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("expected one volume")
        record = records[0]
        mountpoint = record["Mountpoint"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise BehaviorCorpusError("container runtime returned malformed volume metadata") from error
    expected_options = {"type": "tmpfs", "device": "tmpfs", "o": option}
    if (
        record.get("Name") != volume_name
        or record.get("Driver") != "local"
        or record.get("Scope") != "local"
        or record.get("Options") != expected_options
        or record.get("Labels") not in (None, {})
        or not isinstance(mountpoint, str)
        or not Path(mountpoint).is_absolute()
    ):
        raise BehaviorCorpusError(
            "container runtime did not enforce the exact bounded tmpfs volume"
        )
    return mountpoint


def _mount_argument(mount: _Mount) -> str:
    options = [f"type={mount.kind}", f"src={mount.source}", f"dst={mount.destination}"]
    if mount.read_only:
        options.append("readonly")
    if mount.volume_nocopy:
        options.append("volume-nocopy")
    return "--mount=" + ",".join(options)


def _preexec_frame(role: str, nonce: str) -> bytes:
    return _PREEXEC_FRAME_MAGIC + role.encode("ascii") + b":" + nonce.encode("ascii") + b"\n"


def _wrapped_command(
    sandbox: Mapping[str, Any],
    role: str,
    nonce: str,
    limits: _Limits,
    command: Sequence[str],
) -> list[str]:
    return [
        *sandbox["preExecArgv"][1:],
        "behavior-preexec-v1",
        role,
        nonce,
        str(limits.memory_bytes),
        str(limits.processes),
        str(CPU_QUOTA_MICROSECONDS),
        str(CPU_PERIOD_MICROSECONDS),
        str(limits.file_bytes),
        str(limits.open_files),
        str(limits.processes),
        str(limits.cpu_seconds),
        str(sandbox["oomScoreAdjustment"]),
        "--",
        sandbox["environmentLauncher"],
        *command,
    ]


def _consume_preexec_frame(stdout: bytes, role: str, nonce: str) -> bytes:
    expected = _preexec_frame(role, nonce)
    if not stdout.startswith(expected):
        if stdout.startswith(_PREEXEC_FRAME_MAGIC):
            raise BehaviorCorpusError(
                f"sandbox {role} emitted a wrong-role or wrong-nonce pre-exec frame"
            )
        raise BehaviorCorpusError(f"sandbox {role} omitted its pre-exec frame")
    observable = stdout[len(expected) :]
    if _PREEXEC_FRAME_MAGIC in observable:
        raise BehaviorCorpusError(
            f"sandbox {role} emitted a duplicate or spoofed pre-exec frame"
        )
    return observable


def _create_container(
    runtime: Path,
    environment: Mapping[str, str],
    *,
    name: str,
    role: str,
    preexec_nonce: str,
    sandbox: Mapping[str, Any],
    limits: _Limits,
    user: str,
    workdir: str,
    command: Sequence[str],
    mounts: Sequence[_Mount],
    capabilities: Sequence[str] = (),
    publication_settled: Callable[[], None] | None = None,
) -> str:
    wrapped_command = _wrapped_command(
        sandbox,
        role,
        preexec_nonce,
        limits,
        command,
    )
    arguments = [
        os.fspath(runtime),
        "create",
        "--pull=never",
        f"--platform={sandbox['platform']}",
        f"--name={name}",
        "--network=none",
        "--ipc=none",
        "--cgroupns=private",
        f"--runtime={sandbox['engineProfile']['containerRuntime']}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--security-opt=seccomp=builtin",
        f"--pids-limit={limits.processes}",
        f"--memory={limits.memory_bytes}",
        f"--memory-swap={limits.memory_bytes}",
        f"--cpu-period={CPU_PERIOD_MICROSECONDS}",
        f"--cpu-quota={CPU_QUOTA_MICROSECONDS}",
        f"--oom-score-adj={sandbox['oomScoreAdjustment']}",
        f"--ulimit=nofile={limits.open_files}:{limits.open_files}",
        f"--ulimit=fsize={limits.file_bytes}:{limits.file_bytes}",
        f"--ulimit=nproc={limits.processes}:{limits.processes}",
        f"--ulimit=cpu={limits.cpu_seconds}:{limits.cpu_seconds}",
        "--ulimit=core=0:0",
        "--hostname=behavior-corpus",
        "--log-driver=none",
        f"--shm-size={limits.file_bytes}",
        "--attach=stdin",
        "--attach=stdout",
        "--attach=stderr",
        "--interactive",
        "--no-healthcheck",
        "--init=false",
        (
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,"
            f"size={limits.file_bytes},nr_inodes={limits.workspace_entries}"
        ),
        f"--workdir={workdir}",
        f"--user={user}",
    ]
    arguments.extend(f"--cap-add={capability}" for capability in capabilities)
    arguments.extend(_mount_argument(mount) for mount in mounts)
    arguments.extend(
        [
            f"--entrypoint={sandbox['preExecArgv'][0]}",
            sandbox["imageDigest"],
            *wrapped_command,
        ]
    )
    output = _run_control_command(
        arguments, environment, "sandbox container creation"
    )
    if publication_settled is not None:
        publication_settled()
    try:
        container_id = output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BehaviorCorpusError("container runtime returned a malformed container ID") from error
    if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise BehaviorCorpusError("container runtime returned an invalid sandbox container ID")
    _verify_container_configuration(
        runtime,
        environment,
        container_id,
        name,
        sandbox=sandbox,
        limits=limits,
        expected_user=user,
        expected_workdir=workdir,
        expected_command=wrapped_command,
        expected_mounts=mounts,
        expected_capabilities=capabilities,
    )
    return container_id


def _verify_container_configuration(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str,
    container_name: str,
    *,
    sandbox: Mapping[str, Any],
    limits: _Limits,
    expected_user: str,
    expected_workdir: str,
    expected_command: Sequence[str],
    expected_mounts: Sequence[_Mount],
    expected_capabilities: Sequence[str],
) -> None:
    if (
        sandbox.get("resourcePolicyVersion") != OCI_HOST_RESOURCE_POLICY_VERSION
        or sandbox.get("oomScoreAdjustment") != OOM_SCORE_ADJUSTMENT
    ):
        raise BehaviorCorpusError(
            "sandbox selects an unsupported HostConfig/cgroup resource policy"
        )
    payload = _run_control_command(
        [os.fspath(runtime), "container", "inspect", container_id],
        environment,
        "sandbox container configuration inspection",
    )
    try:
        records = json.loads(payload.decode("utf-8"))
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("expected one container")
        record = records[0]
        config = record["Config"]
        host = record["HostConfig"]
        mounts = record["Mounts"]
        state = record["State"]
        network_settings = record["NetworkSettings"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise BehaviorCorpusError(
            "container runtime returned malformed sandbox configuration"
        ) from error
    if (
        record.get("Id") != container_id
        or record.get("Name") != f"/{container_name}"
        or record.get("Image") != sandbox["imageDigest"]
        or config.get("Image") != sandbox["imageDigest"]
    ):
        raise BehaviorCorpusError("container inspect identity is not bound to creation")
    if state.get("Status") != "created" or state.get("Running") is not False:
        raise BehaviorCorpusError("sandbox container changed state before verification")
    expected_host = {
        "ReadonlyRootfs": True,
        "NetworkMode": "none",
        "IpcMode": "none",
        "CgroupnsMode": "private",
        "PidMode": "",
        "UTSMode": "",
        "UsernsMode": "",
        "Privileged": False,
        "PublishAllPorts": False,
        "PidsLimit": limits.processes,
        "Memory": limits.memory_bytes,
        "MemorySwap": limits.memory_bytes,
        "NanoCpus": 0,
        "CpuPeriod": CPU_PERIOD_MICROSECONDS,
        "CpuQuota": CPU_QUOTA_MICROSECONDS,
        "AutoRemove": False,
        "OomKillDisable": False,
        "OomScoreAdj": sandbox["oomScoreAdjustment"],
        "ShmSize": limits.file_bytes,
        "Runtime": sandbox["engineProfile"]["containerRuntime"],
    }
    for field, expected in expected_host.items():
        if (
            field not in host
            or type(host[field]) is not type(expected)
            or host[field] != expected
        ):
            raise BehaviorCorpusError(
                f"container runtime did not enforce sandbox field {field}"
            )
    _verify_host_resource_defaults_v1(host)
    inspected_capabilities = [
        capability.removeprefix("CAP_") for capability in (host.get("CapAdd") or [])
    ]
    if sorted(host.get("CapDrop") or []) != ["ALL"] or sorted(
        inspected_capabilities
    ) != sorted(expected_capabilities):
        raise BehaviorCorpusError("container runtime changed the exact capability set")
    if host.get("SecurityOpt") != ["no-new-privileges", "seccomp=builtin"]:
        raise BehaviorCorpusError(
            "container runtime did not enforce no-new-privileges and built-in seccomp"
        )
    if host.get("Binds") not in (None, []) or host.get("VolumesFrom") not in (
        None,
        [],
    ):
        raise BehaviorCorpusError("container runtime added an implicit mount source")
    exact_empty_host_fields: dict[str, Any] = {
        "Cgroup": "",
        "ContainerIDFile": "",
        "Dns": None,
        "DnsOptions": [],
        "DnsSearch": [],
        "ExtraHosts": None,
        "GroupAdd": None,
        "Isolation": "",
        "Links": None,
        "PortBindings": {},
        "StorageOpt": None,
        "Sysctls": None,
        "VolumeDriver": "",
        "Init": False,
    }
    for field, expected in exact_empty_host_fields.items():
        if host.get(field) != expected:
            raise BehaviorCorpusError(
                f"container runtime enabled undeclared host setting {field}"
            )
    if host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}:
        raise BehaviorCorpusError("container runtime enabled a restart policy")
    if not _REQUIRED_MASKED_PATHS.issubset(set(host.get("MaskedPaths") or [])):
        raise BehaviorCorpusError("container runtime weakened masked kernel paths")
    if not _REQUIRED_READONLY_PATHS.issubset(set(host.get("ReadonlyPaths") or [])):
        raise BehaviorCorpusError("container runtime weakened read-only kernel paths")
    log_config = host.get("LogConfig")
    if log_config != {"Type": "none", "Config": {}}:
        raise BehaviorCorpusError("container runtime did not disable daemon logging")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}:
        raise BehaviorCorpusError("container runtime did not install the private tmpfs")
    expected_tmp = {
        "rw",
        "nosuid",
        "nodev",
        "noexec",
        f"size={limits.file_bytes}",
        f"nr_inodes={limits.workspace_entries}",
    }
    if set(str(tmpfs["/tmp"]).split(",")) != expected_tmp:
        raise BehaviorCorpusError("container runtime weakened private tmpfs options")
    observed_ulimits = {
        item.get("Name"): (item.get("Soft"), item.get("Hard"))
        for item in (host.get("Ulimits") or [])
        if isinstance(item, dict)
    }
    expected_ulimits = {
        "nofile": (limits.open_files, limits.open_files),
        "fsize": (limits.file_bytes, limits.file_bytes),
        "nproc": (limits.processes, limits.processes),
        "cpu": (limits.cpu_seconds, limits.cpu_seconds),
        "core": (0, 0),
    }
    if observed_ulimits != expected_ulimits:
        raise BehaviorCorpusError("container runtime did not enforce exact ulimits")
    expected_config = {
        "Entrypoint": [sandbox["preExecArgv"][0]],
        "Cmd": list(expected_command),
        "WorkingDir": expected_workdir,
        "Hostname": "behavior-corpus",
        "Domainname": "",
        "User": expected_user,
        "Env": sandbox["imageEnvironment"],
        "AttachStdin": True,
        "AttachStdout": True,
        "AttachStderr": True,
        "OpenStdin": True,
        "StdinOnce": True,
        "Tty": False,
        "Healthcheck": {"Test": ["NONE"]},
        "Volumes": None,
    }
    for field, expected in expected_config.items():
        if config.get(field) != expected:
            raise BehaviorCorpusError(
                f"container runtime changed sandbox configuration field {field}"
            )
    networks = network_settings.get("Networks")
    if not isinstance(networks, dict) or set(networks) != {"none"}:
        raise BehaviorCorpusError("container runtime attached an undeclared network")
    network = networks["none"]
    if not isinstance(network, dict) or any(
        network.get(field) not in (None, "", 0)
        for field in (
            "NetworkID",
            "EndpointID",
            "Gateway",
            "IPAddress",
            "MacAddress",
            "IPPrefixLen",
            "IPv6Gateway",
            "GlobalIPv6Address",
            "GlobalIPv6PrefixLen",
        )
    ):
        raise BehaviorCorpusError("container runtime assigned sandbox network identity")
    host_mounts = host.get("Mounts")
    if not isinstance(host_mounts, list) or len(host_mounts) != len(expected_mounts):
        raise BehaviorCorpusError("container runtime changed the closed mount request")
    requested_by_target = {item.get("Target"): item for item in host_mounts}
    if set(requested_by_target) != {mount.destination for mount in expected_mounts}:
        raise BehaviorCorpusError("container runtime changed mount destinations")
    for expected in expected_mounts:
        requested = requested_by_target[expected.destination]
        if (
            requested.get("Type") != expected.kind
            or requested.get("Source") != expected.source
            or bool(requested.get("ReadOnly", False)) != expected.read_only
        ):
            raise BehaviorCorpusError("container runtime changed an authenticated mount")
        if expected.kind == "volume":
            options = requested.get("VolumeOptions") or {}
            if options.get("NoCopy") is not expected.volume_nocopy:
                raise BehaviorCorpusError("container runtime enabled volume population")
    if not isinstance(mounts, list) or len(mounts) != len(expected_mounts):
        raise BehaviorCorpusError("container runtime added an implicit runtime mount")
    observed_by_destination = {item.get("Destination"): item for item in mounts}
    if set(observed_by_destination) != {
        mount.destination for mount in expected_mounts
    }:
        raise BehaviorCorpusError("container runtime changed runtime mount destinations")
    for expected in expected_mounts:
        observed = observed_by_destination[expected.destination]
        if (
            observed.get("Type") != expected.kind
            or observed.get("RW") is expected.read_only
        ):
            raise BehaviorCorpusError("container runtime changed runtime mount access")
        if expected.kind == "bind" and observed.get("Source") != expected.source:
            raise BehaviorCorpusError("container runtime changed a bind mount source")
        if expected.kind == "volume" and (
            observed.get("Name") != expected.source
            or observed.get("Driver") != "local"
            or observed.get("Source") != expected.runtime_source
        ):
            raise BehaviorCorpusError("container runtime changed the tmpfs volume mount")


def _start_keeper(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str,
    container_name: str,
    preexec_nonce: str,
) -> None:
    marker = _preexec_frame("keeper", preexec_nonce)
    frame_reader = _PreexecFrameReader("keeper", preexec_nonce)
    try:
        process = subprocess.Popen(
            [os.fspath(runtime), "start", "--attach", "--interactive", container_id],
            cwd=Path("/"),
            env=dict(environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise BehaviorCorpusError(f"cannot start workspace keeper: {error}") from error
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    primary_error: BaseException | None = None
    deadline = time.monotonic() + CONTROL_UNCERTAINTY_SECONDS
    try:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise BehaviorCorpusError("workspace keeper did not expose control pipes")
        process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while len(stdout) < len(marker):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BehaviorCorpusError("workspace keeper pre-exec frame timed out")
            events = selector.select(remaining)
            if not events:
                raise BehaviorCorpusError("workspace keeper pre-exec frame timed out")
            for key, _ in events:
                event_pipe = cast(BinaryIO, key.fileobj)
                try:
                    chunk = os.read(event_pipe.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(event_pipe)
                    event_pipe.close()
                    continue
                if key.data == "stdout":
                    stdout.extend(chunk)
                    frame_reader.feed(chunk)
                else:
                    stderr.extend(chunk)
                    if len(stderr) > CONTROL_CAPTURE_BYTES:
                        raise BehaviorCorpusError(
                            "workspace keeper pre-exec stderr exceeded its bound"
                        )
            if process.poll() is not None and len(stdout) < len(marker):
                detail = bytes(stderr).decode("utf-8", "replace").strip()
                raise BehaviorCorpusError(
                    "workspace keeper exited before pre-exec enforcement"
                    + (f": {detail}" if detail else "")
                )
        _consume_preexec_frame(bytes(stdout), "keeper", preexec_nonce)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[str] = []
        try:
            _terminate_group(process)
        except BaseException as error:
            cleanup_errors.append(f"could not detach keeper control client: {error}")
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                cleanup_errors.append(f"could not close keeper selector: {error}")
        for process_pipe in (process.stdin, process.stdout, process.stderr):
            if process_pipe is not None and not process_pipe.closed:
                try:
                    process_pipe.close()
                except BaseException as error:
                    cleanup_errors.append(f"could not close keeper pipe: {error}")
        if cleanup_errors:
            detail = "; ".join(cleanup_errors)
            if primary_error is not None:
                _add_exception_note(primary_error, detail)
            else:
                raise BehaviorCorpusError(detail)
    _verify_keeper_running(runtime, environment, container_id, container_name)


def _verify_keeper_running(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str,
    container_name: str,
) -> None:
    payload = _run_control_command(
        [os.fspath(runtime), "container", "inspect", container_id],
        environment,
        "workspace keeper running-state inspection",
    )
    try:
        record = json.loads(payload.decode("utf-8"))[0]
    except (UnicodeDecodeError, json.JSONDecodeError, IndexError, TypeError) as error:
        raise BehaviorCorpusError("container runtime returned malformed keeper state") from error
    if (
        record.get("Id") != container_id
        or record.get("Name") != f"/{container_name}"
        or record.get("State", {}).get("Running") is not True
    ):
        raise BehaviorCorpusError("workspace keeper did not remain running")


def _run_attached_container(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str,
    *,
    role: str,
    preexec_nonce: str,
    stdin: bytes,
    limits: _Limits,
) -> tuple[int, bytes, bytes]:
    marker = _preexec_frame(role, preexec_nonce)
    capture_limits = replace(limits, stdout_bytes=limits.stdout_bytes + len(marker))
    exit_code, stdout, stderr = _execute_bounded(
        [os.fspath(runtime), "start", "--attach", "--interactive", container_id],
        cwd=Path("/"),
        environment=environment,
        stdin=stdin,
        limits=capture_limits,
        apply_process_limits=False,
    )
    return exit_code, _consume_preexec_frame(stdout, role, preexec_nonce), stderr


def _verify_container_exit(
    runtime: Path,
    environment: Mapping[str, str],
    container_id: str,
    container_name: str,
    exit_code: int,
) -> None:
    payload = _run_control_command(
        [os.fspath(runtime), "container", "inspect", container_id],
        environment,
        "sandbox container exit-state inspection",
    )
    try:
        records = json.loads(payload.decode("utf-8"))
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("expected one container")
        record = records[0]
        state = record["State"]
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise BehaviorCorpusError(
            "container runtime returned malformed sandbox exit state"
        ) from error
    if (
        record.get("Id") != container_id
        or record.get("Name") != f"/{container_name}"
        or state.get("Status") != "exited"
        or state.get("Running") is not False
        or state.get("Paused") is not False
        or state.get("Restarting") is not False
        or state.get("OOMKilled") is not False
        or state.get("Dead") is not False
        or state.get("Pid") != 0
        or state.get("ExitCode") != exit_code
        or state.get("Error") != ""
    ):
        raise BehaviorCorpusError(
            "container runtime did not prove the sandbox process exit state"
        )


def _normalization_map(corpus: Mapping[str, Any]) -> dict[str, _Normalization]:
    result: dict[str, _Normalization] = {}
    for record in corpus["normalizations"]:
        result[record["id"]] = _Normalization(
            identifier=record["id"],
            field=record["field"],
            runtime_path=record["runtimePath"],
            replacement=record["replacement"].encode("utf-8"),
        )
    return result


def _normalize_stream(
    payload: bytes,
    field: str,
    identifiers: Sequence[str],
    normalizations: Mapping[str, _Normalization],
    runtime_paths: Mapping[str, Path],
    maximum: int,
) -> bytes:
    result = payload
    for identifier in identifiers:
        normalization = normalizations[identifier]
        if normalization.field != field:
            raise BehaviorCorpusError(
                f"normalization {identifier} cannot be applied to {field}"
            )
        needle = os.fsencode(runtime_paths[normalization.runtime_path])
        if needle not in result:
            raise BehaviorCorpusError(
                f"normalization {identifier} did not match {field}"
            )
        matches = result.count(needle)
        normalized_size = len(result) + matches * (
            len(normalization.replacement) - len(needle)
        )
        if normalized_size > maximum:
            raise BehaviorCorpusError(
                f"normalized {field} exceeded {maximum} bytes"
            )
        result = result.replace(needle, normalization.replacement)
    return result


def _observation(payload: bytes, normalizations: Sequence[str] = ()) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "base64": base64.b64encode(payload).decode("ascii"),
        "normalizations": list(normalizations),
    }


def _safe_workspace_path(workspace: Path, relative: str) -> Path:
    candidate = workspace.joinpath(*PurePosixPath(relative).parts)
    resolved_parent = candidate.parent.resolve()
    try:
        resolved_parent.relative_to(workspace.resolve())
    except ValueError as error:
        raise BehaviorCorpusError(f"workspace path escapes its root: {relative}") from error
    return candidate


def _read_artifact(path: Path, relative: str, maximum: int) -> tuple[bytes, str]:
    payload = _read_regular_snapshot(path, f"artifact {relative}", maximum)
    mode = path.stat(follow_symlinks=False).st_mode
    permissions = mode & 0o7777
    if permissions & 0o7000:
        raise BehaviorCorpusError(f"artifact {relative} carries forbidden special mode bits")
    return payload, f"0o{permissions:03o}"


def _assert_expected_blob(actual: bytes, expected: Mapping[str, Any], label: str) -> None:
    if len(actual) != expected["bytes"]:
        raise BehaviorCorpusError(
            f"{label} byte length mismatch: expected {expected['bytes']}, got {len(actual)}"
        )
    actual_sha256 = hashlib.sha256(actual).hexdigest()
    if actual_sha256 != expected["sha256"]:
        raise BehaviorCorpusError(
            f"{label} SHA-256 mismatch: expected {expected['sha256']}, got {actual_sha256}"
        )
    if base64.b64encode(actual).decode("ascii") != expected["base64"]:
        raise BehaviorCorpusError(f"{label} byte content does not match its expectation")


def _verify_workspace_tree(
    workspace: Path,
    inputs: Mapping[str, tuple[bytes, bool]],
    expected_artifact_paths: set[str] | None,
    declared_directories: set[str],
    limits: _Limits,
) -> set[str]:
    observed: set[str] = set()
    stack = [workspace]
    entries_seen = 0
    logical_bytes = 0
    allocated_bytes = 0
    while stack:
        root_path = stack.pop()
        try:
            iterator = os.scandir(root_path)
        except OSError as error:
            raise BehaviorCorpusError(f"cannot traverse collected workspace: {error}") from error
        with iterator:
            for entry in iterator:
                entries_seen += 1
                if entries_seen > limits.workspace_entries:
                    raise BehaviorCorpusError(
                        "workspace exceeds corpus.limits.workspaceEntries"
                    )
                child = Path(entry.path)
                relative = child.relative_to(workspace).as_posix()
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise BehaviorCorpusError(
                        f"cannot inspect collected workspace entry {relative}: {error}"
                    ) from error
                logical_bytes += metadata.st_size
                allocated_bytes += metadata.st_blocks * 512
                if (
                    logical_bytes > limits.workspace_bytes
                    or allocated_bytes > limits.workspace_bytes
                ):
                    raise BehaviorCorpusError(
                        "workspace exceeds corpus.limits.workspaceBytes"
                    )
                permissions = metadata.st_mode & 0o7777
                if permissions & 0o7000:
                    raise BehaviorCorpusError(
                        f"workspace entry carries forbidden special mode bits: {relative}"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in declared_directories:
                        raise BehaviorCorpusError(
                            f"workspace contains unobserved directory: {relative}"
                        )
                    stack.append(child)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise BehaviorCorpusError(
                        f"workspace contains unexpected non-regular file: {relative}"
                    )
                observed.add(relative)
    if expected_artifact_paths is not None:
        allowed = set(inputs) | expected_artifact_paths
        if unexpected := sorted(observed - allowed):
            raise BehaviorCorpusError(f"workspace contains unobserved artifacts: {unexpected}")
    for relative, (expected_payload, expected_executable) in inputs.items():
        path = _safe_workspace_path(workspace, relative)
        payload, observed_mode = _read_artifact(path, relative, MAX_INPUT_BYTES_PER_CASE)
        expected_mode = "0o500" if expected_executable else "0o400"
        if payload != expected_payload or observed_mode != expected_mode:
            raise BehaviorCorpusError(f"staged input was mutated: {relative}")
    return observed


def _run_case(
    corpus: Mapping[str, Any],
    case: Mapping[str, Any],
    executable_payload: bytes,
    limits: _Limits,
    normalizations: Mapping[str, _Normalization],
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str],
    retention_budget: _RetentionBudget,
    *,
    record_expectations: bool = False,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="behavior-corpus-") as temporary:
        private_root = Path(temporary)
        case_inputs = private_root / "case-inputs"
        case_inputs.mkdir(mode=0o700)
        collected_workspace = private_root / "case-results"
        collected_workspace.mkdir(mode=0o700)
        staged_oracle = private_root / "oracle"
        _write_exclusive(staged_oracle, executable_payload, 0o555)
        runtime_paths = {"workspace": Path("/workspace"), "oracle": Path("/oracle")}
        for relative in corpus["directories"]:
            _safe_workspace_path(case_inputs, relative).mkdir(parents=True, exist_ok=True)

        staged_inputs: dict[str, tuple[bytes, bool]] = {}
        for record in case["inputs"]:
            payload = _decode_base64(
                record["base64"], "case input", maximum=MAX_INPUT_BYTES_PER_CASE
            )
            path = _safe_workspace_path(case_inputs, record["path"])
            _write_exclusive(path, payload, 0o555 if record["executable"] else 0o444)
            staged_inputs[record["path"]] = (payload, record["executable"])
        for root, directories, _ in os.walk(case_inputs):
            Path(root).chmod(0o555)
            for directory in directories:
                (Path(root) / directory).chmod(0o555)

        environment_values = dict(corpus["environment"]["variables"])
        environment_values.update(case["environment"])
        environment = {
            name: _expand(value, runtime_paths)
            for name, value in environment_values.items()
        }
        oracle_arguments = [
            _expand(argument, runtime_paths) for argument in case["arguments"]
        ]
        stdin = _decode_base64(
            case["stdin"]["base64"], "case stdin", maximum=MAX_INPUT_BYTES_PER_CASE
        )
        sandbox = corpus["sandbox"]
        deterministic_files = {
            "/etc/hostname": (private_root / "hostname", b"behavior-corpus\n"),
            "/etc/hosts": (
                private_root / "hosts",
                b"127.0.0.1 localhost\n::1 localhost\n",
            ),
            "/etc/resolv.conf": (
                private_root / "resolv.conf",
                b"# external network disabled\n",
            ),
        }
        for _, (path, payload) in deterministic_files.items():
            _write_exclusive(path, payload, 0o444)
        token = secrets.token_hex(16)
        volume_name = f"behavior-corpus-volume-{token}"
        container_names = {
            role: f"behavior-corpus-{role}-{token}"
            for role in ("keeper", "setup", "target", "collector")
        }
        container_ids: dict[str, str | None] = {
            role: None for role in container_names
        }
        preexec_nonces = {role: secrets.token_hex(16) for role in container_names}
        target_uid, target_gid = _numeric_user(
            sandbox["targetUser"], "corpus.sandbox.targetUser"
        )
        target_command = [
            "-i",
            *[f"{name}={environment[name]}" for name in sorted(environment)],
            "/oracle",
            *oracle_arguments,
        ]
        deterministic_mounts = [
            _Mount("bind", os.fspath(deterministic_files[destination][0]), destination, True)
            for destination in sorted(deterministic_files)
        ]
        volume_mountpoint: str | None = None
        exit_code = -1
        stdout = b""
        stderr = b""
        primary_error: BaseException | None = None
        settlement_deadline: float | None = None
        cleanup_failures: list[tuple[str, BaseException | None]] = []
        cleanup_cancellations: list[tuple[str, BaseException]] = []
        first_cleanup_cancellation: KeyboardInterrupt | SystemExit | None = None
        cleanup_cancellation_count = 0
        prior_sigint_handler: Any = None
        prior_sigint_handler_known = False
        sigint_deferral_installed = False
        cleanup_runs_on_main_thread = (
            threading.current_thread() is threading.main_thread()
        )
        cleanup_targets = (
            ("container", "collector", "collector container"),
            ("container", "target", "target container"),
            ("container", "setup", "setup container"),
            ("container", "keeper", "keeper container"),
            ("volume", "", "workspace volume"),
        )

        def remember_cleanup_exception(label: str, error: BaseException) -> None:
            nonlocal first_cleanup_cancellation, cleanup_cancellation_count
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                cleanup_cancellation_count += 1
                if len(cleanup_cancellations) < 8:
                    cleanup_cancellations.append((label, error))
                if first_cleanup_cancellation is None:
                    first_cleanup_cancellation = error
            else:
                cleanup_failures.append((label, error))

        def remember_cleanup_exception_chain(
            label: str, error: BaseException
        ) -> None:
            """Retain the oldest cleanup exception if bookkeeping was interrupted."""

            chain: list[BaseException] = []
            current: BaseException | None = error
            while (
                current is not None
                and current is not primary_error
                and len(chain) < MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
            ):
                chain.append(current)
                current = current.__context__
            for chained_error in reversed(chain):
                remember_cleanup_exception(label, chained_error)

        def defer_cleanup_sigint(_signum: int, _frame: Any) -> None:
            nonlocal first_cleanup_cancellation, cleanup_cancellation_count
            cleanup_cancellation_count += 1
            deferred = KeyboardInterrupt("SIGINT received during sandbox cleanup")
            if len(cleanup_cancellations) < 8:
                cleanup_cancellations.append(("sandbox cleanup", deferred))
            if first_cleanup_cancellation is None:
                first_cleanup_cancellation = deferred

        def describe_cleanup_exception(error: BaseException) -> str:
            try:
                return _safe_exception_description(error)
            except BaseException:
                return "BaseException: <detail unavailable>"

        def attach_cleanup_note(error: BaseException, note: str) -> None:
            try:
                _add_exception_note_no_throw(error, note)
            except BaseException:
                try:
                    BaseException.add_note(error, note[:16_384])
                except BaseException:
                    try:
                        object.__setattr__(
                            error,
                            "_behavior_corpus_notes",
                            (note[:16_384],),
                        )
                    except BaseException:
                        pass

        def create_with_uncertainty_settlement(
            operation: Callable[[Callable[[], None]], Any],
        ) -> Any:
            nonlocal settlement_deadline
            prior_deadline = settlement_deadline
            armed_deadline = (
                time.monotonic() + CREATE_PUBLICATION_SETTLEMENT_SECONDS
            )
            settlement_deadline = (
                armed_deadline
                if prior_deadline is None
                else max(prior_deadline, armed_deadline)
            )

            def publication_settled() -> None:
                nonlocal settlement_deadline
                # The create client returned successfully, so this name can no
                # longer be published late.  Only now may the prior state return.
                settlement_deadline = prior_deadline

            return operation(publication_settled)

        try:
            volume_mountpoint = create_with_uncertainty_settlement(
                lambda settled: _create_workspace_volume(
                    container_runtime,
                    container_runtime_environment,
                    volume_name,
                    limits,
                    target_uid,
                    target_gid,
                    publication_settled=settled,
                )
            )
            workspace_read_write = _Mount(
                "volume",
                volume_name,
                "/workspace",
                False,
                True,
                volume_mountpoint,
            )
            workspace_read_only = _Mount(
                "volume",
                volume_name,
                "/workspace",
                True,
                True,
                volume_mountpoint,
            )
            keeper_command = ["-i", *sandbox["keeperArgv"]]
            container_ids["keeper"] = create_with_uncertainty_settlement(
                lambda settled: _create_container(
                    container_runtime,
                    container_runtime_environment,
                    name=container_names["keeper"],
                    role="keeper",
                    preexec_nonce=preexec_nonces["keeper"],
                    sandbox=sandbox,
                    limits=limits,
                    user="0:0",
                    workdir="/",
                    command=keeper_command,
                    mounts=[workspace_read_write, *deterministic_mounts],
                    publication_settled=settled,
                )
            )
            _start_keeper(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["keeper"]),
                container_names["keeper"],
                preexec_nonces["keeper"],
            )

            setup_command = [
                "-i",
                f"TARGET_UID={target_uid}",
                f"TARGET_GID={target_gid}",
                f"WORKSPACE_BYTES={limits.workspace_bytes}",
                f"WORKSPACE_ENTRIES={limits.workspace_entries}",
                *sandbox["setupArgv"],
            ]
            setup_mounts = [
                workspace_read_write,
                _Mount("bind", os.fspath(case_inputs), "/case-inputs", True),
                *deterministic_mounts,
            ]
            container_ids["setup"] = create_with_uncertainty_settlement(
                lambda settled: _create_container(
                    container_runtime,
                    container_runtime_environment,
                    name=container_names["setup"],
                    role="setup",
                    preexec_nonce=preexec_nonces["setup"],
                    sandbox=sandbox,
                    limits=limits,
                    user=sandbox["targetUser"],
                    workdir="/",
                    command=setup_command,
                    mounts=setup_mounts,
                    publication_settled=settled,
                )
            )
            setup_exit, setup_stdout, setup_stderr = _run_attached_container(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["setup"]),
                role="setup",
                preexec_nonce=preexec_nonces["setup"],
                stdin=b"",
                limits=_control_limits(),
            )
            _verify_container_exit(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["setup"]),
                container_names["setup"],
                setup_exit,
            )
            if setup_exit != 0 or setup_stdout or setup_stderr:
                raise BehaviorCorpusError(
                    "trusted workspace setup failed: "
                    + (setup_stderr or setup_stdout).decode("utf-8", "replace").strip()
                )
            _remove_container(
                container_runtime,
                container_runtime_environment,
                container_ids["setup"],
                container_names["setup"],
            )
            _verify_keeper_running(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["keeper"]),
                container_names["keeper"],
            )

            target_mounts = [
                workspace_read_write,
                _Mount("bind", os.fspath(staged_oracle), "/oracle", True),
                *deterministic_mounts,
            ]
            container_ids["target"] = create_with_uncertainty_settlement(
                lambda settled: _create_container(
                    container_runtime,
                    container_runtime_environment,
                    name=container_names["target"],
                    role="target",
                    preexec_nonce=preexec_nonces["target"],
                    sandbox=sandbox,
                    limits=limits,
                    user=sandbox["targetUser"],
                    workdir="/workspace",
                    command=target_command,
                    mounts=target_mounts,
                    publication_settled=settled,
                )
            )
            exit_code, stdout, stderr = _run_attached_container(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["target"]),
                role="target",
                preexec_nonce=preexec_nonces["target"],
                stdin=stdin,
                limits=limits,
            )
            _verify_container_exit(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["target"]),
                container_names["target"],
                exit_code,
            )
            _remove_container(
                container_runtime,
                container_runtime_environment,
                container_ids["target"],
                container_names["target"],
            )
            _verify_keeper_running(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["keeper"]),
                container_names["keeper"],
            )

            collector_command = [
                "-i",
                f"WORKSPACE_BYTES={limits.workspace_bytes}",
                f"WORKSPACE_ENTRIES={limits.workspace_entries}",
                *sandbox["collectorArgv"],
            ]
            collector_mounts = [
                workspace_read_only,
                _Mount("bind", os.fspath(collected_workspace), "/case-results", False),
                *deterministic_mounts,
            ]
            container_ids["collector"] = create_with_uncertainty_settlement(
                lambda settled: _create_container(
                    container_runtime,
                    container_runtime_environment,
                    name=container_names["collector"],
                    role="collector",
                    preexec_nonce=preexec_nonces["collector"],
                    sandbox=sandbox,
                    limits=limits,
                    user="0:0",
                    workdir="/",
                    command=collector_command,
                    mounts=collector_mounts,
                    capabilities=["DAC_OVERRIDE"],
                    publication_settled=settled,
                )
            )
            collector_exit, collector_stdout, collector_stderr = _run_attached_container(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["collector"]),
                role="collector",
                preexec_nonce=preexec_nonces["collector"],
                stdin=b"",
                limits=_control_limits(),
            )
            _verify_container_exit(
                container_runtime,
                container_runtime_environment,
                cast(str, container_ids["collector"]),
                container_names["collector"],
                collector_exit,
            )
            if collector_exit != 0 or collector_stdout or collector_stderr:
                raise BehaviorCorpusError(
                    "trusted bounded workspace collector failed: "
                    + (collector_stderr or collector_stdout)
                    .decode("utf-8", "replace")
                    .strip()
                )
            _remove_container(
                container_runtime,
                container_runtime_environment,
                container_ids["collector"],
                container_names["collector"],
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if cleanup_runs_on_main_thread:
                setup_driver_done = False
                setup_driver_interruptions = 0
                while not setup_driver_done:
                    try:
                        try:
                            if not prior_sigint_handler_known:
                                prior_sigint_handler = _ORIGINAL_GETSIGNAL(
                                    signal.SIGINT
                                )
                                prior_sigint_handler_known = True
                            _ORIGINAL_SIGNAL(signal.SIGINT, defer_cleanup_sigint)
                            sigint_deferral_installed = True
                        except BaseException as error:
                            remember_cleanup_exception(
                                "SIGINT deferral setup", error
                            )
                            try:
                                sigint_deferral_installed = (
                                    _ORIGINAL_GETSIGNAL(signal.SIGINT)
                                    is defer_cleanup_sigint
                                )
                            except BaseException as inspection_error:
                                remember_cleanup_exception(
                                    "SIGINT deferral setup inspection",
                                    inspection_error,
                                )
                        setup_driver_done = True
                    except BaseException as bookkeeping_error:
                        remember_cleanup_exception_chain(
                            "SIGINT deferral setup bookkeeping",
                            bookkeeping_error,
                        )
                        setup_driver_interruptions += 1
                        if (
                            setup_driver_interruptions
                            >= MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
                        ):
                            cleanup_failures.append(
                                (
                                    "SIGINT deferral setup was not established",
                                    None,
                                )
                            )
                            setup_driver_done = True

            cleanup_index = 0
            active_cleanup_index: int | None = None
            cleanup_driver_interruptions = [0] * len(cleanup_targets)
            cleanup_driver_done = False
            while not cleanup_driver_done:
                try:
                    while cleanup_index < len(cleanup_targets):
                        active_cleanup_index = cleanup_index
                        cleanup_index += 1
                        kind, role, label = cleanup_targets[active_cleanup_index]
                        interruptions = 0
                        while True:
                            try:
                                if kind == "container":
                                    _remove_container(
                                        container_runtime,
                                        container_runtime_environment,
                                        container_ids[role],
                                        container_names[role],
                                        settle_until=settlement_deadline,
                                    )
                                else:
                                    _remove_volume(
                                        container_runtime,
                                        container_runtime_environment,
                                        volume_name,
                                        settle_until=settlement_deadline,
                                    )
                                break
                            except (KeyboardInterrupt, SystemExit) as error:
                                remember_cleanup_exception(label, error)
                                interruptions += 1
                                if (
                                    interruptions
                                    >= MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
                                ):
                                    cleanup_failures.append((label, None))
                                    break
                            except BaseException as error:
                                cleanup_failures.append((label, error))
                                break
                        active_cleanup_index = None
                    cleanup_driver_done = True
                except BaseException as error:
                    # The index is claimed before target bookkeeping. If an
                    # exception lands there, reset it so that target is retried;
                    # a between-target exception resumes at the next fixed item.
                    failed_index = (
                        active_cleanup_index
                        if active_cleanup_index is not None
                        else min(cleanup_index, len(cleanup_targets) - 1)
                    )
                    failed_label = cleanup_targets[failed_index][2]
                    remember_cleanup_exception_chain(failed_label, error)
                    cleanup_driver_interruptions[failed_index] += 1
                    if (
                        cleanup_driver_interruptions[failed_index]
                        >= MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
                    ):
                        cleanup_failures.append((failed_label, None))
                        cleanup_index = failed_index + 1
                    else:
                        cleanup_index = failed_index
                    active_cleanup_index = None

            if sigint_deferral_installed:
                restoration_attempts = 0
                while (
                    sigint_deferral_installed
                    and restoration_attempts
                    < MAX_DEFERRED_CLEANUP_INTERRUPTS_PER_OBJECT
                ):
                    restoration_attempts += 1
                    try:
                        try:
                            _ORIGINAL_SIGNAL(signal.SIGINT, prior_sigint_handler)
                            sigint_deferral_installed = False
                        except BaseException as error:
                            remember_cleanup_exception(
                                "SIGINT deferral restoration", error
                            )
                    except BaseException as bookkeeping_error:
                        remember_cleanup_exception_chain(
                            "SIGINT deferral restoration bookkeeping",
                            bookkeeping_error,
                        )
                if sigint_deferral_installed:
                    cleanup_failures.append(
                        ("SIGINT deferral restoration was not established", None)
                    )

            diagnostic_target: BaseException | None = (
                primary_error
                if primary_error is not None
                else first_cleanup_cancellation
            )
            if diagnostic_target is not None and first_cleanup_cancellation is not None:
                cancellation_parts = [
                    f"{label}: {describe_cleanup_exception(cleanup_error)}"
                    for label, cleanup_error in cleanup_cancellations
                ]
                cancellation_note = (
                    "sandbox cleanup cancellation was deferred until all residue "
                    "attempts completed: "
                    + "; ".join(cancellation_parts)
                    + f"; cancellations={cleanup_cancellation_count}"
                )
                attach_cleanup_note(diagnostic_target, cancellation_note)
            cleanup_detail = ""
            if cleanup_failures:
                failure_parts: list[str] = []
                for label, cleanup_error in cleanup_failures[:8]:
                    if cleanup_error is None:
                        failure_parts.append(
                            f"{label}: residue absence proof was not established"
                        )
                    else:
                        failure_parts.append(
                            f"{label}: {describe_cleanup_exception(cleanup_error)}"
                        )
                cleanup_detail = "; ".join(failure_parts)
                if diagnostic_target is not None:
                    attach_cleanup_note(
                        diagnostic_target,
                        f"sandbox cleanup also failed: {cleanup_detail}",
                    )
            if primary_error is None:
                if first_cleanup_cancellation is not None:
                    raise first_cleanup_cancellation
                if cleanup_failures:
                    raise BehaviorCorpusError(cleanup_detail)
        expected = case["expected"]
        if exit_code < 0 or exit_code > 255:
            raise BehaviorCorpusError(
                f"case {case['id']} produced unsupported exit code {exit_code}"
            )
        if not record_expectations and exit_code != expected["exitCode"]:
            raise BehaviorCorpusError(
                f"case {case['id']} exit mismatch: expected {expected['exitCode']}, got {exit_code}"
            )
        normalized_streams: dict[str, bytes] = {}
        for field, payload in (("stdout", stdout), ("stderr", stderr)):
            identifiers = expected[field]["normalizations"]
            normalized = _normalize_stream(
                payload,
                field,
                identifiers,
                normalizations,
                runtime_paths,
                limits.stdout_bytes if field == "stdout" else limits.stderr_bytes,
            )
            if not record_expectations:
                _assert_expected_blob(
                    normalized, expected[field], f"case {case['id']} {field}"
                )
            normalized_streams[field] = normalized
        retention_budget.retain(
            sum(len(payload) for payload in normalized_streams.values()),
            f"case {case['id']} streams",
        )

        artifact_observations: list[dict[str, Any]] = []
        expected_artifact_paths = {record["path"] for record in expected["artifacts"]}
        declared_directories = set(corpus["directories"])
        for relative in [*staged_inputs, *expected_artifact_paths]:
            parent = PurePosixPath(relative).parent
            while str(parent) != ".":
                declared_directories.add(parent.as_posix())
                parent = parent.parent
        observed_paths = _verify_workspace_tree(
            collected_workspace,
            staged_inputs,
            None if record_expectations else expected_artifact_paths,
            declared_directories,
            limits,
        )
        generated_paths = observed_paths - set(staged_inputs)
        expected_artifacts = {
            item["path"]: item for item in expected["artifacts"]
        }
        authored_absent_paths = {
            path
            for path, record in expected_artifacts.items()
            if record["present"] is False
        }
        if record_expectations:
            contradicted_absences = sorted(authored_absent_paths & observed_paths)
            if contradicted_absences:
                raise BehaviorCorpusError(
                    f"case {case['id']} authored-absent artifact appeared: "
                    + ", ".join(contradicted_absences)
                )
        discovered_artifact_paths = generated_paths - expected_artifact_paths
        artifact_paths = (
            sorted(expected_artifact_paths | discovered_artifact_paths)
            if record_expectations
            else [item["path"] for item in expected["artifacts"]]
        )
        for relative in artifact_paths:
            expected_record = expected_artifacts.get(relative)
            path = _safe_workspace_path(collected_workspace, relative)
            present = path.exists() or path.is_symlink()
            if (
                not record_expectations
                and expected_record is not None
                and present != expected_record["present"]
            ):
                raise BehaviorCorpusError(
                    f"case {case['id']} artifact {relative} presence mismatch"
                )
            if not present:
                artifact_observations.append(
                    {
                        "path": relative,
                        "present": False,
                        "bytes": None,
                        "sha256": None,
                        "base64": None,
                        "mode": None,
                    }
                )
                continue
            payload, observed_mode = _read_artifact(path, relative, limits.artifact_bytes)
            retention_budget.retain(
                len(payload), f"case {case['id']} artifact {relative}"
            )
            if not record_expectations and expected_record is not None:
                _assert_expected_blob(
                    payload,
                    expected_record,
                    f"case {case['id']} artifact {relative}",
                )
            if (
                not record_expectations
                and expected_record is not None
                and observed_mode != expected_record["mode"]
            ):
                raise BehaviorCorpusError(
                    f"case {case['id']} artifact {relative} exact-mode mismatch"
                )
            artifact_observations.append(
                {
                    "path": relative,
                    "present": True,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "base64": base64.b64encode(payload).decode("ascii"),
                    "mode": observed_mode,
                }
            )
        return {
            "id": case["id"],
            "status": "passed",
            "exitCode": exit_code,
            "stdout": _observation(
                normalized_streams["stdout"], expected["stdout"]["normalizations"]
            ),
            "stderr": _observation(
                normalized_streams["stderr"], expected["stderr"]["normalizations"]
            ),
            "artifacts": artifact_observations,
        }


def run_corpus(
    corpus: dict[str, Any],
    executable_path: Path,
    *,
    corpus_payload: bytes | None = None,
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run and verify every case, returning deterministic checked evidence."""

    validated = validate_corpus(corpus)
    executable = _read_regular_snapshot(
        executable_path, "behavior executable", MAX_EXECUTABLE_BYTES
    )
    expected_executable = validated["executable"]
    if len(executable) != expected_executable["bytes"]:
        raise BehaviorCorpusError("behavior executable byte length does not match corpus")
    executable_sha256 = hashlib.sha256(executable).hexdigest()
    if executable_sha256 != expected_executable["sha256"]:
        raise BehaviorCorpusError("behavior executable SHA-256 does not match corpus")
    if corpus_payload is None:
        corpus_payload = corpus_json_bytes(validated)
    elif _decode_json(corpus_payload, "behavior corpus") != validated:
        raise BehaviorCorpusError("corpus payload does not encode the validated corpus")
    if corpus_payload != corpus_json_bytes(validated):
        raise BehaviorCorpusError(
            "behavior corpus must use canonical sorted, indented JSON with one final newline"
        )
    runtime_environment = _container_runtime_environment(container_runtime_environment)
    runtime_payload = _snapshot_control_client(container_runtime)
    limits = _limits(validated["limits"])
    normalizations = _normalization_map(validated)
    retention_budget = _RetentionBudget()
    with tempfile.TemporaryDirectory(prefix="behavior-control-") as control_directory:
        staged_runtime = Path(control_directory) / "container-runtime"
        _write_exclusive(staged_runtime, runtime_payload, 0o500)
        _verify_oci_runtime(
            staged_runtime,
            runtime_environment,
            validated["sandbox"],
        )
        case_reports = [
            _run_case(
                validated,
                case,
                executable,
                limits,
                normalizations,
                staged_runtime,
                runtime_environment,
                retention_budget,
            )
            for case in validated["cases"]
        ]
    categories = sorted(
        {category for case in validated["cases"] for category in case["categories"]}
    )
    report = {
        "schemaVersion": 1,
        "corpus": {
            "id": validated["id"],
            "sha256": hashlib.sha256(corpus_payload).hexdigest(),
        },
        "executable": {
            "bytes": len(executable),
            "sha256": executable_sha256,
        },
        "sandbox": {
            "backend": validated["sandbox"]["backend"],
            "resourcePolicyVersion": validated["sandbox"]["resourcePolicyVersion"],
            "oomScoreAdjustment": validated["sandbox"]["oomScoreAdjustment"],
            "imageDigest": validated["sandbox"]["imageDigest"],
            "platform": validated["sandbox"]["platform"],
            "isolation": validated["sandbox"]["isolation"],
            "imageEnvironment": validated["sandbox"]["imageEnvironment"],
            "preExecArgv": validated["sandbox"]["preExecArgv"],
            "environmentLauncher": validated["sandbox"]["environmentLauncher"],
            "keeperArgv": validated["sandbox"]["keeperArgv"],
            "setupArgv": validated["sandbox"]["setupArgv"],
            "collectorArgv": validated["sandbox"]["collectorArgv"],
            "targetUser": validated["sandbox"]["targetUser"],
            "controlClient": validated["sandbox"]["controlClient"],
            "engineProfile": validated["sandbox"]["engineProfile"],
        },
        "limits": validated["limits"],
        "summary": {
            "cases": len(case_reports),
            "passed": len(case_reports),
            "categories": categories,
        },
        "cases": case_reports,
    }
    return validate_corpus_report_pair(
        validated,
        report,
        corpus_payload=corpus_payload,
    )


def record_corpus_expectations(
    draft_corpus: dict[str, Any],
    executable_path: Path,
    *,
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Record deterministic expectations for a reviewed corpus draft.

    This profile-authoring operation is deliberately separate from verification.
    Each draft case must already be structurally valid; its stream normalization
    lists and explicitly absent artifact paths are retained, while actual exit,
    stream bytes, and produced regular files become the checked expectations.
    Callers must review and version the result before using :func:`run_corpus`.
    """

    validated = validate_corpus(draft_corpus)
    executable = _read_regular_snapshot(
        executable_path, "behavior executable", MAX_EXECUTABLE_BYTES
    )
    expected_executable = validated["executable"]
    if (
        len(executable) != expected_executable["bytes"]
        or hashlib.sha256(executable).hexdigest() != expected_executable["sha256"]
    ):
        raise BehaviorCorpusError(
            "behavior executable identity does not match the corpus draft"
        )
    runtime_environment = _container_runtime_environment(container_runtime_environment)
    runtime_payload = _snapshot_control_client(container_runtime)
    limits = _limits(validated["limits"])
    normalizations = _normalization_map(validated)
    retention_budget = _RetentionBudget()
    recorded = json.loads(json.dumps(validated))
    with tempfile.TemporaryDirectory(prefix="behavior-control-") as control_directory:
        staged_runtime = Path(control_directory) / "container-runtime"
        _write_exclusive(staged_runtime, runtime_payload, 0o500)
        _verify_oci_runtime(
            staged_runtime,
            runtime_environment,
            validated["sandbox"],
        )
        for index, case in enumerate(validated["cases"]):
            observation = _run_case(
                validated,
                case,
                executable,
                limits,
                normalizations,
                staged_runtime,
                runtime_environment,
                retention_budget,
                record_expectations=True,
            )
            if observation["exitCode"] != case["expected"]["exitCode"]:
                raise BehaviorCorpusError(
                    f"case {case['id']} recording exit mismatch: expected "
                    f"{case['expected']['exitCode']}, got {observation['exitCode']}"
                )
            recorded["cases"][index]["expected"] = {
                "exitCode": observation["exitCode"],
                "stdout": observation["stdout"],
                "stderr": observation["stderr"],
                "artifacts": observation["artifacts"],
            }
    return validate_corpus(recorded)


def run_corpus_file(
    corpus_path: Path,
    executable_path: Path,
    *,
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    corpus, payload = load_corpus(corpus_path)
    return run_corpus(
        corpus,
        executable_path,
        corpus_payload=payload,
        container_runtime=container_runtime,
        container_runtime_environment=container_runtime_environment,
    )


def corpus_json_bytes(corpus: Mapping[str, Any]) -> bytes:
    return (json.dumps(corpus, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_corpus(path: Path, corpus: Mapping[str, Any]) -> None:
    validated = validate_corpus(dict(corpus))
    payload = corpus_json_bytes(validated)
    if len(payload) > MAX_CORPUS_BYTES:
        raise BehaviorCorpusError(
            f"behavior corpus exceeds the {MAX_CORPUS_BYTES}-byte output limit"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def validate_report(value: dict[str, Any]) -> dict[str, Any]:
    report = _object(
        value,
        "report",
        {
            "schemaVersion",
            "corpus",
            "executable",
            "sandbox",
            "limits",
            "summary",
            "cases",
        },
    )
    if isinstance(report["schemaVersion"], bool) or report["schemaVersion"] != 1:
        raise BehaviorCorpusError("report.schemaVersion must be the integer 1")
    corpus = _object(report["corpus"], "report.corpus", {"id", "sha256"})
    _identifier(corpus["id"], "report.corpus.id")
    _sha256(corpus["sha256"], "report.corpus.sha256")
    executable = _object(
        report["executable"], "report.executable", {"bytes", "sha256"}
    )
    _integer(
        executable["bytes"],
        "report.executable.bytes",
        minimum=1,
        maximum=MAX_EXECUTABLE_BYTES,
    )
    _sha256(executable["sha256"], "report.executable.sha256")
    report_limits = _limits(report["limits"])

    empty_sha = hashlib.sha256(b"").hexdigest()
    validate_corpus(
        {
            "schemaVersion": 1,
            "scope": "fixture",
            "id": corpus["id"],
            "executable": executable,
            "sandbox": report["sandbox"],
            "environment": {"clearInherited": True, "variables": {}},
            "limits": report["limits"],
            "directories": [],
            "normalizations": [],
            "cases": [
                {
                    "id": "report-validation",
                    "categories": ["report"],
                    "arguments": [],
                    "environment": {},
                    "stdin": {"bytes": 0, "sha256": empty_sha, "base64": ""},
                    "inputs": [],
                    "expected": {
                        "exitCode": 0,
                        "stdout": {
                            "bytes": 0,
                            "sha256": empty_sha,
                            "base64": "",
                            "normalizations": [],
                        },
                        "stderr": {
                            "bytes": 0,
                            "sha256": empty_sha,
                            "base64": "",
                            "normalizations": [],
                        },
                        "artifacts": [],
                    },
                }
            ],
        }
    )

    summary = _object(
        report["summary"], "report.summary", {"cases", "passed", "categories"}
    )
    cases = _array(report["cases"], "report.cases", nonempty=True, maximum=MAX_CASES)
    case_count = _integer(
        summary["cases"], "report.summary.cases", minimum=1, maximum=MAX_CASES
    )
    passed = _integer(
        summary["passed"], "report.summary.passed", minimum=1, maximum=MAX_CASES
    )
    if case_count != len(cases) or passed != len(cases):
        raise BehaviorCorpusError("report summary counts do not match report cases")
    categories = _array(
        summary["categories"],
        "report.summary.categories",
        nonempty=True,
        maximum=MAX_CATEGORIES,
    )
    category_names = [
        _identifier(item, f"report.summary.categories[{index}]")
        for index, item in enumerate(categories)
    ]
    if category_names != sorted(set(category_names)):
        raise BehaviorCorpusError("report.summary.categories must be sorted and unique")

    retained = 0
    case_ids: list[str] = []
    for case_index, raw_case in enumerate(cases):
        case_path = f"report.cases[{case_index}]"
        case = _object(
            raw_case,
            case_path,
            {"id", "status", "exitCode", "stdout", "stderr", "artifacts"},
        )
        case_ids.append(_identifier(case["id"], f"{case_path}.id"))
        if case["status"] != "passed":
            raise BehaviorCorpusError(f"{case_path}.status must be passed")
        _integer(case["exitCode"], f"{case_path}.exitCode", minimum=0, maximum=255)
        for field in ("stdout", "stderr"):
            stream_path = f"{case_path}.{field}"
            stream_record, payload = _validate_blob(
                case[field],
                stream_path,
                maximum=(
                    report_limits.stdout_bytes
                    if field == "stdout"
                    else report_limits.stderr_bytes
                ),
                extra_fields={"normalizations"},
            )
            retained += len(payload)
            normalizations = _array(
                stream_record["normalizations"],
                f"{stream_path}.normalizations",
                maximum=64,
            )
            normalization_ids = [
                _identifier(item, f"{stream_path}.normalizations[{index}]")
                for index, item in enumerate(normalizations)
            ]
            if len(normalization_ids) != len(set(normalization_ids)):
                raise BehaviorCorpusError(f"{stream_path}.normalizations must be unique")
        artifacts = _array(
            case["artifacts"], f"{case_path}.artifacts", maximum=MAX_ARTIFACTS_PER_CASE
        )
        artifact_paths: list[str] = []
        for artifact_index, raw_artifact in enumerate(artifacts):
            artifact_path = f"{case_path}.artifacts[{artifact_index}]"
            artifact = _object(
                raw_artifact,
                artifact_path,
                {"path", "present", "bytes", "sha256", "base64", "mode"},
            )
            artifact_paths.append(
                _relative_path(artifact["path"], f"{artifact_path}.path")
            )
            if not isinstance(artifact["present"], bool):
                raise BehaviorCorpusError(f"{artifact_path}.present must be boolean")
            if artifact["present"]:
                _, payload = _validate_blob(
                    {
                        "bytes": artifact["bytes"],
                        "sha256": artifact["sha256"],
                        "base64": artifact["base64"],
                    },
                    artifact_path,
                    maximum=report_limits.artifact_bytes,
                )
                retained += len(payload)
                mode = _mode(artifact["mode"], f"{artifact_path}.mode")
                if int(mode, 8) & 0o400 == 0:
                    raise BehaviorCorpusError(
                        f"{artifact_path}.mode must keep the owner-readable bit"
                    )
            elif any(
                artifact[field] is not None
                for field in ("bytes", "sha256", "base64", "mode")
            ):
                raise BehaviorCorpusError(
                    f"{artifact_path} absent observations must use null data fields"
                )
        if artifact_paths != sorted(set(artifact_paths)):
            raise BehaviorCorpusError(f"{case_path}.artifacts paths must be sorted and unique")
        if retained > MAX_RETAINED_BINARY_BYTES:
            raise BehaviorCorpusError("report exceeds the aggregate retained-evidence limit")
    if case_ids != sorted(set(case_ids)):
        raise BehaviorCorpusError("report.cases ids must be sorted and unique")
    return report


def validate_corpus_report_pair(
    corpus: dict[str, Any],
    report: dict[str, Any],
    *,
    corpus_payload: bytes | None = None,
) -> dict[str, Any]:
    """Cross-validate deterministic evidence against its exact reviewed corpus."""

    validated_corpus = validate_corpus(corpus)
    validated_report = validate_report(report)
    canonical_corpus = corpus_json_bytes(validated_corpus)
    if corpus_payload is None:
        corpus_payload = canonical_corpus
    else:
        if len(corpus_payload) > MAX_CORPUS_BYTES:
            raise BehaviorCorpusError(
                f"behavior corpus exceeds the {MAX_CORPUS_BYTES}-byte input limit"
            )
        if _decode_json(corpus_payload, "behavior corpus") != validated_corpus:
            raise BehaviorCorpusError(
                "corpus payload does not encode the validated corpus"
            )
        if corpus_payload != canonical_corpus:
            raise BehaviorCorpusError(
                "behavior corpus must use canonical sorted, indented JSON with one final newline"
            )

    if validated_report["corpus"] != {
        "id": validated_corpus["id"],
        "sha256": hashlib.sha256(corpus_payload).hexdigest(),
    }:
        raise BehaviorCorpusError(
            "behavior report does not identify the exact reviewed corpus bytes"
        )
    for field in ("executable", "sandbox", "limits"):
        if validated_report[field] != validated_corpus[field]:
            raise BehaviorCorpusError(
                f"behavior report {field} does not match its reviewed corpus"
            )

    corpus_case_ids = [case["id"] for case in validated_corpus["cases"]]
    report_case_ids = [case["id"] for case in validated_report["cases"]]
    if report_case_ids != corpus_case_ids:
        raise BehaviorCorpusError(
            "behavior report ordered case IDs do not match its reviewed corpus"
        )
    categories = sorted(
        {
            category
            for case in validated_corpus["cases"]
            for category in case["categories"]
        }
    )
    if validated_report["summary"]["categories"] != categories:
        raise BehaviorCorpusError(
            "behavior report category union does not match its reviewed corpus"
        )
    for corpus_case, report_case in zip(
        validated_corpus["cases"], validated_report["cases"], strict=True
    ):
        expected = corpus_case["expected"]
        for field in ("exitCode", "stdout", "stderr", "artifacts"):
            if report_case[field] != expected[field]:
                raise BehaviorCorpusError(
                    f"behavior report case {corpus_case['id']} {field} does not "
                    "match its reviewed expectation"
                )
    return validated_report


def report_json_bytes(report: Mapping[str, Any]) -> bytes:
    validated = validate_report(dict(report))
    payload = (json.dumps(validated, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise BehaviorCorpusError(
            f"behavior report exceeds the {MAX_REPORT_BYTES}-byte output limit"
        )
    return payload


def load_report(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular_snapshot(path, "behavior report", MAX_REPORT_BYTES)
    report = validate_report(_decode_json(payload, "behavior report"))
    if payload != report_json_bytes(report):
        raise BehaviorCorpusError(
            "behavior report must use canonical sorted, indented JSON with one final newline"
        )
    return report, payload


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    payload = report_json_bytes(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
