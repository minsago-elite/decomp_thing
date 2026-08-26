"""Thin GCC 16.2.0 profile for the generic behavior-corpus recorder.

All driver-specific cases and deterministic companion programs live here.
The generic runner knows only opaque executables, byte inputs, process
observations, artifacts, and an authenticated OCI sandbox.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any, Mapping

from oracle.behavior_corpus import (
    MAX_EXECUTABLE_BYTES,
    OCI_HOST_RESOURCE_POLICY_VERSION,
    OOM_SCORE_ADJUSTMENT,
    PYTHON_PREEXEC_ENFORCER_V1,
    _read_regular_snapshot,
    record_corpus_expectations,
)


IMAGE_DIGEST = "sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248"
CONTROL_CLIENT_BYTES = 42_677_472
CONTROL_CLIENT_SHA256 = "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13"
CONTROL_CLIENT_VERSION = "Docker version 29.7.2, build a7dcaa6\n"
ISOLATION = (
    "network-none-readonly-root-cap-drop-all-no-new-privileges-"
    "pid-ipc-private-cgroup-bounds"
)
IMAGE_ENVIRONMENT = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    (
        "GPG_KEYS=B215C1633BCA0477615F1B35A5B3A004745C015A \t"
        "B3C42148A44E6983B3E4CC0793FA9B1AB75C61B8 \t"
        "90AA470469D3965A87A5DCB494D03953902C9419 \t"
        "80F98B2E0DAB6C8281BDF541A7C8C3B2F71EDF1C \t"
        "7F74F97C103468EE5D750B583AB00996FC26A641 \t"
        "33C235A34C46AA3FFB293709A328C3A2C3C45C06 \t"
        "D3A93CAD751C2AF4F8C7AD516C35B99309B5FA62"
    ),
    (
        "GCC_MIRRORS=https://ftpmirror.gnu.org/gcc \t\t"
        "https://mirrors.kernel.org/gnu/gcc \t\t"
        "https://bigsearcher.com/mirrors/gcc/releases \t\t"
        "http://www.netgull.com/gcc/releases \t\t"
        "https://ftpmirror.gnu.org/gcc \t\t"
        "https://sourceware.org/pub/gcc/releases \t\t"
        "ftp://ftp.gnu.org/gnu/gcc"
    ),
    "GCC_VERSION=16.2.0",
]

SETUP_PROGRAM = r'''import os, stat
source = "/case-inputs"
target = "/workspace"
maximum_bytes = int(os.environ["WORKSPACE_BYTES"])
maximum_entries = int(os.environ["WORKSPACE_ENTRIES"])
target_uid = int(os.environ["TARGET_UID"])
target_gid = int(os.environ["TARGET_GID"])
mount_records = [line.split() for line in open("/proc/self/mountinfo") if " /workspace " in line]
if len(mount_records) != 1:
    raise RuntimeError("workspace mount identity is ambiguous")
mount_record = mount_records[0]
separator = mount_record.index("-")
mount_options = set(mount_record[5].split(","))
super_options = set(mount_record[separator + 3].split(","))
if mount_record[separator + 1] != "tmpfs" or not {"rw", "nosuid", "nodev"}.issubset(mount_options) or "rw" not in super_options:
    raise RuntimeError("workspace is not the required tmpfs mount")
filesystem = os.statvfs(target)
capacity = filesystem.f_blocks * filesystem.f_frsize
if capacity < maximum_bytes or capacity >= maximum_bytes + filesystem.f_frsize or filesystem.f_files != maximum_entries:
    raise RuntimeError("workspace tmpfs quotas do not match the profile")
metadata = os.stat(target, follow_symlinks=False)
if metadata.st_uid != target_uid or metadata.st_gid != target_gid or metadata.st_mode & 0o7777 != 0o700:
    raise RuntimeError("workspace tmpfs ownership does not match the profile")
stack = [(source, target)]
while stack:
    source_root, target_root = stack.pop()
    for entry in sorted(os.scandir(source_root), key=lambda item: item.name):
        source_path = entry.path
        target_path = os.path.join(target_root, entry.name)
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            os.mkdir(target_path, 0o700)
            stack.append((source_path, target_path))
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            mode = 0o500 if metadata.st_mode & 0o111 else 0o400
            source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
            target_fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            try:
                while True:
                    chunk = os.read(source_fd, 1048576)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        view = view[written:]
                os.fchmod(target_fd, mode)
            finally:
                os.close(source_fd)
                os.close(target_fd)
        else:
            raise RuntimeError("case input tree contains a non-regular entry")
'''

COLLECTOR_PROGRAM = r'''import os, stat
source = "/workspace"
target = "/case-results"
maximum_bytes = int(os.environ["WORKSPACE_BYTES"])
maximum_entries = int(os.environ["WORKSPACE_ENTRIES"])
records = []
stack = [("", source)]
logical = allocated = 0
while stack:
    relative_root, source_root = stack.pop()
    for entry in sorted(os.scandir(source_root), key=lambda item: item.name):
        relative = entry.name if not relative_root else relative_root + "/" + entry.name
        metadata = entry.stat(follow_symlinks=False)
        records.append((relative, metadata))
        if len(records) > maximum_entries:
            raise RuntimeError("workspace entry bound exceeded")
        logical += metadata.st_size
        allocated += metadata.st_blocks * 512
        if logical > maximum_bytes or allocated > maximum_bytes:
            raise RuntimeError("workspace byte bound exceeded")
        if metadata.st_mode & 0o7000:
            raise RuntimeError("workspace special mode bits are forbidden")
        if stat.S_ISDIR(metadata.st_mode):
            stack.append((relative, entry.path))
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("workspace contains a non-regular entry")
        elif not metadata.st_mode & 0o400:
            raise RuntimeError("workspace file is not owner-readable")
for relative, metadata in sorted(records, key=lambda item: (item[0].count("/"), item[0])):
    destination = os.path.join(target, *relative.split("/"))
    source_path = os.path.join(source, *relative.split("/"))
    if stat.S_ISDIR(metadata.st_mode):
        os.mkdir(destination, 0o700)
        continue
    source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    remaining = metadata.st_size
    try:
        while remaining:
            chunk = os.read(source_fd, min(remaining, 1048576))
            if not chunk:
                raise RuntimeError("workspace file changed during collection")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise RuntimeError("workspace file grew during collection")
        os.fchmod(destination_fd, metadata.st_mode & 0o777)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
'''

KEEPER_ARGV = ["/usr/bin/sleep", "infinity"]
SETUP_ARGV = ["/usr/bin/python3", "-I", "-S", "-B", "-c", SETUP_PROGRAM]
COLLECTOR_ARGV = [
    "/usr/bin/python3",
    "-I",
    "-S",
    "-B",
    "-c",
    COLLECTOR_PROGRAM,
]

CC1 = b"""#!/bin/sh
set -eu
output=
output_next=0
preprocess=0
missing_input=0
for argument do
    if [ "$output_next" = 1 ]; then
        output=$argument
        output_next=0
        continue
    fi
    case "$argument" in
        -o) output_next=1 ;;
        -E) preprocess=1 ;;
        missing.c) missing_input=1 ;;
    esac
done
if [ "${BEHAVIOR_EXPECT_COMPILER_PATH-}" = 1 ]; then
    if [ "$0" != /workspace/env-tools/cc1 ]; then
        printf '%s\n' 'mock cc1: COMPILER_PATH was not used' >&2
        exit 80
    fi
    printf '%s\n' 'observed-compiler-path=/workspace/env-tools/cc1' >&2
fi
if [ "$missing_input" = 1 ]; then
    printf '%s\n' 'mock cc1: missing input missing.c' >&2
    exit 1
fi
if [ "$preprocess" = 1 ]; then
    if [ -n "$output" ]; then
        printf '%s\n' 'MOCK-PREPROCESSED' > "$output"
    else
        printf '%s\n' 'MOCK-PREPROCESSED'
    fi
else
    if [ -z "$output" ]; then
        printf '%s\n' 'mock cc1: missing output' >&2
        exit 81
    fi
    printf '%s\n' 'MOCK-ASSEMBLY' > "$output"
fi
"""

ASSEMBLER = b"""#!/bin/sh
set -eu
output=
output_next=0
for argument do
    if [ "$output_next" = 1 ]; then
        output=$argument
        output_next=0
        continue
    fi
    [ "$argument" = -o ] && output_next=1
done
if [ -z "$output" ]; then
    printf '%s\n' 'mock as: missing output' >&2
    exit 82
fi
printf 'MOCK-OBJECT\\000v1\n' > "$output"
"""

LINKER = b"""#!/bin/sh
set -eu
output=
output_next=0
for argument do
    if [ "$output_next" = 1 ]; then
        output=$argument
        output_next=0
        continue
    fi
    [ "$argument" = -o ] && output_next=1
done
if [ -z "$output" ]; then
    printf '%s\n' 'mock collect2: missing output' >&2
    exit 83
fi
printf 'MOCK-EXECUTABLE\\000v1\n' > "$output"
chmod 700 "$output"
"""


def _blob(payload: bytes) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def _input(path: str, payload: bytes, *, executable: bool = False) -> dict[str, Any]:
    return {"path": path, **_blob(payload), "executable": executable}


def _absent(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "present": False,
        "bytes": None,
        "sha256": None,
        "base64": None,
        "mode": None,
    }


def _draft_expected(*absent_paths: str, exit_code: int = 0) -> dict[str, Any]:
    empty = _blob(b"")
    return {
        "exitCode": exit_code,
        "stdout": {**empty, "normalizations": []},
        "stderr": {**empty, "normalizations": []},
        "artifacts": [_absent(path) for path in sorted(absent_paths)],
    }


def _case(
    identifier: str,
    categories: list[str],
    arguments: list[str],
    *,
    stdin: bytes = b"",
    inputs: list[dict[str, Any]] | None = None,
    environment: Mapping[str, str] | None = None,
    absent_paths: tuple[str, ...] = (),
    exit_code: int = 0,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "categories": sorted(categories),
        "arguments": arguments,
        "environment": dict(sorted((environment or {}).items())),
        "stdin": _blob(stdin),
        "inputs": sorted(inputs or [], key=lambda item: item["path"]),
        "expected": _draft_expected(*absent_paths, exit_code=exit_code),
    }


def sandbox_profile() -> dict[str, Any]:
    """Return the exact trusted executor profile for this benchmark adapter."""

    return {
        "backend": "oci-container-v1",
        "resourcePolicyVersion": OCI_HOST_RESOURCE_POLICY_VERSION,
        "oomScoreAdjustment": OOM_SCORE_ADJUSTMENT,
        "imageDigest": IMAGE_DIGEST,
        "platform": "linux/amd64",
        "isolation": ISOLATION,
        "imageEnvironment": list(IMAGE_ENVIRONMENT),
        "preExecArgv": [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-B",
            "-c",
            PYTHON_PREEXEC_ENFORCER_V1,
        ],
        "environmentLauncher": "/usr/bin/env",
        "keeperArgv": list(KEEPER_ARGV),
        "setupArgv": list(SETUP_ARGV),
        "collectorArgv": list(COLLECTOR_ARGV),
        "targetUser": "65534:65534",
        "controlClient": {
            "bytes": CONTROL_CLIENT_BYTES,
            "sha256": CONTROL_CLIENT_SHA256,
            "version": CONTROL_CLIENT_VERSION,
        },
        "engineProfile": {
            "product": "Docker Engine - Community",
            "serverVersion": "29.7.2",
            "serverCommit": "6a43e3d",
            "apiVersion": "1.55",
            "operatingSystem": "linux",
            "architecture": "amd64",
            "kernelVersion": "7.1.8-gentoo-dist-hardened",
            "componentsSha256": (
                "53eac8fe100341b65c87b5840bbf271f1d471f6b74553ba8d410156ebaaab011"
            ),
            "cgroupVersion": 2,
            "cgroupDriver": "systemd",
            "storageDriver": "overlay2",
            "securityOptions": [
                "name=cgroupns",
                "name=rootless",
                "name=seccomp,profile=builtin",
            ],
            "containerRuntime": "runc",
            "containerRuntimePath": "runc",
            "containerRuntimeVersion": "1.4.3",
            "containerRuntimeCommit": "v1.4.3-0-gbb14dab",
            "containerRuntimeFeaturesSha256": (
                "c41c71ffb7a88612341e64b88f053f6b3f18832a9563efab0a5be8d4e664cd2c"
            ),
            "volumePlugin": "local",
        },
    }


def build_draft(executable_path: Path) -> dict[str, Any]:
    executable = _read_regular_snapshot(
        executable_path, "GCC behavior executable", MAX_EXECUTABLE_BYTES
    )
    cc1 = _input("tools/cc1", CC1, executable=True)
    assembler = _input("tools/as", ASSEMBLER, executable=True)
    collect2 = _input("tools/collect2", LINKER, executable=True)
    source = b"int main(void) { return 0; }\n"
    assembly = b".text\n.globl corpus_entry\ncorpus_entry:\n  ret\n"
    cases = [
        _case(
            "assembly-file",
            ["artifacts", "assembly", "exit-status"],
            ["-B/workspace/tools/", "-c", "input.s", "-o", "assembly.o"],
            inputs=[assembler, _input("input.s", assembly)],
        ),
        _case(
            "compile-file",
            ["artifacts", "exit-status", "file-compile"],
            ["-B/workspace/tools/", "-c", "source.c", "-o", "file.o"],
            inputs=[assembler, cc1, _input("source.c", source)],
        ),
        _case(
            "compile-stdin",
            ["artifacts", "exit-status", "file-compile", "stdin"],
            ["-B/workspace/tools/", "-x", "c", "-c", "-", "-o", "stdin.o"],
            stdin=source,
            inputs=[assembler, cc1],
        ),
        _case(
            "diagnostic-invalid-input",
            ["diagnostics", "exit-status", "invalid-inputs", "stderr"],
            ["-B/workspace/tools/", "-c", "missing.c", "-o", "missing.o"],
            inputs=[cc1],
            absent_paths=("missing.o",),
            exit_code=1,
        ),
        _case(
            "diagnostic-invalid-option",
            ["diagnostics", "exit-status", "invalid-inputs", "stderr"],
            ["--definitely-not-a-supported-corpus-option"],
            exit_code=1,
        ),
        _case(
            "environment-search-path",
            ["environment-search-paths", "exit-status", "preprocessing", "stderr"],
            ["-E", "source.c"],
            inputs=[
                _input("env-tools/cc1", CC1, executable=True),
                _input("source.c", source),
            ],
            environment={
                "BEHAVIOR_EXPECT_COMPILER_PATH": "1",
                "COMPILER_PATH": "/workspace/env-tools",
            },
        ),
        _case(
            "help-driver",
            ["exit-status", "help", "stdout"],
            ["--help"],
        ),
        _case(
            "linking",
            ["artifacts", "exit-status", "linking"],
            [
                "-B/workspace/tools/",
                "-fno-use-linker-plugin",
                "-nostdlib",
                "source.c",
                "-o",
                "linked.bin",
            ],
            inputs=[assembler, cc1, collect2, _input("source.c", source)],
        ),
        _case(
            "metadata-dumpmachine",
            ["exit-status", "metadata", "stdout", "target-query"],
            ["-dumpmachine"],
        ),
        _case(
            "metadata-dumpversion",
            ["exit-status", "metadata", "stdout"],
            ["-dumpfullversion"],
        ),
        _case(
            "metadata-version",
            ["exit-status", "metadata", "stdout"],
            ["--version"],
        ),
        _case(
            "preprocess-file",
            ["exit-status", "preprocessing", "stdout"],
            ["-B/workspace/tools/", "-E", "source.c"],
            inputs=[cc1, _input("source.c", source)],
        ),
        _case(
            "preprocess-stdin",
            ["exit-status", "preprocessing", "stdin", "stdout"],
            ["-B/workspace/tools/", "-E", "-x", "c", "-"],
            stdin=source,
            inputs=[cc1],
        ),
        _case(
            "response-file",
            ["artifacts", "exit-status", "response-files"],
            ["@compile.rsp"],
            inputs=[
                assembler,
                cc1,
                _input(
                    "compile.rsp",
                    b"-B/workspace/tools/ -c response.c -o response.o\n",
                ),
                _input("response.c", source),
            ],
        ),
    ]
    return {
        "schemaVersion": 1,
        "scope": "production",
        "id": "gcc-16-2-0-driver-behavior",
        "executable": {
            "bytes": len(executable),
            "sha256": hashlib.sha256(executable).hexdigest(),
        },
        "sandbox": sandbox_profile(),
        "environment": {
            "clearInherited": True,
            "variables": {
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "SOURCE_DATE_EPOCH": "1786060800",
                "TMPDIR": "/workspace/tmp",
                "TZ": "UTC",
            },
        },
        "limits": {
            "timeoutMilliseconds": 5000,
            "stdoutBytes": 262144,
            "stderrBytes": 262144,
            "artifactBytes": 2097152,
            "memoryBytes": 536870912,
            "fileBytes": 2097152,
            "openFiles": 64,
            "processes": 64,
            "cpuSeconds": 5,
            "workspaceBytes": 16777216,
            "workspaceEntries": 512,
        },
        "directories": ["env-tools", "tmp", "tools"],
        "normalizations": [],
        "cases": cases,
    }


def generate_corpus(
    executable_path: Path,
    *,
    container_runtime: Path,
    container_runtime_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return record_corpus_expectations(
        build_draft(executable_path),
        executable_path,
        container_runtime=container_runtime,
        container_runtime_environment=container_runtime_environment,
    )
