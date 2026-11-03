"""Block anonymous storage that cannot be charged to the case's bounded tmpfs.

A target can otherwise retain arbitrary write-populated memfd files or detached
System V shared-memory segments without consuming its mounted filesystem quota.
This small filter leaves ordinary compiler/file/process syscalls unchanged. It
is additional to the namespace, process and filesystem limits, not a syscall
allowlist or an independent containment authority.
"""
from __future__ import annotations

import errno
import os
import platform
import stat
import struct
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from oracle.behavior_corpus import BehaviorCorpusError

POLICY_ID = "bounded-file-storage-v1"

# Linux audit architecture and syscall numbers from the native 64-bit syscall ABIs.
_NATIVE_ABIS = {
    "x86_64": (0xC000003E, (319, 29, 447)),  # memfd_create, shmget, memfd_secret
    "aarch64": (0xC00000B7, (279, 194, 447)),
}
_LD_WORD_ABSOLUTE = 0x20
_JUMP_EQUAL = 0x15
_JUMP_GREATER_EQUAL = 0x35
_RETURN = 0x06
_KILL_PROCESS = 0x80000000
_ALLOW = 0x7FFF0000
_DENY = 0x00050000 | errno.EPERM
_MAXIMUM_FILTER_BYTES = 128


def storage_filter_bytes(machine: str | None = None) -> bytes:
    """Return classic BPF for one supported native ABI; compat/x32 calls refuse."""
    machine = platform.machine() if machine is None else machine
    if sys.platform != "linux" or sys.byteorder != "little" or struct.calcsize("P") != 8 or machine not in _NATIVE_ABIS:
        raise BehaviorCorpusError("anonymous-storage filter requires native Linux x86-64 or AArch64")
    audit_arch, calls = _NATIVE_ABIS[machine]
    instructions = [
        (_LD_WORD_ABSOLUTE, 0, 0, 4),  # seccomp_data.arch
        (_JUMP_EQUAL, 1, 0, audit_arch),
        (_RETURN, 0, 0, _KILL_PROCESS),
        (_LD_WORD_ABSOLUTE, 0, 0, 0),  # seccomp_data.nr
        # x32 uses the same audit arch as x86-64 but a different syscall table.
        # No supported native ABI uses this high range (including negative nr).
        (_JUMP_GREATER_EQUAL, 0, 1, 0x40000000),
        (_RETURN, 0, 0, _KILL_PROCESS),
    ]
    for number in calls:
        instructions.extend(((_JUMP_EQUAL, 0, 1, number), (_RETURN, 0, 0, _DENY)))
    instructions.append((_RETURN, 0, 0, _ALLOW))
    payload = b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions)
    if len(payload) > _MAXIMUM_FILTER_BYTES:
        raise BehaviorCorpusError("anonymous-storage filter exceeds its fixed size bound")
    return payload


@contextmanager
def anonymous_storage_filter(scratch: Path) -> Iterator[int]:
    """Retain a private repository-owned regular-file FD for bwrap --seccomp.

    Include the yielded FD in Popen.pass_fds. Bubblewrap consumes and closes it
    while installing the filter before target execution. The parent keeps its
    own copy only through the child lifetime; no memfd allocation is used here.
    """
    payload = storage_filter_bytes()  # Refuse unsupported ABI before creating a file.
    metadata = scratch.lstat()
    repository = Path(__file__).resolve().parents[1]
    if (
        not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not scratch.resolve(strict=True).is_relative_to(repository)
    ):
        raise BehaviorCorpusError("seccomp scratch must be a private owned repository directory")
    with tempfile.TemporaryFile(mode="w+b", dir=scratch) as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise BehaviorCorpusError("seccomp input is not a regular file")
        handle.write(payload)
        handle.flush()
        handle.seek(0)
        yield handle.fileno()
