"""Construct a contained shared-library probe without trusting an ELF's interpreter.

The loader is identified from the already running Python executable. A subject may use that
installed loader (including its system symlink aliases), but it cannot choose a program to execute
on the host. Even the trusted loader's ``--list`` operation runs in an empty, read-only bubblewrap
root: ELF metadata can influence loader behavior, so inspecting it is not a host-safe operation.

This module only reads bounded ELF metadata and constructs the plan. The caller must execute the
plan through its ordinary bounded sandbox process runner, not through a raw subprocess helper.
"""
from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence

from oracle.behavior_corpus import BehaviorCorpusError

MAX_PROGRAM_HEADERS = 64
MAX_INTERPRETER_BYTES = 4096
SYSTEM_LIBRARY_ROOTS = (Path("/lib"), Path("/lib64"), Path("/usr/lib"), Path("/usr/lib64"))
SUBJECT_PATH = "/oracle/subject"


def _absolute_normal_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value.startswith("/") or str(path) != value or ".." in path.parts
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise BehaviorCorpusError(f"{label} must be a canonical absolute ASCII path")
    return value


def elf_interpreter(binary: Path) -> str:
    """Read exactly one bounded ELF64 little-endian PT_INTERP without executing the file."""
    try:
        with binary.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise BehaviorCorpusError("loader input is not a regular ELF file")
            header = stream.read(64)
            if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
                raise BehaviorCorpusError("loader input must be ELF64 little-endian")
            kind, _, version = struct.unpack_from("<HHI", header, 16)
            offset, = struct.unpack_from("<Q", header, 32)
            header_size, entry_size, count = struct.unpack_from("<HHH", header, 52)
            if (
                kind not in (2, 3) or version != 1 or header_size != 64 or entry_size != 56
                or not 1 <= count <= MAX_PROGRAM_HEADERS or offset < 64
                or offset + count * entry_size > metadata.st_size
            ):
                raise BehaviorCorpusError("ELF program-header table is malformed or exceeds its bound")
            stream.seek(offset)
            table = stream.read(count * entry_size)
            if len(table) != count * entry_size:
                raise BehaviorCorpusError("ELF program-header table was truncated")
            interpreters = []
            for index in range(count):
                entry = struct.unpack_from("<IIQQQQQQ", table, index * entry_size)
                if entry[0] != 3:
                    continue
                position, size = entry[2], entry[5]
                if not 2 <= size <= MAX_INTERPRETER_BYTES or position + size > metadata.st_size:
                    raise BehaviorCorpusError("ELF interpreter is malformed or exceeds its bound")
                stream.seek(position)
                encoded = stream.read(size)
                if len(encoded) != size or not encoded.endswith(b"\0") or b"\0" in encoded[:-1]:
                    raise BehaviorCorpusError("ELF interpreter must have one terminal NUL")
                try:
                    interpreters.append(_absolute_normal_path(encoded[:-1].decode("ascii"), "ELF interpreter"))
                except UnicodeError as error:
                    raise BehaviorCorpusError("ELF interpreter is not ASCII") from error
            if len(interpreters) != 1:
                raise BehaviorCorpusError("ELF input must have exactly one interpreter")
            return interpreters[0]
    except OSError as error:
        raise BehaviorCorpusError("cannot read bounded ELF interpreter metadata") from error


@dataclass(frozen=True)
class LoaderProbePlan:
    command: tuple[str, ...]
    interpreter: str
    library_roots: tuple[Path, ...]


def _inside_system_roots(path: str, roots: Sequence[Path]) -> bool:
    """Both the advertised mount path and its host referent stay inside library roots."""
    candidate = Path(path)
    return any(candidate.is_relative_to(root) for root in roots) and any(
        candidate.resolve(strict=True).is_relative_to(root.resolve(strict=True)) for root in roots
    )


def loader_probe_plan(binary: Path, bwrap: Path, base_argv: Sequence[str]) -> LoaderProbePlan:
    """Admit the host loader independently, then plan only an isolated ``--list`` invocation."""
    subject_interpreter = elf_interpreter(binary)
    host_interpreter = elf_interpreter(Path("/proc/self/exe"))
    roots = tuple(root for root in SYSTEM_LIBRARY_ROOTS if root.is_dir())
    try:
        if not roots or not _inside_system_roots(host_interpreter, roots):
            raise BehaviorCorpusError("host ELF loader is outside the supported system library roots")
        if not _inside_system_roots(subject_interpreter, roots) or not os.path.samefile(
            subject_interpreter, host_interpreter
        ):
            raise BehaviorCorpusError("subject ELF interpreter differs from the independently identified host loader")
        if not stat.S_ISREG(os.stat(host_interpreter).st_mode):
            raise BehaviorCorpusError("host ELF loader is not a regular file")
    except OSError as error:
        raise BehaviorCorpusError("subject ELF interpreter is missing or unsupported on this host") from error
    command = [os.fspath(bwrap), *base_argv]
    for root in roots:
        command.extend(("--ro-bind", os.fspath(root), os.fspath(root)))
    # The host cache contains only loader lookup data; no configuration directory is exposed.
    cache = Path("/etc/ld.so.cache")
    if cache.exists():
        if not stat.S_ISREG(cache.lstat().st_mode):
            raise BehaviorCorpusError("host loader cache is not a regular non-symlink file")
        command.extend(("--ro-bind", os.fspath(cache), os.fspath(cache)))
    command.extend(("--ro-bind", os.fspath(binary), SUBJECT_PATH, "--chdir", "/", "--remount-ro", "/"))
    command.extend((host_interpreter, "--list", SUBJECT_PATH))
    return LoaderProbePlan(tuple(command), subject_interpreter, roots)


def validate_probe_libraries(plan: LoaderProbePlan, paths: Sequence[str], maximum: int) -> list[str]:
    """Do not let loader-controlled stdout select arbitrary host files for later snapshotting."""
    values = list(dict.fromkeys((*paths, plan.interpreter)))
    if not values or len(values) > maximum:
        raise BehaviorCorpusError("shared-library closure is empty or exceeds its bound")
    for value in values:
        _absolute_normal_path(value, "resolved library")
        try:
            if not _inside_system_roots(value, plan.library_roots) or not stat.S_ISREG(os.stat(value).st_mode):
                raise BehaviorCorpusError("resolved library is outside the contained system library roots")
        except OSError as error:
            raise BehaviorCorpusError("resolved library is missing or unsupported on this host") from error
    return values
