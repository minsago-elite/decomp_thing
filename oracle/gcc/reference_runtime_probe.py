"""Inspect trusted reference ELF runtime inputs inside the pinned GCC image.

This probe never starts an inspected program: it uses readelf and the image's
glibc loader in --list mode. It is not a candidate admission mechanism.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

LOADER = "/lib64/ld-linux-x86-64.so.2"
ENVIRONMENT = {"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1786060800",
               "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}


def identity(path: str) -> dict:
    source = Path(path)
    resolved = source.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"runtime input is not a regular file: {path}")
    data = resolved.read_bytes()
    if not data.startswith(b"\x7fELF"):
        raise ValueError(f"runtime input is not ELF: {path}")
    return {"path": path, "resolvedPath": str(resolved), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def command(*arguments: str) -> str:
    result = subprocess.run(arguments, env=ENVIRONMENT, capture_output=True,
                            text=True, timeout=15, check=True)
    if result.stderr:
        raise ValueError(f"runtime probe emitted stderr: {arguments[0]}: {result.stderr}")
    return result.stdout


def inspect(path: str) -> dict:
    executable = identity(path)
    headers = command("/usr/bin/readelf", "-lW", path)
    interpreters = re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", headers)
    if interpreters not in ([], [LOADER]):
        raise ValueError(f"unexpected ELF interpreter for {path}: {interpreters}")
    dynamic = command("/usr/bin/readelf", "-dW", path)
    if "(RPATH)" in dynamic or "(RUNPATH)" in dynamic:
        raise ValueError(f"runtime search path is not admitted: {path}")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic)
    if not interpreters and not needed:
        return {"elf": executable, "interpreter": None, "needed": [], "libraries": [],
                "kernelObjects": []}
    libraries = {}
    kernel_objects = []
    for line in command(LOADER, "--list", path).splitlines():
        line = line.strip()
        if re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line):
            kernel_objects.append("linux-vdso.so.1")
            continue
        match = re.fullmatch(r"(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)", line)
        if not match:
            raise ValueError(f"unresolved or unsupported loader entry: {line}")
        name, library = match.groups()
        if not library.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/local/lib/")):
            raise ValueError(f"library is outside the immutable image roots: {library}")
        key = name or Path(library).name
        if key in libraries:
            raise ValueError(f"duplicate loader entry: {key}")
        measured = identity(library)
        if not measured["resolvedPath"].startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/local/lib/")):
            raise ValueError(f"resolved library leaves the immutable image roots: {library}")
        libraries[key] = {"name": key, **measured}
    if not set(needed).issubset(libraries):
        raise ValueError(f"incomplete dependency closure for {path}")
    return {"elf": executable, "interpreter": identity(LOADER) if interpreters else None,
            "needed": needed, "libraries": [libraries[key] for key in sorted(libraries)],
            "kernelObjects": kernel_objects}


def main() -> None:
    if not sys.argv[1:]:
        raise ValueError("expected at least one trusted reference ELF")
    print(json.dumps({path: inspect(path) for path in sys.argv[1:]}, sort_keys=True))


if __name__ == "__main__":
    main()
