"""Clang 22.1.6 cases for the generic behavior-corpus recorder."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any, Mapping

from oracle.behavior_corpus import (
    MAX_EXECUTABLE_BYTES,
    _read_regular_snapshot,
    record_corpus_expectations,
)
from oracle.gcc.generate_behavior_corpus import sandbox_profile as shared_executor_profile


def _blob(payload: bytes) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def _input(path: str, payload: bytes) -> dict[str, Any]:
    return {"path": path, **_blob(payload), "executable": False}


def _expected(exit_code: int = 0, *absent: str) -> dict[str, Any]:
    empty = _blob(b"")
    return {
        "exitCode": exit_code,
        "stdout": {**empty, "normalizations": []},
        "stderr": {**empty, "normalizations": []},
        "artifacts": [
            {
                "path": path,
                "present": False,
                "bytes": None,
                "sha256": None,
                "base64": None,
                "mode": None,
            }
            for path in sorted(absent)
        ],
    }


def _case(
    identifier: str,
    categories: list[str],
    arguments: list[str],
    *,
    stdin: bytes = b"",
    inputs: list[dict[str, Any]] | None = None,
    exit_code: int = 0,
    absent: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "id": identifier,
        "categories": sorted(categories),
        "arguments": arguments,
        "environment": {},
        "stdin": _blob(stdin),
        "inputs": sorted(inputs or [], key=lambda item: item["path"]),
        "expected": _expected(exit_code, *absent),
    }


def sandbox_profile() -> dict[str, Any]:
    """Bind Clang to the already-reviewed exact generic executor authority."""

    return shared_executor_profile()


def build_draft(executable_path: Path) -> dict[str, Any]:
    executable = _read_regular_snapshot(
        executable_path, "Clang behavior executable", MAX_EXECUTABLE_BYTES
    )
    source = b"int answer(void) { return 42; }\n"
    invalid = b"int broken( {\n"
    cases = [
        _case(
            "compile-file",
            ["artifacts", "file-compile"],
            ["-c", "source.c", "-o", "source.o"],
            inputs=[_input("source.c", source)],
        ),
        _case(
            "compile-stdin",
            ["artifacts", "file-compile", "stdin"],
            ["-x", "c", "-c", "-", "-o", "stdin.o"],
            stdin=source,
        ),
        _case(
            "diagnostic-invalid-option",
            ["diagnostics", "exit-status", "option-handling", "stderr"],
            ["--definitely-not-a-clang-option"],
            exit_code=1,
        ),
        _case(
            "diagnostic-syntax",
            ["diagnostics", "exit-status", "stderr"],
            ["-fsyntax-only", "broken.c"],
            inputs=[_input("broken.c", invalid)],
            exit_code=1,
        ),
        _case("help-driver", ["help", "option-handling", "stdout"], ["--help"]),
        _case(
            "link-program",
            ["artifacts", "linking", "produced-program"],
            [
                "-nostdlib",
                "-Wl,--build-id=none",
                "-Wl,-e,answer",
                "source.c",
                "-o",
                "program",
            ],
            inputs=[_input("source.c", source)],
        ),
        _case("metadata-target", ["metadata", "target-query", "stdout"], ["-dumpmachine"]),
        _case("metadata-version", ["metadata", "stdout"], ["--version"]),
        _case(
            "preprocess-file",
            ["preprocessing", "stdout"],
            ["-E", "-P", "source.c"],
            inputs=[_input("source.c", source)],
        ),
        _case(
            "preprocess-stdin",
            ["preprocessing", "stdin", "stdout"],
            ["-E", "-P", "-x", "c", "-"],
            stdin=source,
        ),
        _case(
            "response-file",
            ["artifacts", "option-handling", "response-files"],
            ["@compile.rsp"],
            inputs=[
                _input("compile.rsp", b"-c response.c -o response.o\n"),
                _input("response.c", source),
            ],
        ),
    ]
    return {
        "schemaVersion": 1,
        "scope": "production",
        "id": "clang-22-1-6-driver-behavior",
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
                "SOURCE_DATE_EPOCH": "1779182222",
                "TMPDIR": "/workspace/tmp",
                "TZ": "UTC",
            },
        },
        "limits": {
            "timeoutMilliseconds": 10000,
            "stdoutBytes": 1048576,
            "stderrBytes": 1048576,
            "artifactBytes": 16777216,
            "memoryBytes": 1073741824,
            "fileBytes": 16777216,
            "openFiles": 128,
            "processes": 128,
            "cpuSeconds": 10,
            "workspaceBytes": 33554432,
            "workspaceEntries": 1024,
        },
        "directories": ["tmp"],
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
