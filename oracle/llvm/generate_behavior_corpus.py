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
    cxx_source = (
        b"template <class T> T twice(T value) { return value + value; }\n"
        b"int answer() { return twice(21); }\n"
    )
    objc_source = b"@interface Box\n- (int)value;\n@end\n@implementation Box\n- (int)value { return 42; }\n@end\n"
    assembly = b".text\n.globl answer\n.type answer,@function\nanswer:\n  mov $42, %eax\n  ret\n"
    cases = [
        _case(
            "assemble-invalid",
            ["assembler", "diagnostics", "exit-status", "stderr"],
            ["-c", "broken.s", "-o", "broken.o"],
            inputs=[_input("broken.s", b".text\nanswer:\n  definitely_not_an_instruction\n")],
            exit_code=1,
            absent=("broken.o",),
        ),
        _case(
            "assemble-valid",
            ["artifacts", "assembler", "object-emission"],
            ["-c", "answer.s", "-o", "answer.o"],
            inputs=[_input("answer.s", assembly)],
        ),
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
            "compile-c-standard",
            ["artifacts", "c", "file-compile", "language-standard"],
            ["-nostdinc", "-std=c17", "-pedantic-errors", "-c", "source.c", "-o", "c17.o"],
            inputs=[_input("source.c", source)],
        ),
        _case(
            "compile-cxx-standard",
            ["artifacts", "cxx", "file-compile", "language-standard", "templates"],
            ["-nostdinc", "-std=c++20", "-c", "source.cpp", "-o", "cxx20.o"],
            inputs=[_input("source.cpp", cxx_source)],
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
        _case(
            "diagnostic-color-always",
            ["color", "diagnostics", "exit-status", "stderr"],
            ["-fcolor-diagnostics", "-fsyntax-only", "broken.c"],
            inputs=[_input("broken.c", invalid)],
            exit_code=1,
        ),
        _case(
            "diagnostic-color-never",
            ["color", "diagnostics", "exit-status", "stderr"],
            ["-fno-color-diagnostics", "-fsyntax-only", "broken.c"],
            inputs=[_input("broken.c", invalid)],
            exit_code=1,
        ),
        _case(
            "diagnostic-error-limit",
            ["diagnostic-limits", "diagnostics", "exit-status", "stderr"],
            ["-ferror-limit=2", "-fsyntax-only", "many.c"],
            inputs=[_input("many.c", b"int a( {\nint b( {\nint c( {\n")],
            exit_code=1,
        ),
        _case(
            "diagnostic-fixit",
            ["caret-ranges", "diagnostics", "exit-status", "fix-its", "stderr"],
            ["-fdiagnostics-parseable-fixits", "-fsyntax-only", "fixit.c"],
            inputs=[_input("fixit.c", b"int main(void) { int value = 1 return value; }\n")],
            exit_code=1,
        ),
        _case(
            "diagnostic-missing-include",
            ["diagnostics", "fatal-errors", "include-search", "stderr"],
            ["-nostdinc", "-fsyntax-only", "missing.c"],
            inputs=[_input("missing.c", b"#include \"absent.h\"\n")],
            exit_code=1,
        ),
        _case(
            "diagnostic-template-backtrace",
            ["cxx", "diagnostics", "notes", "stderr", "templates"],
            ["-nostdinc", "-std=c++20", "-fsyntax-only", "template.cpp"],
            inputs=[
                _input(
                    "template.cpp",
                    b"template<class T> int read(T value) { return value.missing; }\n"
                    b"int answer() { return read(42); }\n",
                )
            ],
            exit_code=1,
        ),
        _case(
            "diagnostic-warning-option",
            ["diagnostics", "option-provenance", "stderr", "warnings"],
            ["-nostdinc", "-Wall", "-Wextra", "-fsyntax-only", "warning.c"],
            inputs=[_input("warning.c", b"int answer(int unused) { return 42; }\n")],
        ),
        _case(
            "driver-missing-linker",
            ["diagnostics", "exit-status", "linking", "missing-tools", "stderr"],
            ["-nostdlib", "-fuse-ld=definitely-missing", "source.c", "-o", "program"],
            inputs=[_input("source.c", source)],
            exit_code=1,
            absent=("program",),
        ),
        _case(
            "driver-print-commands",
            ["assembler", "driver-orchestration", "linking", "stderr"],
            ["-###", "-save-temps=obj", "-nostdlib", "source.c", "-o", "program"],
            inputs=[_input("source.c", source)],
            absent=("program",),
        ),
        _case(
            "emit-assembly",
            ["artifacts", "assembly-emission", "code-generation"],
            ["-nostdinc", "-S", "source.c", "-o", "source.s"],
            inputs=[_input("source.c", source)],
        ),
        _case(
            "emit-llvm-ir",
            ["artifacts", "code-generation", "llvm-ir"],
            ["-nostdinc", "-S", "-emit-llvm", "source.c", "-o", "source.ll"],
            inputs=[_input("source.c", source)],
        ),
        _case("help-driver", ["help", "option-handling", "stdout"], ["--help"]),
        _case(
            "include-search-order",
            ["include-search", "preprocessing", "stdout"],
            ["-E", "-P", "-nostdinc", "-I", "quoted", "-isystem", "system", "source.c"],
            inputs=[
                _input("quoted/value.h", b"int selected = 1;\n"),
                _input("source.c", b"#include <value.h>\n"),
                _input("system/value.h", b"int selected = 2;\n"),
            ],
        ),
        _case(
            "include-trace",
            ["include-search", "include-trace", "preprocessing", "stderr", "stdout"],
            ["-E", "-P", "-H", "-nostdinc", "-I", "include", "source.c"],
            inputs=[
                _input("include/answer.h", b"#define ANSWER 42\n"),
                _input("source.c", b"#include \"answer.h\"\nint answer = ANSWER;\n"),
            ],
        ),
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
        _case(
            "link-undefined-symbol",
            ["diagnostics", "exit-status", "linking", "stderr"],
            ["-save-temps=obj", "-nostdlib", "-Wl,--build-id=none", "undefined.c", "-o", "program"],
            inputs=[_input("undefined.c", b"extern int missing(void); int _start(void) { return missing(); }\n")],
            exit_code=1,
            absent=("program",),
        ),
        _case("metadata-target", ["metadata", "target-query", "stdout"], ["-dumpmachine"]),
        _case("metadata-resource-dir", ["metadata", "resource-directory", "stdout"], ["-print-resource-dir"]),
        _case("metadata-version", ["metadata", "stdout"], ["--version"]),
        _case(
            "modules-flag-supported",
            ["cxx", "modules", "syntax-only"],
            ["-nostdinc", "-std=c++20", "-fmodules", "-fsyntax-only", "source.cpp"],
            inputs=[_input("source.cpp", cxx_source)],
        ),
        _case(
            "objective-c-syntax",
            ["objective-c", "syntax-only"],
            ["-nostdinc", "-x", "objective-c", "-fsyntax-only", "source.m"],
            inputs=[_input("source.m", objc_source)],
        ),
        _case(
            "precompile-header",
            ["artifacts", "pch", "preprocessing-state"],
            [
                "-nostdinc",
                "-x",
                "c-header",
                "-Xclang",
                "-fno-pch-timestamp",
                "answer.h",
                "-o",
                "answer.pch",
            ],
            inputs=[_input("answer.h", b"#ifndef ANSWER_H\n#define ANSWER_H\n#define ANSWER 42\n#endif\n")],
        ),
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
            "preprocess-dependencies",
            ["artifacts", "dependency-output", "preprocessing"],
            ["-nostdinc", "-I", "include", "-MMD", "-MF", "source.d", "-c", "source.c", "-o", "source.o"],
            inputs=[
                _input("include/answer.h", b"#define ANSWER 42\n"),
                _input("source.c", b"#include \"answer.h\"\nint answer(void) { return ANSWER; }\n"),
            ],
        ),
        _case(
            "preprocess-macro-state",
            ["macros", "preprocessing", "stdout"],
            ["-E", "-P", "-nostdinc", "-D", "COMMAND=6", "macro.c"],
            inputs=[
                _input(
                    "macro.c",
                    b"#define JOIN_(a,b) a##b\n#define JOIN(a,b) JOIN_(a,b)\n"
                    b"#define STRING_(x) #x\n#define STRING(x) STRING_(x)\n"
                    b"#define SUM(first, ...) first + __VA_ARGS__\n"
                    b"#if COMMAND == 6\nint JOIN(ans,wer) = SUM(COMMAND, 36);\n"
                    b"const char *name = STRING(answer);\n#endif\n",
                )
            ],
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
        _case(
            "response-file-nested",
            ["artifacts", "option-handling", "response-files"],
            ["@outer.rsp"],
            inputs=[
                _input("inner.rsp", b"-nostdinc -std=c17 -c response.c -o nested.o\n"),
                _input("outer.rsp", b"@inner.rsp\n"),
                _input("response.c", source),
            ],
        ),
        _case(
            "response-file-recursion",
            ["diagnostics", "exit-status", "response-files", "stderr"],
            ["@recursive.rsp"],
            inputs=[_input("recursive.rsp", b"@recursive.rsp\n")],
            exit_code=1,
        ),
        _case(
            "target-i386-object",
            ["artifacts", "object-emission", "target-i386", "target-selection"],
            ["--target=i386-unknown-linux-gnu", "-nostdinc", "-c", "source.c", "-o", "i386.o"],
            inputs=[_input("source.c", source)],
        ),
        _case(
            "target-unsupported-aarch64",
            ["diagnostics", "exit-status", "target-selection", "unsupported-mode"],
            ["--target=aarch64-unknown-linux-gnu", "-nostdinc", "-c", "source.c", "-o", "aarch64.o"],
            inputs=[_input("source.c", source)],
            exit_code=1,
            absent=("aarch64.o",),
        ),
        _case(
            "target-x86-macros",
            ["preprocessing", "stdout", "target-selection", "target-x86-64"],
            ["--target=x86_64-unknown-linux-gnu", "-nostdinc", "-dM", "-E", "-x", "c", "/dev/null"],
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
        "directories": ["include", "quoted", "system", "tmp"],
        "normalizations": [],
        "cases": sorted(cases, key=lambda case: case["id"]),
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
