#!/usr/bin/env python3
"""Capture real GCC 16.2.0 metadata, diagnostic, preprocessing and dependency references.

Every case runs the installed `gcc` of the pinned official base image that
`build-toolchain.Dockerfile` builds on, with no network, a read-only root
filesystem, no capabilities, `-nostdinc`, and only staged include roots. Each
case is executed twice in fresh workspaces; any byte difference fails the
capture. `--check` re-captures and compares with the checked-in records.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "oracle/gcc/16.2.0"
PREPROCESSING_RECORD = ORACLE / "preprocessing-reference-evidence.json"
DEPENDENCY_RECORD = ORACLE / "dependency-generation-reference.json"
METADATA_RECORD = ORACLE / "metadata-diagnostic-reference.json"
ORCHESTRATION_RECORD = ORACLE / "orchestration-phase-reference.json"
IMAGE = "docker.io/library/gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0"
IMAGE_CONFIG = "sha256:103614947d5ebe34fc48305dcee29625bcf37fbe12d5d4bbca60e00fa601a22f"
ENVIRONMENT = {"LC_ALL": "C", "SOURCE_DATE_EPOCH": "1786060800", "TZ": "UTC"}
WORKDIR = "/w"
TIMEOUT_SECONDS = 60
ANALYSIS_BOUNDARY = (
    "No Ghidra analysis is part of this record; bundled Ghidra isolation and the "
    "authenticated oracle boundary remain unchanged, and no GHIDRA_HOME fallback "
    "or analyzeHeadless invocation is introduced."
)

# The corpus source is reused byte-for-byte from behavior-corpus.json case compile-file.
SOURCE_C = b"int main(void) { return 0; }\n"

INCLUDE_TREE = {
    "include.c": (
        b'#include "local.h"\n'
        b"#include <common.h>\n"
        b"#include <sys.h>\n"
        b"int value = LOCAL + COMMON + SYS;\n"
    ),
    "quote/local.h": b"#define LOCAL 1\n",
    "inc/a/common.h": b"#include_next <common.h>\n#define COMMON (COMMON_B + 10)\n",
    "inc/b/common.h": b"#define COMMON_B 20\n",
    "sys/sys.h": b"#define SYS 300\n",
}

MACROS_C = (
    b"#ifdef DEFINED\nint defined_value = DEFINED;\n#endif\n"
    b"#ifdef UNDEFINED\nint undefined_value;\n#endif\n"
    b"#define LOCAL_MACRO(x) ((x) * 2)\n"
    b"int local = LOCAL_MACRO(EMPTY 3);\n"
    b"#undef LOCAL_MACRO\n"
    b"#ifndef LOCAL_MACRO\nint removed = 1;\n#endif\n"
    b"const char *flag = FLAG;\n"
)

ASSEMBLY = b"#define REG %eax\n\tmovl $0, REG\n\tret\n"

DEPENDENCY_TREE = {
    "dep.c": b'#include "dep.h"\n#include <sys.h>\nint dep = DEP + SYS;\n',
    "dep.h": b'#include "nested/inner.h"\n#define DEP INNER\n',
    "nested/inner.h": b"#define INNER 7\n",
    "sys/sys.h": b"#define SYS 300\n",
}


def case(case_id, arguments, inputs, stdin=b"", categories=(), nostdinc=True):
    return {
        "id": case_id,
        "arguments": ["-nostdinc", *arguments] if nostdinc else list(arguments),
        "inputs": inputs,
        "stdin": stdin,
        "categories": list(categories),
    }


PREPROCESSING_CASES = [
    case("preprocess-file", ["-E", "source.c"], {"source.c": SOURCE_C}, categories=["file"]),
    case("preprocess-stdin", ["-E", "-"], {}, stdin=SOURCE_C, categories=["stdin"]),
    case(
        "preprocess-stdin-explicit-language",
        ["-x", "c", "-E", "-"],
        {},
        stdin=SOURCE_C,
        categories=["stdin", "language-selection"],
    ),
    case(
        "include-search",
        ["-iquote", "quote", "-Iinc/a", "-Iinc/b", "-isystem", "sys", "-E", "include.c"],
        INCLUDE_TREE,
        categories=["include-search", "include-next"],
    ),
    case(
        "include-search-missing-header",
        ["-E", "missing.c"],
        {"missing.c": b'#include "absent.h"\nint after;\n'},
        categories=["include-search", "diagnostic"],
    ),
    case(
        "macro-definition-undefinition",
        ["-DDEFINED=42", "-DUNDEFINED", "-UUNDEFINED", "-DEMPTY=", "-DFLAG=\"on\"", "-E", "macros.c"],
        {"macros.c": MACROS_C},
        categories=["macro-definition", "macro-undefinition"],
    ),
    case(
        "macro-dump-definitions",
        ["-DDEFINED=42", "-UDEFINED", "-DKEPT=1", "-E", "-dD", "-P", "source.c"],
        {"source.c": SOURCE_C},
        categories=["macro-definition", "macro-undefinition"],
    ),
    case(
        "error-directive",
        ["-E", "error.c"],
        {"error.c": b"int before;\n#error stop here\nint after;\n"},
        categories=["diagnostic"],
    ),
    case(
        "language-assembler-with-cpp-explicit",
        ["-x", "assembler-with-cpp", "-E", "code.txt"],
        {"code.txt": ASSEMBLY},
        categories=["language-selection"],
    ),
    case(
        "language-assembler-with-cpp-suffix",
        ["-E", "code.S"],
        {"code.S": ASSEMBLY},
        categories=["language-selection"],
    ),
    case(
        "language-preprocessed-c-suffix",
        ["-E", "already.i"],
        {"already.i": b"# 1 \"already.c\"\nint already = 1;\n"},
        categories=["language-selection"],
    ),
    case(
        "language-c-explicit-with-output",
        ["-x", "c", "-E", "code.txt", "-o", "code.i"],
        {"code.txt": b"#define V 5\nint v = V;\n"},
        categories=["language-selection", "artifacts"],
    ),
]

DEPENDENCY_CASES = [
    case("dependency-source-c", ["-M", "source.c"], {"source.c": SOURCE_C}, categories=["M"]),
    case("dependency-M", ["-isystem", "sys", "-M", "dep.c"], DEPENDENCY_TREE, categories=["M", "system-header"]),
    case("dependency-MM", ["-isystem", "sys", "-MM", "dep.c"], DEPENDENCY_TREE, categories=["MM", "system-header"]),
    case(
        "dependency-MD-MF",
        ["-isystem", "sys", "-E", "-MD", "-MF", "dep.d", "dep.c", "-o", "dep.i"],
        DEPENDENCY_TREE,
        categories=["MD", "MF", "artifacts"],
    ),
    case(
        "dependency-MT-MP",
        ["-isystem", "sys", "-MM", "-MT", "custom target.o", "-MP", "dep.c"],
        DEPENDENCY_TREE,
        categories=["MM", "MT", "MP"],
    ),
    case(
        "dependency-MQ",
        ["-isystem", "sys", "-MM", "-MQ", "$(obj)/dep.o", "dep.c"],
        DEPENDENCY_TREE,
        categories=["MM", "MQ"],
    ),
    case(
        "dependency-MG-missing-header",
        ["-MM", "-MG", "generated.c"],
        {"generated.c": b'#include "generated.h"\nint g;\n'},
        categories=["MM", "MG"],
    ),
    case(
        "dependency-missing-header",
        ["-MM", "generated.c"],
        {"generated.c": b'#include "generated.h"\nint g;\n'},
        categories=["MM", "diagnostic"],
    ),
]


MALFORMED_C = b"int main(void) { return 0 }\n"


def query(case_id, arguments, categories):
    return case(case_id, arguments, {}, categories=categories, nostdinc=False)


METADATA_CASES = [
    query("version", ["--version"], ["version"]),
    query("dumpversion", ["-dumpversion"], ["version"]),
    query("dumpfullversion", ["-dumpfullversion"], ["version"]),
    query("dumpmachine", ["-dumpmachine"], ["target"]),
    query("verbose-configuration", ["-v"], ["version", "target", "configuration"]),
    query("print-search-dirs", ["-print-search-dirs"], ["search-directory"]),
    query("print-prog-name-cc1", ["-print-prog-name=cc1"], ["search-directory"]),
    query("print-libgcc-file-name", ["-print-libgcc-file-name"], ["search-directory"]),
    query("help", ["--help"], ["help"]),
    query("no-input", [], ["missing-input"]),
    case(
        "missing-input-file",
        ["-c", "absent.c"],
        {},
        categories=["missing-input"],
        nostdinc=False,
    ),
    query("option-missing-argument", ["-o"], ["option-validation", "missing-input"]),
    case(
        "option-invalid-language",
        ["-x", "bogus", "source.c"],
        {"source.c": SOURCE_C},
        categories=["option-validation"],
        nostdinc=False,
    ),
    case(
        "option-invalid-standard",
        ["-std=bogus", "-c", "source.c"],
        {"source.c": SOURCE_C},
        categories=["option-validation", "unsupported-option"],
        nostdinc=False,
    ),
    case(
        "option-invalid-frontend-value",
        ["-march=bogus", "-c", "source.c"],
        {"source.c": SOURCE_C},
        categories=["option-validation"],
    ),
    query("unsupported-long-option", ["--bogus-long"], ["unsupported-option", "missing-input"]),
    case(
        "unsupported-flag-option",
        ["-fbogus-flag", "-c", "source.c"],
        {"source.c": SOURCE_C},
        categories=["unsupported-option"],
        nostdinc=False,
    ),
    case(
        "malformed-source",
        ["-c", "bad.c"],
        {"bad.c": MALFORMED_C},
        categories=["malformed-input"],
    ),
    case(
        "malformed-link-input",
        ["data.bin"],
        {"data.bin": b"\x00not an object\n"},
        categories=["malformed-input"],
        nostdinc=False,
    ),
]

MAIN_C = b'#include <stdio.h>\nint helper(int);\nint main(void) { printf("sum=%d\\n", helper(40)); return helper(1); }\n'
HELPER_C = b"int helper(int x) { return x + 2; }\n"
HELPER_S = b"\t.text\n\t.globl helper\n\t.type helper, @function\nhelper:\n\tleal 2(%rdi), %eax\n\tret\n"
EXIT_C = b"int main(void) { return 7; }\n"


def orchestration(case_id, arguments, inputs, categories, program=None):
    spec = case(case_id, arguments, inputs, categories=categories, nostdinc=False)
    spec["program"] = program
    return spec


ORCHESTRATION_CASES = [
    orchestration("compile-to-assembly", ["-S", "source.c"], {"source.c": SOURCE_C}, ["compile"]),
    orchestration("compile-to-object", ["-c", "source.c"], {"source.c": SOURCE_C}, ["compile", "assemble"]),
    orchestration("compile-pipe", ["-pipe", "-c", "source.c"], {"source.c": SOURCE_C}, ["compile", "assemble", "pipe"]),
    orchestration(
        "compile-save-temps",
        ["-save-temps", "-c", "source.c"],
        {"source.c": SOURCE_C},
        ["preprocess", "compile", "assemble", "save-temps"],
    ),
    orchestration("assemble-only", ["-c", "helper.s"], {"helper.s": HELPER_S}, ["assemble"]),
    orchestration(
        "preprocess-and-assemble",
        ["-c", "code.S", "-o", "code.o"],
        {"code.S": ASSEMBLY},
        ["preprocess", "assemble"],
    ),
    orchestration(
        "link-single",
        ["source.c", "-o", "prog"],
        {"source.c": EXIT_C},
        ["compile", "assemble", "link", "program-behavior"],
        program="prog",
    ),
    orchestration(
        "link-multiple-sources",
        ["main.c", "helper.c", "-o", "prog"],
        {"main.c": MAIN_C, "helper.c": HELPER_C},
        ["compile", "assemble", "link", "program-behavior"],
        program="prog",
    ),
    orchestration(
        "link-mixed-c-and-assembly",
        ["main.c", "helper.s", "-o", "prog"],
        {"main.c": MAIN_C, "helper.s": HELPER_S},
        ["compile", "assemble", "link", "program-behavior"],
        program="prog",
    ),
    orchestration("link-default-output", ["source.c"], {"source.c": EXIT_C}, ["link", "program-behavior"], program="a.out"),
    orchestration(
        "failure-compile",
        ["-c", "bad.c"],
        {"bad.c": MALFORMED_C},
        ["compile", "failure-propagation"],
    ),
    orchestration(
        "failure-assemble-source",
        ["-c", "bad.s"],
        {"bad.s": b"\tbogus_instruction %eax\n"},
        ["assemble", "failure-propagation"],
    ),
    orchestration(
        "failure-assemble-after-compile",
        ["-c", "inline.c"],
        {"inline.c": b'void f(void) { __asm__("bogus_instruction"); }\n'},
        ["compile", "assemble", "failure-propagation"],
    ),
    orchestration(
        "failure-link-undefined-symbol",
        ["main.c", "-o", "prog"],
        {"main.c": MAIN_C},
        ["compile", "assemble", "link", "failure-propagation"],
    ),
]

# Phase tools are recognised by the basename of the first word of a driver command line.
PHASE_TOOLS = {"cc1": "compile", "as": "assemble", "collect2": "link", "lto-wrapper": "lto", "ld": "link"}
TEMPORARY_NAME = re.compile(rb"/tmp/cc[A-Za-z0-9]{6}(\.[A-Za-z0-9]+)?")
TEMPORARY_NORMALIZATION = {
    "pattern": TEMPORARY_NAME.pattern.decode(),
    "replacement": "<tmp-N> plus the original suffix, N numbering distinct names in order of first appearance per stream",
    "reason": "the driver draws temporary file names from mkstemp, so they differ between otherwise identical runs",
    "appliesTo": "driver plans, verbose traces and execution streams; artifacts are never normalized",
}


def normalize_temporaries(data: bytes) -> bytes:
    names: dict[bytes, int] = {}

    def replace(match: re.Match) -> bytes:
        stem = match.group(0)[: len(match.group(0)) - len(match.group(1) or b"")]
        number = names.setdefault(stem, len(names) + 1)
        return b"<tmp-%d>%s" % (number, match.group(1) or b"")

    return TEMPORARY_NAME.sub(replace, data)


def phase_commands(text: str) -> list[dict]:
    commands = []
    for line in text.splitlines():
        if not line.startswith(" "):
            continue
        try:
            argv = shlex.split(line)
        except ValueError:
            continue
        if not argv:
            continue
        tool = PurePosixPath(argv[0]).name
        if tool not in PHASE_TOOLS:
            continue
        phase = "preprocess" if tool == "cc1" and "-E" in argv else PHASE_TOOLS[tool]
        commands.append({"phase": phase, "tool": argv[0], "argv": argv})
    return commands


def run_gcc(runtime: str, scratch: Path, spec: dict, label: str, extra: list[str]) -> tuple[Path, subprocess.CompletedProcess]:
    workspace = scratch / f"{spec['id']}-{label}"
    workspace.mkdir()
    stage(workspace, spec["inputs"])
    return workspace, run_container(runtime, workspace, ["gcc", *extra, *spec["arguments"]], b"")


def orchestrate(runtime: str, scratch: Path, spec: dict, attempt: int) -> dict:
    _, plan = run_gcc(runtime, scratch, spec, f"plan-{attempt}", ["-###"])
    _, trace = run_gcc(runtime, scratch, spec, f"trace-{attempt}", ["-v"])
    workspace, result = run_gcc(runtime, scratch, spec, f"run-{attempt}", [])
    plan_stderr = normalize_temporaries(plan.stderr)
    trace_stderr = normalize_temporaries(trace.stderr)
    observed = {
        "plan": {
            "exitCode": plan.returncode,
            "stderr": stream(plan_stderr),
            "phases": phase_commands(plan_stderr.decode("utf-8", "backslashreplace")),
        },
        "executedPhases": {
            "source": "commands echoed by `gcc -v` before each phase runs; a failing phase stops later ones",
            "exitCode": trace.returncode,
            "stderrSha256": digest(trace_stderr),
            "phases": phase_commands(trace_stderr.decode("utf-8", "backslashreplace")),
        },
        "execution": {
            "exitCode": result.returncode,
            "stdout": stream(normalize_temporaries(result.stdout)),
            "stderr": stream(normalize_temporaries(result.stderr)),
            "artifacts": collect(workspace, spec["inputs"]),
        },
    }
    if spec["program"]:
        program = run_container(runtime, workspace, [f"./{spec['program']}"], b"")
        observed["programBehavior"] = {
            "program": spec["program"],
            "exitCode": program.returncode,
            "stdout": stream(program.stdout),
            "stderr": stream(program.stderr),
        }
    return observed


def capture_orchestration_case(runtime: str, scratch: Path, spec: dict) -> dict:
    first = orchestrate(runtime, scratch, spec, 1)
    second = orchestrate(runtime, scratch, spec, 2)
    if first != second:
        raise SystemExit(f"{spec['id']}: independent repetition differs")
    return {
        "id": spec["id"],
        "categories": spec["categories"],
        "arguments": spec["arguments"],
        "environment": ENVIRONMENT,
        "inputs": [
            {"path": path, "bytes": len(data), "sha256": digest(data)}
            for path, data in sorted(spec["inputs"].items())
        ],
        "observed": first,
        "repetitions": 2,
        "normalizations": ["temporary-file-names"],
    }


def phase_tool_identities(runtime: str, scratch: Path) -> dict:
    workspace = scratch / "phase-identity"
    workspace.mkdir()
    stage(workspace, {})
    script = (
        "set -eu; "
        "for tool in cc1 collect2 lto-wrapper liblto_plugin.so; do "
        "path=$(gcc -print-prog-name=$tool); "
        "printf '%s\\t%s\\t%s\\t%s\\n' \"$tool\" \"$path\" \"$(readlink -f \"$path\")\" \"$(sha256sum < \"$path\" | cut -d' ' -f1)\"; "
        "done; "
        "for tool in as ld; do "
        "path=$(command -v $tool); "
        "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$tool\" \"$path\" \"$(readlink -f \"$path\")\" "
        "\"$(sha256sum < \"$path\" | cut -d' ' -f1)\" \"$($tool --version | head -n 1)\"; "
        "done"
    )
    result = run_container(runtime, workspace, ["sh", "-c", script], b"")
    if result.returncode != 0:
        raise SystemExit(f"phase tool identity query failed: {result.stderr.decode(errors='replace')}")
    identities = {}
    for line in result.stdout.decode().splitlines():
        fields = line.split("\t")
        entry = {"path": fields[1], "resolvedPath": fields[2], "sha256": fields[3]}
        if len(fields) > 4:
            entry["version"] = fields[4]
        identities[fields[0]] = entry
    return {
        "compile": {"role": "cc1", **identities["cc1"]},
        "assemble": {"role": "as", "invokedAs": "as", "lookup": "PATH", **identities["as"]},
        "link": {"role": "collect2", **identities["collect2"]},
        "linkEditor": {"role": "ld", "invokedBy": "collect2", "lookup": "PATH", **identities["ld"]},
        "ltoWrapper": {"role": "lto-wrapper", **identities["lto-wrapper"]},
        "ltoPlugin": {"role": "liblto_plugin.so", "loadedBy": "ld via collect2 -plugin", **identities["liblto_plugin.so"]},
    }


IDENTITY_SUBSTITUTIONS = [
    {
        "token": "gcc",
        "where": "the program-name prefix of driver diagnostics (`gcc: error:`, `gcc: fatal error:`)",
        "permitted": "the basename a candidate driver is invoked as",
    },
    {
        "token": "/usr/local",
        "where": "install-prefix components of search-directory, program-name, libgcc and `-v` configuration output",
        "permitted": "the candidate's configured install prefix, applied to the whole prefix only",
    },
]
IDENTITY_SUBSTITUTION_LIMIT = (
    "No other substitution is permitted: version, target triple, option spellings, "
    "diagnostic wording, exit status and stream assignment must match byte-for-byte."
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stream(data: bytes) -> dict:
    return {
        "bytes": len(data),
        "sha256": digest(data),
        "base64": base64.b64encode(data).decode("ascii"),
        "text": data.decode("utf-8", "backslashreplace"),
    }


def run_container(runtime: str, workspace: Path, arguments: list[str], stdin: bytes) -> subprocess.CompletedProcess:
    command = [
        runtime, "run", "--rm", "-i",
        "--platform", "linux/amd64",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pull", "never",
        "-v", f"{workspace}:{WORKDIR}",
        "-w", WORKDIR,
    ]
    for key, value in sorted(ENVIRONMENT.items()):
        command += ["-e", f"{key}={value}"]
    command += [IMAGE, *arguments]
    return subprocess.run(command, input=stdin, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)


def stage(workspace: Path, inputs: dict[str, bytes]) -> None:
    for relative, data in inputs.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
    # The container user may differ from the host user (rootless userns or docker root).
    for directory in [workspace, *(p for p in workspace.rglob("*") if p.is_dir())]:
        directory.chmod(0o777)


def collect(workspace: Path, inputs: dict[str, bytes]) -> list[dict]:
    artifacts = []
    for path in sorted(p for p in workspace.rglob("*") if p.is_file()):
        relative = path.relative_to(workspace).as_posix()
        data = path.read_bytes()
        if inputs.get(relative) == data:
            continue
        artifacts.append({"path": relative, **stream(data)})
    return artifacts


def execute(runtime: str, scratch: Path, spec: dict, attempt: int) -> dict:
    workspace = scratch / f"{spec['id']}-{attempt}"
    workspace.mkdir()
    stage(workspace, spec["inputs"])
    result = run_container(runtime, workspace, ["gcc", *spec["arguments"]], spec["stdin"])
    return {
        "exitCode": result.returncode,
        "stdout": stream(result.stdout),
        "stderr": stream(result.stderr),
        "artifacts": collect(workspace, spec["inputs"]),
    }


def capture_case(runtime: str, scratch: Path, spec: dict) -> dict:
    first = execute(runtime, scratch, spec, 1)
    second = execute(runtime, scratch, spec, 2)
    if first != second:
        raise SystemExit(f"{spec['id']}: independent repetition differs")
    return {
        "id": spec["id"],
        "categories": spec["categories"],
        "arguments": spec["arguments"],
        "environment": ENVIRONMENT,
        "inputs": [
            {"path": path, "bytes": len(data), "sha256": digest(data)}
            for path, data in sorted(spec["inputs"].items())
        ],
        "stdin": {"bytes": len(spec["stdin"]), "sha256": digest(spec["stdin"])},
        "observed": first,
        "repetitions": 2,
        "normalizations": [],
    }


def toolchain_identity(runtime: str, scratch: Path) -> dict:
    workspace = scratch / "identity"
    workspace.mkdir()
    stage(workspace, {})
    script = (
        "set -eu; "
        "cc1=$(gcc -print-prog-name=cc1); "
        "include=$(gcc -print-file-name=include); "
        "printf '%s\\n' \"$(gcc -dumpfullversion)\" \"$(gcc -dumpmachine)\" \"$(command -v gcc)\" \"$cc1\" \"$include\"; "
        "sha256sum \"$(command -v gcc)\" \"$cc1\""
    )
    result = run_container(runtime, workspace, ["sh", "-c", script], b"")
    if result.returncode != 0:
        raise SystemExit(f"toolchain identity query failed: {result.stderr.decode(errors='replace')}")
    lines = result.stdout.decode().splitlines()
    version, machine, driver, cc1, include = lines[:5]
    hashes = {path: sha for sha, path in (line.split(maxsplit=1) for line in lines[5:])}
    inspect = subprocess.run(
        [runtime, "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True, check=True
    )
    image_id = inspect.stdout.strip()
    if not image_id.startswith("sha256:"):
        image_id = f"sha256:{image_id}"
    if image_id != IMAGE_CONFIG:
        raise SystemExit(f"image config {image_id} does not match pinned {IMAGE_CONFIG}")
    return {
        "image": IMAGE,
        "imageConfig": IMAGE_CONFIG,
        "baseOf": "oracle/gcc/16.2.0/build-toolchain.Dockerfile",
        "platform": "linux/amd64",
        "version": version,
        "target": machine,
        "driver": {"path": driver, "sha256": hashes[driver]},
        "frontend": {"role": "cc1", "path": cc1, "sha256": hashes[cc1]},
        "resourceIncludeDirectory": include,
        "includeSearch": "-nostdinc; only staged workspace include roots are searched",
        "sandbox": "--network none --read-only --cap-drop ALL --security-opt no-new-privileges",
    }


def records(runtime: str, scratch: Path) -> tuple[dict, dict, dict, dict]:
    identity = toolchain_identity(runtime, scratch)
    metadata = [capture_case(runtime, scratch, spec) for spec in METADATA_CASES]
    preprocessing = [capture_case(runtime, scratch, spec) for spec in PREPROCESSING_CASES]
    dependency = [capture_case(runtime, scratch, spec) for spec in DEPENDENCY_CASES]
    phase_tools = phase_tool_identities(runtime, scratch)
    orchestration_cases = [capture_orchestration_case(runtime, scratch, spec) for spec in ORCHESTRATION_CASES]
    capture = {
        "tool": "scripts/capture-gcc-preprocessing-reference.py",
        "independentRepetition": "each case ran twice in fresh workspaces with byte-identical results",
    }
    gaps = {
        "reconstructedCandidateComparison": "unavailable",
        "reason": (
            "These records are the real GCC 16.2.0 frontend reference. Comparing a "
            "reconstructed candidate driver against them is downstream work."
        ),
    }
    return (
        {
            "schemaVersion": 2,
            "issue": 709,
            "id": "gcc-16-2-0-preprocessing-reference",
            "status": "captured",
            "scope": "real-frontend-preprocessing",
            "toolchain": identity,
            "capture": capture,
            "cases": preprocessing,
            "productionGates": gaps,
            "analysisBoundary": ANALYSIS_BOUNDARY,
        },
        {
            "schemaVersion": 2,
            "issue": 710,
            "id": "gcc-16-2-0-dependency-generation-reference",
            "status": "captured",
            "scope": "real-frontend-dependency-generation",
            "toolchain": identity,
            "capture": capture,
            "cases": dependency,
            "productionGates": gaps,
            "analysisBoundary": ANALYSIS_BOUNDARY,
        },
        {
            "schemaVersion": 2,
            "issue": 706,
            "id": "gcc-16-2-0-metadata-diagnostic-reference",
            "status": "captured",
            "scope": "real-driver-metadata-and-diagnostics",
            "toolchain": identity,
            "capture": capture,
            "cases": metadata,
            "identitySubstitutions": IDENTITY_SUBSTITUTIONS,
            "identitySubstitutionLimit": IDENTITY_SUBSTITUTION_LIMIT,
            "productionGates": gaps,
            "analysisBoundary": ANALYSIS_BOUNDARY,
        },
        {
            "schemaVersion": 2,
            "issue": 712,
            "id": "gcc-16-2-0-orchestration-phase-reference",
            "status": "captured",
            "scope": "real-driver-phase-orchestration",
            "toolchain": {**identity, "includeSearch": "default system include search", "phaseTools": phase_tools},
            "capture": {
                **capture,
                "runsPerRepetition": (
                    "`gcc -###` for the planned phases, `gcc -v` for the phases actually started, "
                    "then the plain command for exit status, streams and artifacts; linked programs "
                    "are then run in the same sandbox"
                ),
            },
            "normalizations": {"temporary-file-names": TEMPORARY_NORMALIZATION},
            "cases": orchestration_cases,
            "productionGates": {
                **gaps,
                "reason": (
                    "This record is the real GCC 16.2.0 phase-orchestration reference. Replaying a "
                    "reconstructed candidate driver against it, with the same phase tools, is downstream work."
                ),
            },
            "analysisBoundary": ANALYSIS_BOUNDARY,
        },
    )


def render(record: dict) -> str:
    return json.dumps(record, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", default=os.environ.get("CONTAINER_RUNTIME", "docker"))
    parser.add_argument("--scratch", type=Path, help="directory for per-case workspaces")
    parser.add_argument("--check", action="store_true", help="fail if the checked-in records differ")
    args = parser.parse_args()

    scratch_parent = args.scratch or ROOT / "build"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="gcc-preprocessing-", dir=scratch_parent))
    try:
        rendered = {path: render(record) for path, record in zip(
            (PREPROCESSING_RECORD, DEPENDENCY_RECORD, METADATA_RECORD, ORCHESTRATION_RECORD), records(args.runtime, scratch)
        )}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    if args.check:
        stale = [path for path, text in rendered.items() if path.read_text() != text]
        for path in stale:
            print(f"{path.relative_to(ROOT)} differs from a fresh capture", file=sys.stderr)
        return 1 if stale else 0
    for path, text in rendered.items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
