#!/usr/bin/env python3
"""Capture real GCC 16.2.0 metadata, diagnostic, preprocessing and dependency references.

Every case runs in the pinned official base image that `build-toolchain.Dockerfile`
builds on. Every metadata case runs the authenticated oracle driver mounted at
its configured bindir; frontend cases mount its manifest-pinned cc1. Preprocessing
and dependency cases run the image's installed `gcc`. Runs have
no network, a read-only root
filesystem, no capabilities, and only staged include roots; preprocessing and
dependency cases add `-nostdinc`, metadata cases invoke the driver as users do. Each
case is executed twice in fresh workspaces; any byte difference fails the
capture. `--check` re-captures and compares with the checked-in records.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "oracle/gcc/16.2.0"
PREPROCESSING_RECORD = ORACLE / "preprocessing-reference-evidence.json"
DEPENDENCY_RECORD = ORACLE / "dependency-generation-reference.json"
METADATA_RECORD = ORACLE / "metadata-diagnostic-reference.json"
ORACLE_MANIFEST = ORACLE / "oracle-manifest.json"
BUILD_RECORD = ORACLE / "build-record.json"
ORACLE_DRIVER = ORACLE / "artifacts/gcc-driver.stripped"
ORACLE_FRONTEND_MANIFEST = ORACLE / "cc1-oracle-manifest.json"
ORACLE_FRONTEND_ARCHIVE = ORACLE / "artifacts/gcc-cc1.stripped.xz"
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


# Metadata cases exercise the driver as invoked by users, so none passes -nostdinc.
# Every metadata case runs the authenticated oracle driver. Frontend cases mount
# the same-build manifest-pinned cc1; the malformed-link case selects pinned-image
# collect2 and runtime libraries explicitly because the original install tree is absent.
METADATA_LINK_ENVIRONMENT = {
    "COMPILER_PATH": "/usr/local/libexec/gcc/x86_64-linux-gnu/16.2.0",
    "LIBRARY_PATH": "/usr/local/lib/gcc/x86_64-linux-gnu/16.2.0",
}


def metadata_case(case_id, arguments, categories, inputs=None, frontend=False, link=False):
    spec = case(case_id, arguments, inputs or {}, categories=categories, nostdinc=False)
    spec["driver"] = "oracle"
    spec["frontend"] = frontend
    spec["environment"] = dict(METADATA_LINK_ENVIRONMENT) if link else {}
    return spec


METADATA_CASES = [
    metadata_case("version", ["--version"], ["version"]),
    metadata_case("dumpversion", ["-dumpversion"], ["version"]),
    metadata_case("dumpfullversion", ["-dumpfullversion"], ["version"]),
    metadata_case("dumpmachine", ["-dumpmachine"], ["target"]),
    metadata_case("verbose-configuration", ["-v"], ["version", "target", "configuration"]),
    metadata_case("print-search-dirs", ["-print-search-dirs"], ["search-directory"]),
    metadata_case("print-prog-name-cc1", ["-print-prog-name=cc1"], ["search-directory"]),
    metadata_case("print-libgcc-file-name", ["-print-libgcc-file-name"], ["search-directory"]),
    metadata_case("help", ["--help"], ["help"]),
    metadata_case("no-input", [], ["missing-input"]),
    metadata_case("missing-input-file", ["-c", "absent.c"], ["missing-input"], frontend=True),
    metadata_case("option-missing-argument", ["-o"], ["option-validation", "missing-input"]),
    metadata_case(
        "option-invalid-language",
        ["-x", "bogus", "source.c"],
        ["option-validation"],
        {"source.c": SOURCE_C},
    ),
    metadata_case(
        "option-invalid-standard",
        ["-std=bogus", "-c", "source.c"],
        ["option-validation", "unsupported-option"],
        {"source.c": SOURCE_C},
    ),
    metadata_case(
        "option-invalid-frontend-value",
        ["-march=bogus", "-c", "source.c"],
        ["option-validation"],
        {"source.c": SOURCE_C},
        frontend=True,
    ),
    metadata_case("unsupported-long-option", ["--bogus-long"], ["unsupported-option", "missing-input"]),
    metadata_case(
        "unsupported-flag-option",
        ["-fbogus-flag", "-c", "source.c"],
        ["unsupported-option"],
        {"source.c": SOURCE_C},
    ),
    metadata_case("malformed-source", ["-c", "bad.c"], ["malformed-input"], {"bad.c": MALFORMED_C}, frontend=True),
    metadata_case(
        "malformed-link-input",
        ["data.bin"],
        ["malformed-input"],
        {"data.bin": b"\x00not an object\n"},
        link=True,
    ),
]

# Each pattern's group 1 is the only span the substitution may replace. The driver
# name sites were found by running every case as a differently named symlink;
# `gcc version` in `-v` and `other gcc components` in `--help` are literal text.
def oracle_install_prefix() -> str:
    configure = json.loads(BUILD_RECORD.read_text())["commands"]["configure"]
    return next(argument.split("=", 1)[1] for argument in configure if argument.startswith("--prefix="))


# The oracle driver is mounted at its configured bindir so its prefixes are not relocated.
ORACLE_PREFIX = oracle_install_prefix()
ORACLE_DRIVER_PATH = f"{ORACLE_PREFIX}/bin/gcc"
ORACLE_FRONTEND_PATH = f"{ORACLE_PREFIX}/libexec/gcc/x86_64-pc-linux-gnu/16.2.0/cc1"

IDENTITY_SUBSTITUTIONS = [
    {
        "id": "driver-basename",
        "token": "gcc",
        "where": (
            "the driver program name: the prefix of driver diagnostics (`gcc: error:`, "
            "`gcc: fatal error:`), the `--version` banner (`gcc (GCC) 16.2.0`), and the "
            "`--help` usage line and sub-process sentence (`Usage: gcc`, `invoked by gcc.`)"
        ),
        "permitted": "the basename a candidate driver is invoked as",
        "patterns": [
            r"^(gcc)(?=: (?:fatal )?error: )",
            r"^(gcc)(?= \(GCC\) )",
            r"^Usage: (gcc)(?= \[options\] file\.\.\.$)",
            r"(?<= invoked by )(gcc)(?=\.  )",
        ],
    },
    {
        "id": "driver-argv0",
        "token": ORACLE_DRIVER_PATH,
        "where": "the `COLLECT_GCC=` line of `-v` output",
        "permitted": "the exact argv[0] string a candidate driver is invoked with",
        "patterns": [rf"^COLLECT_GCC=({re.escape(ORACLE_DRIVER_PATH)})$"],
    },
    {
        "id": "install-prefix",
        "token": ORACLE_PREFIX,
        "where": "install-prefix components of search-directory and `-v` configuration output",
        "permitted": "the candidate's configured install prefix, applied to the whole prefix only",
        "patterns": [
            rf"(?<![\w/.])({re.escape(ORACLE_PREFIX)})(?=/)",
            rf"^Configured with: .* --prefix=({re.escape(ORACLE_PREFIX)})(?= |$)",
        ],
    },
]

# Metadata cases are re-run through a symlink with this name to prove the driver-name rules.
ALTERNATE_DRIVER = f"{WORKDIR}/candidate-cc"
ALTERNATE_SUBSTITUTION = {
    "driver-basename": ALTERNATE_DRIVER.rsplit("/", 1)[1],
    "driver-argv0": ALTERNATE_DRIVER,
}

IDENTITY_SUBSTITUTION_LIMIT = (
    "No other substitution is permitted: version, target triple, option spellings, "
    "diagnostic wording, exit status and stream assignment must match byte-for-byte."
)


def substitute(data: bytes, values: dict[str, str]) -> bytes:
    """Replace the group-1 span of each matching identity pattern, line by line."""
    lines = data.decode("utf-8", "surrogateescape").split("\n")
    for rule in IDENTITY_SUBSTITUTIONS:
        if rule["id"] not in values:
            continue
        value = values[rule["id"]]
        for pattern in rule["patterns"]:
            regex = re.compile(pattern)

            def replace(match: re.Match) -> str:
                start, end = match.start(1) - match.start(), match.end(1) - match.start()
                return match.group(0)[:start] + value + match.group(0)[end:]

            lines = [regex.sub(replace, line) for line in lines]
    return "\n".join(lines).encode("utf-8", "surrogateescape")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stream(data: bytes) -> dict:
    return {
        "bytes": len(data),
        "sha256": digest(data),
        "base64": base64.b64encode(data).decode("ascii"),
        "text": data.decode("utf-8", "backslashreplace"),
    }


def run_container(
    runtime: str, workspace: Path, arguments: list[str], stdin: bytes, mounts: tuple = ()
) -> subprocess.CompletedProcess:
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
    for source, target in mounts:
        command += ["-v", f"{source}:{target}:ro"]
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


def execute(runtime: str, scratch: Path, spec: dict, attempt: str, alternate: bool = False) -> dict:
    workspace = scratch / f"{spec['id']}-{attempt}"
    workspace.mkdir()
    stage(workspace, spec["inputs"])
    oracle = spec.get("driver") == "oracle"
    driver = ORACLE_DRIVER_PATH if oracle else "gcc"
    mounts = ((ORACLE_DRIVER, ORACLE_DRIVER_PATH),) if oracle else ()
    if spec.get("frontend"):
        mounts += ((scratch / "oracle-cc1", ORACLE_FRONTEND_PATH),)
    command = [driver, *spec["arguments"]]
    if alternate:
        script = 'ln -s "$(command -v "$1")" "$0" && shift && exec "$0" "$@"'
        command = ["sh", "-c", script, ALTERNATE_DRIVER, driver, *spec["arguments"]]
    if spec.get("environment"):
        command = ["env", *(f"{key}={value}" for key, value in sorted(spec["environment"].items())), *command]
    result = run_container(runtime, workspace, command, spec["stdin"], mounts)
    if alternate:
        (workspace / Path(ALTERNATE_DRIVER).relative_to(WORKDIR)).unlink(missing_ok=True)
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
        **({"driver": spec["driver"]} if "driver" in spec else {}),
        "categories": spec["categories"],
        "arguments": spec["arguments"],
        "environment": {**ENVIRONMENT, **spec.get("environment", {})},
        **({"frontend": "manifest-pinned-oracle-cc1"} if spec.get("frontend") else {}),
        "inputs": [
            {"path": path, "bytes": len(data), "sha256": digest(data)}
            for path, data in sorted(spec["inputs"].items())
        ],
        "stdin": {"bytes": len(spec["stdin"]), "sha256": digest(spec["stdin"])},
        "observed": first,
        "repetitions": 2,
        "normalizations": [],
    }


def check_driver_name_substitution(runtime: str, scratch: Path, spec: dict, observed: dict) -> None:
    alternate = execute(runtime, scratch, spec, "alternate", alternate=True)
    expected = {
        **observed,
        **{
            name: stream(substitute(base64.b64decode(observed[name]["base64"]), ALTERNATE_SUBSTITUTION))
            for name in ("stdout", "stderr")
        },
    }
    if alternate != expected:
        raise SystemExit(f"{spec['id']}: driver-name substitutions do not account for {ALTERNATE_DRIVER}")


def oracle_driver_identity() -> dict:
    manifest = json.loads(ORACLE_MANIFEST.read_text())
    stripped = manifest["artifacts"]["stripped"]
    data = ORACLE_DRIVER.read_bytes()
    if (len(data), digest(data)) != (stripped["bytes"], stripped["sha256"]):
        raise SystemExit(f"{ORACLE_DRIVER.relative_to(ROOT)} does not match {ORACLE_MANIFEST.relative_to(ROOT)}")
    return {
        "id": manifest["oracle"]["id"],
        "artifact": f"oracle/gcc/16.2.0/{stripped['path']}",
        "bytes": stripped["bytes"],
        "sha256": stripped["sha256"],
        "manifest": {"path": "oracle/gcc/16.2.0/oracle-manifest.json", "sha256": digest(ORACLE_MANIFEST.read_bytes())},
        "mountedAt": ORACLE_DRIVER_PATH,
        "installTree": "not retained; the driver and required manifest-pinned frontend are mounted read-only per metadata case",
    }


def prepare_oracle_frontend(scratch: Path, archive: Path = ORACLE_FRONTEND_ARCHIVE) -> dict:
    manifest = json.loads(ORACLE_FRONTEND_MANIFEST.read_text())
    driver_manifest = json.loads(ORACLE_MANIFEST.read_text())
    if manifest["oracle"] != driver_manifest["oracle"] or manifest["inputs"]["sourceLock"] != driver_manifest["inputs"]["sourceLock"]:
        raise SystemExit("frontend and driver oracle source identities differ")
    for role in ("sourceLock", "buildRecord"):
        item = manifest["inputs"][role]
        data = (ORACLE / item["path"]).read_bytes()
        if (len(data), digest(data)) != (item["bytes"], item["sha256"]):
            raise SystemExit(f"frontend {role} does not match its manifest")
    artifact = manifest["artifacts"]["stripped"]
    with archive.open("rb") as source:
        compressed = source.read(artifact["bytes"] + 1)
    if len(compressed) > artifact["bytes"]:
        raise SystemExit("frontend archive exceeds the artifact size bound")
    decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
    try:
        data = decoder.decompress(compressed, max_length=artifact["bytes"] + 1)
    except lzma.LZMAError as error:
        raise SystemExit(f"invalid frontend archive: {error}") from error
    if not decoder.eof or decoder.unused_data or (len(data), digest(data)) != (artifact["bytes"], artifact["sha256"]):
        raise SystemExit("frontend archive does not contain exactly the manifest-pinned artifact")
    target = scratch / "oracle-cc1"
    target.write_bytes(data)
    target.chmod(0o555)
    return {
        "role": "cc1",
        "artifact": f"oracle/gcc/16.2.0/{artifact['path']}",
        "bytes": artifact["bytes"],
        "sha256": artifact["sha256"],
        "archive": {"path": "oracle/gcc/16.2.0/artifacts/gcc-cc1.stripped.xz", "bytes": len(compressed), "sha256": digest(compressed)},
        "manifest": {"path": "oracle/gcc/16.2.0/cc1-oracle-manifest.json", "sha256": digest(ORACLE_FRONTEND_MANIFEST.read_bytes())},
        "source": manifest["oracle"],
        "sourceLock": manifest["inputs"]["sourceLock"],
        "mountedAt": ORACLE_FRONTEND_PATH,
        "scope": "read-only mount for missing-input-file, option-invalid-frontend-value and malformed-source only",
    }


def metadata_link_support(runtime: str, scratch: Path) -> dict:
    workspace = scratch / "metadata-link-identity"
    workspace.mkdir()
    stage(workspace, {})
    paths = {
        "collect2": f"{METADATA_LINK_ENVIRONMENT['COMPILER_PATH']}/collect2",
        "ld": "/usr/bin/ld",
    }
    script = 'set -eu; for path do printf "%s\\t%s\\t%s\\t%s\\n" "$path" "$(readlink -f "$path")" "$(stat -Lc %s "$path")" "$(sha256sum < "$path" | cut -d" " -f1)"; done'
    result = run_container(runtime, workspace, ["sh", "-c", script, "metadata-link-identity", *paths.values()], b"")
    if result.returncode != 0:
        raise SystemExit(f"metadata linker identity query failed: {result.stderr.decode(errors='replace')}")
    lines = [line.split("\t") for line in result.stdout.decode().splitlines()]
    if len(lines) != len(paths) or any(len(line) != 4 for line in lines):
        raise SystemExit("metadata linker identity query returned malformed output")
    return {
        "image": IMAGE,
        "imageConfig": IMAGE_CONFIG,
        "scope": "malformed-link-input only; image collect2 and ld selected by explicit environment",
        "environment": METADATA_LINK_ENVIRONMENT,
        "tools": [{"role": role, "path": row[0], "resolvedPath": row[1], "bytes": int(row[2]), "sha256": row[3]}
                  for role, row in zip(paths, lines)],
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


def records(runtime: str, scratch: Path) -> tuple[dict, dict, dict]:
    identity = toolchain_identity(runtime, scratch)
    oracle_driver = oracle_driver_identity()
    oracle_frontend = prepare_oracle_frontend(scratch)
    link_support = metadata_link_support(runtime, scratch)
    metadata = [capture_case(runtime, scratch, spec) for spec in METADATA_CASES]
    for spec, captured in zip(METADATA_CASES, metadata):
        check_driver_name_substitution(runtime, scratch, spec, captured["observed"])
    preprocessing = [capture_case(runtime, scratch, spec) for spec in PREPROCESSING_CASES]
    dependency = [capture_case(runtime, scratch, spec) for spec in DEPENDENCY_CASES]
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
            "toolchain": {
                **{key: identity[key] for key in ("image", "imageConfig", "baseOf", "platform", "sandbox")},
                "scope": "image runtime; metadata executable owners are oracleDriver, oracleFrontend and linkSupport",
                "includeSearch": "the driver's default include search; no metadata case passes -nostdinc",
            },
            "oracleDriver": oracle_driver,
            "oracleFrontend": oracle_frontend,
            "linkSupport": link_support,
            "driverSelection": (
                "every metadata case runs the authenticated oracle driver; frontend cases mount the "
                "same-source manifest-pinned cc1; malformed-link-input selects pinned-image collect2 "
                "and ld with the recorded COMPILER_PATH and LIBRARY_PATH"
            ),
            "capture": capture,
            "cases": metadata,
            "identitySubstitutions": IDENTITY_SUBSTITUTIONS,
            "identitySubstitutionCheck": (
                f"each case also ran as a symlinked driver {ALTERNATE_DRIVER}; its streams, exit "
                "status and artifacts equal the reference after the driver-basename and "
                "driver-argv0 substitutions"
            ),
            "identitySubstitutionLimit": IDENTITY_SUBSTITUTION_LIMIT,
            "productionGates": gaps,
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
            (PREPROCESSING_RECORD, DEPENDENCY_RECORD, METADATA_RECORD), records(args.runtime, scratch)
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
