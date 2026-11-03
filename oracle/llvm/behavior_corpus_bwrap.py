"""LLVM provenance adapter for the generic ``bubblewrap-v1`` behavior corpus backend (issue #97).

The supplemental corpus ``22.1.6/behavior-corpus-bwrap-v1.json`` expresses the issue97
``bubblewrap-hosted-v1`` produced-program observation as ordinary corpus data for the program-neutral
runner in ``oracle.behavior_corpus_bwrap``: the same locked Clang, the same reviewed ``_start``
fixture, the same pinned argv, limits, compile diagnostic and single temporary-object normalization,
plus the reviewed normalized program digest and the explicitly versioned v2 process, kernel-storage
and syscall policies. The original standalone v1 profile keeps its own execution evidence.
It neither reuses nor replaces the historical OCI corpus ``22.1.6/behavior-corpus.json``. It grants no
candidate, Kotlin-runtime, effectiveness or release authority.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from oracle.behavior_corpus import BehaviorCorpusError, _read_regular_snapshot, _write_exclusive
from oracle.behavior_corpus_bwrap import (
    BACKEND,
    BASE_ARGV,
    STORAGE_POLICY_ID,
    storage_filter_identity,
    MAX_REPORT_BYTES,
    blob,
    load_corpus,
    load_report,
    report_json_bytes,
    run_corpus,
    validate_corpus,
    validate_corpus_report_pair,
    write_corpus,
)
from oracle.llvm.produced_program import ARGUMENTS, CLANG, MANIFEST_SHA256, MARKER, PROFILE, _locked_inputs, _sha
from oracle.llvm.produced_program_bwrap import (
    COMPILE_STDERR,
    EXPECTED_EXIT,
    LIMITS,
    TEMP_OBJECT,
    TEMP_OBJECT_NORMAL,
)

CORPUS_ID = "clang-22-1-6-produced-program-bwrap-v1"
GENERIC_PROFILE_ID = "bubblewrap-hosted-v2"
CORPUS_PATH = PROFILE / "behavior-corpus-bwrap-v1.json"
NORMALIZATION_ID = "clang-temporary-object"
# SHA-256 of the produced program after its one temporary-object name is normalized. It was identical
# on hosted ubuntu-24.04 (GNU ld 2.42) and on Gentoo (GNU ld 2.47), so replay pins the content itself.
NORMALIZED_PROGRAM_SHA256 = "410ac003de21de01ecd687f80b754fd9b25d05b20b22bd3a948b41deed5f45de"
# Aggregate bounds the generic backend adds beyond the issue97 per-process limits: tasks the sandbox may
# add to this user's total, and the live quota over its writable workspace and /tmp.
AGGREGATE_LIMITS = {"processes": 32, "writableBytes": 64 * 1024 * 1024, "writableEntries": 64}


def build_corpus() -> dict[str, Any]:
    """The reviewed supplemental corpus, derived only from locked issue97 constants and inputs."""
    _, source = _locked_inputs()
    return validate_corpus({
        "schemaVersion": 1,
        "scope": "production",
        "id": CORPUS_ID,
        "executable": dict(CLANG),
        "sandbox": {
            "backend": BACKEND,
            "profile": GENERIC_PROFILE_ID,
            "storagePolicy": STORAGE_POLICY_ID,
            "syscallPolicy": storage_filter_identity(62),
            "baseArgv": list(BASE_ARGV),
            "executablePath": "/oracle/clang",
            "workspacePath": "/work",
            "programPath": "/oracle/program",
            "executeElfMachine": 62,
            "hostTools": [{"name": "ld", "hostSearchPath": "/usr/bin:/bin", "sandboxPath": "/usr/bin/ld"}],
        },
        "environment": {"LC_ALL": "C", "PATH": "/usr/bin", "TMPDIR": "/tmp"},
        "limits": {**LIMITS, **AGGREGATE_LIMITS},
        "artifactNormalizations": [{
            "id": NORMALIZATION_ID,
            "pattern": TEMP_OBJECT.pattern.decode("ascii"),
            "replacementBase64": base64.b64encode(TEMP_OBJECT_NORMAL).decode("ascii"),
        }],
        "cases": [{
            "id": "reviewed-start-exit-42",
            "categories": ["produced-program-compilation", "produced-program-execution"],
            "repetitions": 2,
            "arguments": list(ARGUMENTS),
            "inputs": [{"path": "start.s", "mode": "0o644", **blob(source)}],
            "expected": {
                "exitCode": 0,
                "stdout": blob(b""),
                "stderr": blob(COMPILE_STDERR),
                "artifacts": [{
                    "path": "program",
                    "mode": "0o755",
                    "normalizations": [NORMALIZATION_ID],
                    "normalizedSha256": NORMALIZED_PROGRAM_SHA256,
                }],
            },
            "execute": {
                "artifact": "program",
                "arguments": [],
                "expected": {"exitCode": EXPECTED_EXIT, "stdout": blob(MARKER), "stderr": blob(b"")},
            },
        }],
    })


def _require_reviewed_corpus(corpus: Mapping[str, Any]) -> None:
    if corpus != build_corpus():
        raise BehaviorCorpusError("supplemental bubblewrap corpus differs from the reviewed issue97 corpus")


def _require_gnu_ld(report: Mapping[str, Any]) -> None:
    tools = {tool["name"]: tool for tool in report["hostTools"]}
    if set(tools) != {"ld"} or not tools["ld"]["versionLine"].startswith("GNU ld "):
        raise BehaviorCorpusError("supplemental profile requires the host GNU ld")


def locate_clang(manifest_path: Path, artifact_root: Path) -> Path:
    """Authenticate the locked manifest and return the stripped Clang path under the artifact root."""
    payload = _read_regular_snapshot(manifest_path, "locked LLVM manifest", 1024 * 1024)
    if _sha(payload) != MANIFEST_SHA256:
        raise BehaviorCorpusError("LLVM manifest identity mismatch")
    stripped = json.loads(payload)["artifacts"]["stripped"]
    if {"bytes": stripped["bytes"], "sha256": stripped["sha256"]} != CLANG:
        raise BehaviorCorpusError("LLVM manifest stripped identity differs from the locked Clang")
    # The manifest is pinned by hash, so its relative path is reviewed data; run_corpus re-hashes the bytes.
    return artifact_root / stripped["path"]


def run_supplemental_corpus(
    corpus_path: Path, manifest_path: Path, artifact_root: Path, *, bwrap: Path, temporary_root: Path
) -> dict[str, Any]:
    corpus, payload = load_corpus(corpus_path)
    _require_reviewed_corpus(corpus)
    report = run_corpus(
        corpus,
        locate_clang(manifest_path, artifact_root),
        corpus_payload=payload,
        bwrap=bwrap,
        temporary_root=temporary_root,
    )
    _require_gnu_ld(report)
    return report


def verify_supplemental_pair(corpus_path: Path, report_path: Path) -> dict[str, Any]:
    """Offline replay of a retained report against the committed corpus; no host access."""
    corpus, corpus_payload = load_corpus(corpus_path)
    _require_reviewed_corpus(corpus)
    report, _ = load_report(report_path)
    checked = validate_corpus_report_pair(corpus, corpus_payload, report)
    _require_gnu_ld(checked)
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-corpus", action="store_true", help="regenerate the committed corpus")
    mode.add_argument("--run", action="store_true", help="run the corpus live under bubblewrap")
    mode.add_argument("--verify-pair", nargs=2, type=Path, metavar=("CORPUS", "REPORT"))
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--manifest", type=Path, default=PROFILE / "oracle-manifest.json")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--temporary-root", type=Path)
    parser.add_argument("--bwrap", type=Path, default=Path("/usr/bin/bwrap"))
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    execution = (args.artifact_root, args.temporary_root, args.json_output)
    if not args.run and any(value is not None for value in execution):
        parser.error("only --run accepts execution arguments")
    try:
        if args.write_corpus:
            write_corpus(args.corpus, build_corpus())
            print(f"wrote {args.corpus}")
            return 0
        if args.verify_pair is not None:
            checked = verify_supplemental_pair(*args.verify_pair)
            runs = sum(len(case["runs"]) for case in checked["cases"])
            print(f"bubblewrap corpus/report pair verified offline: {len(checked['cases'])} case(s), {runs} run(s)")
            return 0
        if any(value is None for value in execution):
            parser.error("--run requires --artifact-root, --temporary-root and --json-output")
        repository = Path(__file__).resolve().parents[2]
        root = args.temporary_root.absolute()
        if not root.is_dir() or root.is_symlink() or not root.resolve().is_relative_to(repository):
            parser.error("temporary root must be an existing directory inside the repository")
        if not args.json_output.absolute().parent.resolve(strict=True).is_relative_to(repository):
            raise BehaviorCorpusError("report output must remain inside the repository")
        report = run_supplemental_corpus(
            args.corpus, args.manifest, args.artifact_root, bwrap=args.bwrap, temporary_root=root
        )
        payload = report_json_bytes(report)
        if len(payload) > MAX_REPORT_BYTES:
            raise BehaviorCorpusError("report exceeds its fixed retention bound")
        _write_exclusive(args.json_output, payload, 0o600)
    except (BehaviorCorpusError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"bubblewrap behavior corpus failed: {error}", file=sys.stderr)
        return 1
    print("bubblewrap behavior corpus passed: every case compiled and executed as the corpus requires")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
