"""Issue97 Python compatibility reference observation, never candidate/release authority.

Only the reviewed Clang fixture can be recorded. The two target executions use
one exact historical generic OCI profile; unsupported hosts fail, never skip.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from typing import Any, Mapping

from oracle.behavior_corpus import (
    BehaviorCorpusError, _decode_json, _read_regular_snapshot, _write_exclusive,
    corpus_json_bytes, load_corpus, record_corpus_observations, run_corpus,
    validate_corpus, validate_corpus_report_pair,
)

PROFILE = Path(__file__).resolve().parent / "22.1.6"
HISTORICAL_CORPUS_SHA256 = "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b"
MANIFEST_SHA256 = "5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40"
SOURCE_SHA256 = "067c59ddfc218482261817347938158523e4cf05ef80c3ee31488c5e3582c7f8"
CLANG = {"bytes": 84561368, "sha256": "65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006"}
MARKER = b"issue97-produced-program\n"
ARGUMENTS = ["--target=x86_64-unknown-linux-gnu", "-nostdlib", "-static", "-no-pie",
             "-Wl,--build-id=none", "-Wl,-e,_start", "start.s", "-o", "program"]
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
AUTHORITY = {"kind": "python-compatibility-reference-observation", "candidateExecuted": False,
             "kotlinRuntimeQualified": False, "effectivenessQualified": False, "releaseQualified": False}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _blob(payload: bytes) -> dict[str, Any]:
    return {"bytes": len(payload), "sha256": _sha(payload),
            "base64": base64.b64encode(payload).decode("ascii")}


def _expected(exit_code: int, stdout: bytes = b"") -> dict[str, Any]:
    return {"exitCode": exit_code, "stdout": {**_blob(stdout), "normalizations": []},
            "stderr": {**_blob(b""), "normalizations": []}, "artifacts": []}


def _locked_inputs() -> tuple[dict[str, Any], bytes]:
    historical, payload = load_corpus(PROFILE / "behavior-corpus.json")
    if _sha(payload) != HISTORICAL_CORPUS_SHA256:
        raise BehaviorCorpusError("historical corpus identity changed")
    source = _read_regular_snapshot(PROFILE / "produced-program-start.s", "reviewed start fixture", 4096)
    if _sha(source) != SOURCE_SHA256:
        raise BehaviorCorpusError("reviewed start fixture identity changed")
    return historical, source


def compile_corpus() -> dict[str, Any]:
    historical, source = _locked_inputs()
    corpus = copy.deepcopy(historical)
    corpus.update(id="clang-22-1-6-produced-program-compile-v1", directories=["tmp"], cases=[{
        "id": "compile-reviewed-start", "categories": ["produced-program-compilation"],
        "arguments": list(ARGUMENTS), "environment": {}, "stdin": _blob(b""),
        "inputs": [{"path": "start.s", **_blob(source), "executable": False}],
        "expected": _expected(0),
    }])
    return validate_corpus(corpus)


def _require_static_amd64(payload: bytes) -> None:
    """Bounded ELF inspection only; never load or execute a supplied ELF on the host."""
    if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
        raise BehaviorCorpusError("produced artifact must be ELF64 little-endian")
    kind, machine, version, entry, phoff = struct.unpack_from("<HHIQQ", payload, 16)
    ehsize, phsize, phcount = struct.unpack_from("<HHH", payload, 52)
    if (kind, machine, version, ehsize, phsize) != (2, 62, 1, 64, 56) or not 1 <= phcount <= 64:
        raise BehaviorCorpusError("produced artifact must be bounded static amd64 ET_EXEC")
    if phoff < 64 or phoff + phsize * phcount > len(payload):
        raise BehaviorCorpusError("produced ELF program headers exceed its snapshot")
    executable_entry = False
    for index in range(phcount):
        typ, flags, offset, address, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", payload, phoff + index * phsize)
        if typ in (2, 3):
            raise BehaviorCorpusError("produced ELF must have no interpreter or dynamic dependencies")
        if offset + size > len(payload) or size > memory:
            raise BehaviorCorpusError("produced ELF segment exceeds its snapshot")
        if typ == 1 and flags & 1 and address <= entry < address + size:
            executable_entry = True
    if not executable_entry:
        raise BehaviorCorpusError("produced ELF entry is not in file-backed executable bytes")


def _artifact(report: Mapping[str, Any], maximum: int) -> tuple[dict[str, Any], bytes]:
    try:
        cases = report["cases"]
        if len(cases) != 1 or cases[0]["id"] != "compile-reviewed-start":
            raise BehaviorCorpusError("compilation observation population changed")
        artifacts = cases[0]["artifacts"]
        if len(artifacts) != 1:
            raise BehaviorCorpusError("compilation must produce exactly one program")
        artifact = artifacts[0]
        if set(artifact) != {"path", "present", "bytes", "sha256", "base64", "mode"}:
            raise BehaviorCorpusError("produced artifact fields changed")
        if artifact["path"] != "program" or artifact["present"] is not True or artifact["mode"] != "0o755":
            raise BehaviorCorpusError("produced program path/presence/mode mismatch")
        size = artifact["bytes"]
        if type(size) is not int or not 0 < size <= maximum:
            raise BehaviorCorpusError("produced program exceeds the fixed artifact bound")
        encoded = artifact["base64"]
        if not isinstance(encoded, str) or len(encoded) != 4 * ((size + 2) // 3):
            raise BehaviorCorpusError("produced program encoded size mismatch")
        payload = base64.b64decode(encoded, validate=True)
        if len(payload) != size or _sha(payload) != artifact["sha256"] or base64.b64encode(payload).decode("ascii") != encoded:
            raise BehaviorCorpusError("produced program snapshot identity mismatch")
        _require_static_amd64(payload)
        return dict(artifact), payload
    except (KeyError, TypeError, ValueError) as error:
        raise BehaviorCorpusError("malformed produced artifact observation") from error


def execution_corpus(artifact: Mapping[str, Any]) -> dict[str, Any]:
    corpus = compile_corpus()
    corpus.update(id="clang-22-1-6-produced-program-execution-v1",
                  executable={key: artifact[key] for key in ("bytes", "sha256")}, cases=[{
        "id": "execute-exact-produced-program", "categories": ["produced-program-execution"],
        "arguments": [], "environment": {}, "stdin": _blob(b""), "inputs": [],
        "expected": _expected(42, MARKER),
    }])
    return validate_corpus(corpus)


def verify_observation(document: dict[str, Any]) -> dict[str, Any]:
    """Strict offline cross-binding, not authentication of caller-asserted live execution."""
    fields = {"schemaVersion", "authority", "manifestSha256", "sourceSha256", "compileCorpus",
              "compileReport", "executionCorpus", "executionReport", "producedArtifact"}
    if not isinstance(document, dict) or set(document) != fields or type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1:
        raise BehaviorCorpusError("paired observation envelope changed")
    authority = document["authority"]
    if (not isinstance(authority, dict) or authority != AUTHORITY
            or any(type(authority.get(key)) is not bool for key in AUTHORITY if key != "kind")
            or document["manifestSha256"] != MANIFEST_SHA256 or document["sourceSha256"] != SOURCE_SHA256):
        raise BehaviorCorpusError("paired observation authority or source binding changed")
    draft = compile_corpus()
    recorded, report = document["compileCorpus"], document["compileReport"]
    validate_corpus_report_pair(recorded, report, corpus_payload=corpus_json_bytes(recorded))
    artifact, _ = _artifact(report, draft["limits"]["artifactBytes"])
    draft["cases"][0]["expected"]["artifacts"] = [artifact]
    if recorded != draft:
        raise BehaviorCorpusError("compilation source/argv/profile/limits/expectations changed")
    runtime = execution_corpus(artifact)
    if document["executionCorpus"] != runtime or document["producedArtifact"] != artifact:
        raise BehaviorCorpusError("second execution is not bound to the exact produced snapshot")
    validate_corpus_report_pair(runtime, document["executionReport"], corpus_payload=corpus_json_bytes(runtime))
    return document


def load_observation(path: Path) -> dict[str, Any]:
    payload = _read_regular_snapshot(path, "paired observation", MAX_EVIDENCE_BYTES)
    document = _decode_json(payload, "paired observation")
    if payload != (json.dumps(document, sort_keys=True, indent=2) + "\n").encode():
        raise BehaviorCorpusError("paired observation must be canonical JSON")
    return verify_observation(document)


def _private_snapshot(path: Path, expected: bytes, mode: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BehaviorCorpusError("private produced snapshot is absent or unreadable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != mode:
        raise BehaviorCorpusError("produced snapshot must remain a single-link regular file with exact mode")
    if _read_regular_snapshot(path, "private produced snapshot", len(expected), require_executable=True) != expected:
        raise BehaviorCorpusError("private produced snapshot changed")


def observe_produced_program(manifest_path: Path, artifact_root: Path, temporary_root: Path,
                             *, container_runtime: Path,
                             container_runtime_environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    manifest_payload = _read_regular_snapshot(manifest_path, "locked LLVM manifest", 1024 * 1024)
    if _sha(manifest_payload) != MANIFEST_SHA256:
        raise BehaviorCorpusError("LLVM manifest identity mismatch")
    # Paths come only from the exact checked manifest, never a caller-supplied executable selector.
    manifest = json.loads(manifest_payload)
    relative = manifest["artifacts"]["stripped"]["path"]
    executable = artifact_root / relative
    draft = compile_corpus()
    if draft["executable"] != CLANG:
        raise BehaviorCorpusError("locked Clang identity changed")
    repository = Path(__file__).resolve().parents[2]
    if (not temporary_root.is_absolute() or not temporary_root.is_dir() or temporary_root.is_symlink()
            or not temporary_root.resolve().is_relative_to(repository)
            or not Path(tempfile.gettempdir()).resolve().is_relative_to(repository)):
        raise BehaviorCorpusError("all explicit and generic temporary roots must remain inside the repository")
    # Generic recorder checks the actual Clang snapshot against CLANG before any target execution.
    recorded, compilation = record_corpus_observations(
        draft, executable, container_runtime=container_runtime,
        container_runtime_environment=container_runtime_environment)
    validate_corpus_report_pair(recorded, compilation, corpus_payload=corpus_json_bytes(recorded))
    artifact, payload = _artifact(compilation, draft["limits"]["artifactBytes"])
    expected_compile = compile_corpus()
    expected_compile["cases"][0]["expected"]["artifacts"] = [artifact]
    if recorded != expected_compile:
        raise BehaviorCorpusError("compilation did not match its fixed source/argv/streams contract")
    # payload is the same execution's bounded collector snapshot, not a reopened build path.
    runtime = execution_corpus(artifact)
    with tempfile.TemporaryDirectory(prefix="issue97-produced-", dir=temporary_root) as directory:
        program = Path(directory) / "program"
        _write_exclusive(program, payload, int(artifact["mode"], 8))
        _private_snapshot(program, payload, 0o755)
        try:
            execution = run_corpus(runtime, program, container_runtime=container_runtime,
                                   container_runtime_environment=container_runtime_environment)
        finally:
            _private_snapshot(program, payload, 0o755)
    return verify_observation({"schemaVersion": 1, "authority": dict(AUTHORITY),
        "manifestSha256": MANIFEST_SHA256, "sourceSha256": SOURCE_SHA256,
        "compileCorpus": recorded, "compileReport": compilation, "executionCorpus": runtime,
        "executionReport": execution, "producedArtifact": artifact})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=PROFILE / "oracle-manifest.json")
    parser.add_argument("--verify-observation", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--temporary-root", type=Path)
    parser.add_argument("--container-runtime", type=Path)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    if args.verify_observation is not None:
        if any((args.artifact_root, args.temporary_root, args.container_runtime, args.json_output)):
            parser.error("offline verification does not accept execution arguments")
        try:
            load_observation(args.verify_observation)
        except (BehaviorCorpusError, OSError, ValueError) as error:
            print(f"paired observation verification failed: {error}", file=sys.stderr)
            return 1
        print("Paired compatibility reference cross-binding verified; no execution or attestation inferred")
        return 0
    if any(value is None for value in (args.artifact_root, args.temporary_root, args.container_runtime, args.json_output)):
        parser.error("execution requires artifact-root, temporary-root, container-runtime and json-output")
    # The generic executor's own temporary paths must share the same explicit repository-owned root.
    repository = Path(__file__).resolve().parents[2]
    root = args.temporary_root.absolute()
    if not root.is_dir() or root.is_symlink() or not root.resolve().is_relative_to(repository):
        parser.error("temporary root must be an existing directory inside the repository")
    tempfile.tempdir = os.fspath(root)
    environment = {"DOCKER_HOST": os.environ["DOCKER_HOST"]} if "DOCKER_HOST" in os.environ else None
    try:
        document = observe_produced_program(args.manifest, args.artifact_root, root,
            container_runtime=args.container_runtime, container_runtime_environment=environment)
        payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise BehaviorCorpusError("paired evidence exceeds its fixed retention bound")
        if not args.json_output.absolute().parent.resolve(strict=True).is_relative_to(repository):
            raise BehaviorCorpusError("observation output must remain inside the repository")
        _write_exclusive(args.json_output, payload, 0o600)
    except (BehaviorCorpusError, OSError, ValueError) as error:
        print(f"produced-program observation failed: {error}", file=sys.stderr)
        return 1
    print("Python compatibility reference observation passed: compile + exact produced-program execution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
