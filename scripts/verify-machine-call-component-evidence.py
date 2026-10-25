#!/usr/bin/env python3
"""Offline integrity checks for retained positive-only component evidence, not qualification."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zlib


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 64 * 1024 * 1024
MAX_CONTROL_BYTES = 2 * 1024 * 1024
LIMIT_CEILINGS = {"maximumRoots": 131072, "maximumInstructionsPerRoot": 1000000,
                  "maximumInstructions": 10000000, "maximumCalls": 1000000,
                  "maximumWorkUnits": 100000000, "maximumOutputBytes": MAX_BYTES,
                  "maximumWallMillis": 1800000}
COUNTS = {"rawFunctionSymbols", "roots", "canonicalFunctions", "instructionAttempts", "physicalCallSites",
          "positiveInternalCallSites", "unresolvedCallSites", "rootsWithUnresolvedOwnership", "rootsWithTraversalStops"}
RUNTIME = {"archiveBytes", "archiveSha256", "bridgeSha256", "bundleManifestSha256", "languageId", "languageVersion"}
RUNTIME_PATHS = {"bundleRoot", "ghidraArchivePath"}
SOURCE_PATHS = {
    "ghidra-bridge/src/main/java/decompengine/ghidra/ByteInstructionDecoderV1.java",
    "src/main/kotlin/decompengine/oracle/fulltree/FullTreeElfLayout.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallReportV1.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallWorkerV1.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallsV1.kt",
}


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fields(value: object, expected: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == expected, f"{label}: unknown or missing fields")
    return value


def integer(value: object, minimum: int = 0, maximum: int = MAX_BYTES) -> int:
    require(type(value) is int and minimum <= value <= maximum, "integer exceeds its supported bound")
    return value


def text(value: object, maximum: int = 16384) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and "\0" not in value, "invalid bounded text")
    return value


def digest(value: object, length: int = 64) -> str:
    require(type(value) is str and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None, "noncanonical digest")
    return value


def relative_path(value: object) -> str:
    value = text(value)
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and all(part not in ("", ".", "..") for part in path.parts),
            "path must be normalized and repository relative")
    require("\\" not in value and "\n" not in value and "\r" not in value, "invalid path characters")
    return value


def informational_path(value: object) -> None:
    # These are original-host coordinates only. Never resolve, stat, open, or execute them.
    value = text(value)
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "invalid informational original path")


def repository_path(path: Path, *, existing: bool) -> Path:
    root = REPOSITORY_ROOT.resolve()
    absolute = path if path.is_absolute() else root / path
    require(absolute == Path(os.path.abspath(absolute)), "path must be normalized")
    require(absolute.is_relative_to(root) and absolute != root, "path is outside the repository")
    cursor = root
    for part in absolute.relative_to(root).parts[:-1]:
        cursor /= part
        info = cursor.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "path parent must be an existing nonsymlink directory")
    if existing:
        info = absolute.lstat()
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), "input must be a regular nonsymlink file")
    else:
        require(not os.path.lexists(absolute), "extraction destination already exists")
    return absolute


def read_file(path: Path, maximum: int) -> bytes:
    path = repository_path(path, existing=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "input file exceeds byte bound")
        result = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(result) <= maximum and len(result) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input changed while reading")
        return result


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _preflight_json(source: str) -> None:
    """Bound nesting and value nodes before the standard JSON parser allocates its tree."""
    index = depth = nodes = 0
    while index < len(source):
        char = source[index]
        if char.isspace() or char in ",:":
            index += 1
            continue
        if char in "[{":
            depth += 1
            nodes += 1
            require(depth <= 64, "JSON nesting exceeds bound")
            index += 1
        elif char in "]}":
            depth -= 1
            require(depth >= 0, "JSON nesting is malformed")
            index += 1
        elif char == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            following = index
            while following < len(source) and source[following].isspace():
                following += 1
            if following == len(source) or source[following] != ":":
                nodes += 1
        else:
            nodes += 1
            while index < len(source) and source[index] not in " \r\n\t,]}:":
                index += 1
        require(nodes <= 1000000, "JSON value-node count exceeds bound")
    require(depth == 0, "JSON nesting is incomplete")


def parse_canonical(data: bytes, maximum: int = MAX_BYTES) -> dict:
    require(len(data) <= maximum, "JSON exceeds byte bound")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def number(token: str) -> int:
        require(len(token) <= 256, "JSON integer exceeds bound")
        return int(token)

    def reject_number(token: str) -> None:
        raise VerificationError(f"noninteger/nonfinite JSON number: {token}")

    try:
        source = data.decode("utf-8", errors="strict")
        _preflight_json(source)
        value = json.loads(source, object_pairs_hook=pairs, parse_int=number,
                           parse_float=reject_number, parse_constant=reject_number)
        require(type(value) is dict and canonical_bytes(value) == data, "JSON is not a canonical object")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise VerificationError(f"invalid bounded JSON: {error}") from error


def file_reference(value: object, *, stored: bool = False) -> dict:
    expected = {"path", "bytes", "sha256"}
    if stored:
        expected |= {"compression", "storedBytes", "storedSha256"}
    value = fields(value, expected, "file commitment")
    relative_path(value["path"])
    integer(value["bytes"], 1)
    digest(value["sha256"])
    if stored:
        require(value["compression"] == "gzip", "unsupported report compression")
        integer(value["storedBytes"], 1)
        digest(value["storedSha256"])
    return value


def verify_bytes(data: bytes, reference: dict, *, stored: bool = False) -> None:
    length, checksum = ("storedBytes", "storedSha256") if stored else ("bytes", "sha256")
    require(len(data) == reference[length] and sha256(data).hexdigest() == reference[checksum], "committed bytes or SHA-256 differ")


def inflate_report(data: bytes, maximum: int = MAX_BYTES) -> bytes:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        result = decompressor.decompress(data, maximum + 1)
        require(len(result) <= maximum and not decompressor.unconsumed_tail, "gzip decompressed bytes exceed bound")
        require(decompressor.eof and not decompressor.unused_data, "gzip must contain exactly one complete member and no trailing bytes")
        return result
    except zlib.error as error:
        raise VerificationError(f"invalid gzip: {error}") from error


def git(arguments: list[str], maximum: int = MAX_BYTES) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"})
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(REPOSITORY_ROOT), *arguments],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= maximum, "recorded Git object is missing or exceeds bound")
    return result.stdout


def verify_git_object(specification: str, kind: str) -> int:
    require(git(["cat-file", "-t", specification], 32) == (kind + "\n").encode(), "recorded Git object has wrong type")
    size = git(["cat-file", "-s", specification], 32)
    require(re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", size) is not None, "invalid Git object size")
    return integer(int(size), 0)


def verify_git_blob(commit: str, reference: dict) -> None:
    specification = commit + ":" + reference["path"]
    require(verify_git_object(specification, "blob") == reference["bytes"], "recorded Git blob byte count differs")
    # Type and size are checked first. --no-textconv prevents Git from invoking a content transformer.
    verify_bytes(git(["show", "--no-ext-diff", "--no-textconv", specification], reference["bytes"]), reference)


def false_authority(record: dict) -> None:
    for key in ("complete", "releaseEligible", "negativeCompleteness"):
        require(record[key] is False, f"{key} cannot grant authority")


def verify_report_bindings(evidence: dict, request: dict, report: dict) -> None:
    fields(request, {"schemaVersion", "kind", "canonicalOracle", "richFile", "manifestSha256", "runtime", "limits", "outputPath"}, "request")
    require(type(request["schemaVersion"]) is int and request["schemaVersion"] == 1 and request["kind"] == "independent-machine-call-request-v1", "request schema differs")
    informational_path(request["outputPath"])
    limits = fields(request["limits"], set(LIMIT_CEILINGS), "request limits")
    for key, ceiling in LIMIT_CEILINGS.items():
        integer(limits[key], 1, ceiling)
    runtime = fields(request["runtime"], RUNTIME | RUNTIME_PATHS, "request runtime")
    for key in RUNTIME_PATHS:
        informational_path(runtime[key])
    require({key: runtime[key] for key in RUNTIME} == evidence["runtime"], "request runtime commitment differs")
    for input_key, request_key in (("rich", "richFile"), ("canonicalOracle", "canonicalOracle")):
        reference = fields(request[request_key], {"path", "bytes", "sha256"}, "request input")
        informational_path(reference["path"])
        require(reference["bytes"] == evidence["inputs"][input_key]["bytes"] and type(reference["bytes"]) is int and
                reference["sha256"] == evidence["inputs"][input_key]["sha256"], "request input commitment differs")
    require(request["manifestSha256"] == evidence["inputs"]["artifactManifest"]["sha256"], "request manifest commitment differs")
    fields(report, {"schemaVersion", "kind", "scope", "complete", "releaseEligible", "negativeCompleteness", "canonicalPopulationComplete",
        "rawSymbolPopulationComplete", "inputSha256", "inputBytes", "canonicalOracleSha256", "artifactManifestSha256", "imageBase",
        "languageId", "languageVersion", "decoderAuthentication", "limits", "canonicalOracleRecordLimit", "canonicalPopulation", "roots", "calls", "counts",
        "requestSha256", "runtime", "containmentStatus"}, "report")
    require(type(report["schemaVersion"]) is int and report["schemaVersion"] == 1 and report["kind"] == "independent-machine-call-positive-observations" and
            report["scope"] == "component", "report schema differs")
    false_authority(report)
    require(report["canonicalPopulationComplete"] is True and report["rawSymbolPopulationComplete"] is True, "report input inventory is incomplete")
    require(report["containmentStatus"] == "external-owner-required" and report["decoderAuthentication"] == "authenticated-bundled-worker-v1", "report boundary differs")
    require(report["requestSha256"] == evidence["payloads"]["request"]["sha256"] and report["runtime"] == runtime and
            report["limits"] == limits, "report request/runtime/limit commitment differs")
    fields(report["limits"], set(LIMIT_CEILINGS), "report limits")
    for key, ceiling in LIMIT_CEILINGS.items():
        integer(report["limits"][key], 1, ceiling)
    require(report["inputSha256"] == request["richFile"]["sha256"] and type(report["inputBytes"]) is int and
            report["inputBytes"] == request["richFile"]["bytes"] and report["canonicalOracleSha256"] == request["canonicalOracle"]["sha256"] and
            report["artifactManifestSha256"] == request["manifestSha256"], "report input commitment differs")
    require(report["languageId"] == runtime["languageId"] and report["languageVersion"] == runtime["languageVersion"] and
            type(report["canonicalOracleRecordLimit"]) is int and report["canonicalOracleRecordLimit"] == 20000, "report language or oracle limit differs")
    require(type(report["imageBase"]) is str and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", report["imageBase"]), "invalid image base")
    for name, maximum in (("canonicalPopulation", min(20000, limits["maximumRoots"])), ("roots", limits["maximumRoots"]), ("calls", limits["maximumCalls"])):
        require(type(report[name]) is list and len(report[name]) <= maximum, "report inventory exceeds bound")
    root_ids = set()
    locators = set()
    instructions = unresolved_roots = stopped_roots = 0
    for root in report["roots"]:
        fields(root, {"id", "rva", "endExclusiveRva", "fileOffset", "ownershipProblems", "traversalStops", "traversalStopEvents", "instructionAttempts", "negativeCompleteness", "origins"}, "report root")
        require(root["negativeCompleteness"] is False and text(root["id"]) not in root_ids, "root authority or identity differs")
        root_ids.add(root["id"])
        instructions += integer(root["instructionAttempts"], 0, limits["maximumInstructionsPerRoot"])
        require(all(type(root[key]) is list for key in ("ownershipProblems", "traversalStops", "traversalStopEvents", "origins")), "invalid root inventory")
        for event in root["traversalStopEvents"]:
            fields(event, {"address", "rva", "reason", "targetAddress", "bytesKind", "bytes"}, "traversal stop")
        unresolved_roots += bool(root["ownershipProblems"])
        stopped_roots += bool(root["traversalStops"])
        require(root["origins"], "root has no symbol origin")
        for origin in root["origins"]:
            fields(origin, {"name", "locator", "type", "binding", "visibility", "other", "sectionKind", "sectionIndex", "sectionName", "value", "size"}, "symbol origin")
            require(text(origin["locator"]) not in locators, "duplicate symbol origin")
            locators.add(origin["locator"])
    positives = 0
    for call in report["calls"]:
        fields(call, {"callerRoot", "callerRva", "callerCanonicalId", "instructionRva", "instructionBytes", "instructionLength", "classification",
            "directTargetRva", "directTargetAddress", "rawPcodeCallTargetAddress", "targetAgreement", "targetCanonicalId", "directTargetAddresses",
            "fallthroughAddress", "contextStatus", "disposition", "negativeCompleteness"}, "call site")
        require(call["negativeCompleteness"] is False and text(call["callerRoot"]) in root_ids, "call authority or root reference differs")
        positives += call["disposition"] == "positive-internal-exact-start"
        require(call["classification"] in {"direct-call", "indirect-call"} and
                call["disposition"] in {"positive-internal-exact-start", "unresolved-instruction-overlap", "unresolved-indirect-target",
                    "unresolved-caller-outside-canonical-population", "unresolved-caller-canonical-exclusion", "unresolved-target-outside-canonical-population",
                    "unresolved-target-canonical-exclusion", "unresolved-target-extent"}, "unknown call classification/disposition")
    canonical_ids = set()
    for item in report["canonicalPopulation"]:
        fields(item, {"id", "rva", "exclusion", "rootIds", "disposition"}, "canonical row")
        if item["exclusion"] is not None:
            fields(item["exclusion"], {"kind", "reason"}, "canonical exclusion")
        require(text(item["id"]) not in canonical_ids and type(item["rootIds"]) is list and
                all(type(root) is str and root in root_ids for root in item["rootIds"]), "canonical identity or root reference differs")
        canonical_ids.add(item["id"])
    expected = {"rawFunctionSymbols": len(locators), "roots": len(root_ids), "canonicalFunctions": len(canonical_ids),
        "instructionAttempts": instructions, "physicalCallSites": len(report["calls"]), "positiveInternalCallSites": positives,
        "unresolvedCallSites": len(report["calls"]) - positives, "rootsWithUnresolvedOwnership": unresolved_roots,
        "rootsWithTraversalStops": stopped_roots}
    fields(report["counts"], COUNTS, "report counts")
    require(all(type(value) is int for value in report["counts"].values()) and report["counts"] == expected == evidence["counts"], "retained counts differ from report populations")
    require(instructions <= limits["maximumInstructions"] and len(locators) <= limits["maximumRoots"], "retained population exceeds request bounds")


def verify_evidence(evidence_path: Path) -> tuple[bytes, dict]:
    evidence_path = repository_path(evidence_path, existing=True)
    evidence = parse_canonical(read_file(evidence_path, MAX_CONTROL_BYTES), MAX_CONTROL_BYTES)
    fields(evidence, {"schemaVersion", "kind", "authority", "complete", "releaseEligible", "negativeCompleteness", "containmentStatus",
        "counts", "inputs", "payloads", "producerJar", "runtime", "source"}, "evidence")
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["kind"] == "retained-machine-call-component-evidence" and
            evidence["authority"] == "component-only" and evidence["containmentStatus"] == "external-owner-required", "unsupported evidence boundary")
    false_authority(evidence)
    fields(evidence["counts"], COUNTS, "evidence counts")
    for value in evidence["counts"].values():
        integer(value, 0, 10000000)
    fields(evidence["runtime"], RUNTIME, "evidence runtime")
    runtime = evidence["runtime"]
    require(type(runtime["archiveBytes"]) is int and runtime["archiveBytes"] == 569445154 and
            runtime["archiveSha256"] == "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54" and
            runtime["languageId"] == "x86:LE:64:default" and runtime["languageVersion"] == "4.8", "runtime pins differ")
    for key in ("archiveSha256", "bridgeSha256", "bundleManifestSha256"):
        digest(runtime[key])
    # Metadata only: no producer-JAR bytes are retained, loaded, or attested by this verifier.
    file_reference(evidence["producerJar"])
    inputs = fields(evidence["inputs"], {"artifactManifest", "canonicalOracle", "rich"}, "evidence inputs")
    for reference in inputs.values():
        file_reference(reference)
    payloads = fields(evidence["payloads"], {"report", "request"}, "evidence payloads")
    file_reference(payloads["request"])
    file_reference(payloads["report"], stored=True)
    require(payloads["report"]["path"] != payloads["request"]["path"], "payload paths overlap")
    request_bytes = read_file(evidence_path.parent / payloads["request"]["path"], MAX_CONTROL_BYTES)
    verify_bytes(request_bytes, payloads["request"])
    report_stored = read_file(evidence_path.parent / payloads["report"]["path"], MAX_BYTES)
    verify_bytes(report_stored, payloads["report"], stored=True)
    report_bytes = inflate_report(report_stored)
    verify_bytes(report_bytes, payloads["report"])
    request, report = parse_canonical(request_bytes, MAX_CONTROL_BYTES), parse_canonical(report_bytes)
    verify_report_bindings(evidence, request, report)
    require(len(report_bytes) <= request["limits"]["maximumOutputBytes"], "report exceeds committed output limit")
    source = fields(evidence["source"], {"commit", "tree", "files"}, "source provenance")
    commit, tree = digest(source["commit"], 40), digest(source["tree"], 40)
    try:
        verify_git_object(commit, "commit")
    except VerificationError as error:
        raise VerificationError(f"recorded source commit {commit} is unavailable or invalid; fetch that commit's history before offline verification") from error
    verify_git_object(tree, "tree")
    require(git(["show", "-s", "--format=%T", commit], 64) == (tree + "\n").encode(), "recorded source commit/tree disagree")
    require(type(source["files"]) is list and len(source["files"]) == len(SOURCE_PATHS), "incomplete source inventory")
    for reference in source["files"]:
        file_reference(reference)
    require([item["path"] for item in source["files"]] == sorted(SOURCE_PATHS), "source inventory is not exact and ordered")
    for reference in [*source["files"], *inputs.values()]:
        verify_git_blob(commit, reference)
    return report_bytes, evidence["counts"]


def extract_report(destination: Path, report_bytes: bytes) -> None:
    destination = repository_path(destination, existing=False)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(report_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        destination.unlink()
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="repository-local evidence manifest selected by the benchmark adapter")
    parser.add_argument("--extract-report", type=Path, help="create the exact verified report at a new repository-local path")
    arguments = parser.parse_args(argv)
    try:
        report_bytes, counts = verify_evidence(arguments.evidence)
        if arguments.extract_report is not None:
            extract_report(arguments.extract_report, report_bytes)
    except (VerificationError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified retained component payloads and recorded Git blobs: {counts['physicalCallSites']} call sites, "
          f"{counts['positiveInternalCallSites']} positive internal sites")
    print("Component-only; no production qualification. Producer JAR identity is a recorded build observation; "
          "its bytes and source-to-binary attestation are not verified.")
    if arguments.extract_report is not None:
        print(f"recovered exact report: {arguments.extract_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
