#!/usr/bin/env python3
"""Offline integrity checks for retained positive-only component evidence, not qualification."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import zlib
from bisect import bisect_left, bisect_right
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Literal, cast, overload

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
RUNTIME_SNAPSHOTS = {"bridgeSnapshot", "bundleManifestSnapshot"}
SOURCE_PATHS = {
    "ghidra-bridge/src/main/java/decompengine/ghidra/ByteInstructionDecoderV1.java",
    "src/main/kotlin/decompengine/oracle/fulltree/FullTreeElfLayout.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallReportV1.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallWorkerV1.kt",
    "src/main/kotlin/decompengine/oracle/machinecalls/IndependentMachineCallsV1.kt",
}
EXTERNAL_SOURCE_PATHS = SOURCE_PATHS | {
    "ghidra-bridge/src/main/java/decompengine/ghidra/ByteStaticMemoryTransferDecoderV1.java",
    *{"src/main/kotlin/decompengine/oracle/externalcalls/" + name + ".kt" for name in (
        "BoundedElfDynamicBindingsV1", "ElfRelocationWriteCoverageV1", "IndependentExternalCallsV1",
        "IndependentExternalCallReportV1", "IndependentExternalCallWorkerV1")},
}
MACHINE_KIND = "retained-machine-call-component-evidence"
EXTERNAL_KIND = "retained-external-call-component-evidence"
EXTERNAL_LIMITS = {key: value for key, value in LIMIT_CEILINGS.items()
                   if key in {"maximumCalls", "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis"}}
EXTERNAL_LIMITS["maximumCalls"] = 100000
EXTERNAL_COUNTS = {"sourcePhysicalSites", "composedSiteRecords", "namespaceEntries", "dispositions"}


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def fields(value: object, expected: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise VerificationError(f"{label}: unknown or missing fields")
    return value


def integer(value: object, minimum: int = 0, maximum: int = MAX_BYTES) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise VerificationError("integer exceeds its supported bound")
    return value


def text(value: object, maximum: int = 16384) -> str:
    if type(value) is not str or not 0 < len(value) <= maximum or "\0" in value:
        raise VerificationError("invalid bounded text")
    return value


def digest(value: object, length: int = 64) -> str:
    if type(value) is not str or re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None:
        raise VerificationError("noncanonical digest")
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


@contextmanager
def open_repository_parent(path: Path, *, existing: bool) -> Iterator[tuple[int, str]]:
    # Pathname preflight is diagnostic only. Every subsequent filesystem operation is
    # anchored to retained nonsymlink directory descriptors, including leaf cleanup.
    selected = repository_path(path, existing=existing)
    root = REPOSITORY_ROOT.resolve()
    parts = selected.relative_to(root).parts
    with ExitStack() as descriptors:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.callback(os.close, parent)
        for part in parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            descriptors.callback(os.close, parent)
        yield parent, parts[-1]


def read_file(path: Path, maximum: int) -> bytes:
    with open_repository_parent(path, existing=True) as (parent, leaf):
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
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
                            env=environment, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= maximum, "recorded Git object is missing or exceeds bound")
    return result.stdout


def verify_git_object(specification: str, kind: str) -> int:
    require(git(["cat-file", "-t", specification], 32) == (kind + "\n").encode(), "recorded Git object has wrong type")
    size = git(["cat-file", "-s", specification], 32)
    require(re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", size) is not None, "invalid Git object size")
    return integer(int(size), 0)


def read_git_blob(commit: str, reference: dict, maximum: int = MAX_BYTES) -> bytes:
    file_reference(reference)
    specification = commit + ":" + reference["path"]
    require(reference["bytes"] <= maximum and verify_git_object(specification, "blob") == reference["bytes"],
            "recorded Git blob byte count differs or exceeds bound")
    # Type and size are checked first. --no-textconv prevents Git from invoking a content transformer.
    data = git(["show", "--no-ext-diff", "--no-textconv", specification], reference["bytes"])
    verify_bytes(data, reference)
    return data


def verify_git_blob(commit: str, reference: dict) -> None:
    read_git_blob(commit, reference)


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
    require(type(report["imageBase"]) is str and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", report["imageBase"]) is not None,
            "invalid image base")
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


@overload
def address(value: object, *, nullable: Literal[False] = False) -> int: ...


@overload
def address(value: object, *, nullable: Literal[True]) -> int | None: ...


def address(value: object, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not str or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", value) is None:
        raise VerificationError("invalid canonical unsigned address")
    return int(value, 16)


def inventory_rows(value: object, keys: set[str], maximum: int, label: str) -> list[dict]:
    if type(value) is not list or len(value) > maximum:
        raise VerificationError(f"{label}: inventory exceeds bound")
    for item in value:
        fields(item, keys, label)
    return cast(list[dict], value)


EXTERNAL_STATUSES = {"retained-canonical-target", "static-import-request-reference"} | {
    "unresolved-" + suffix for suffix in (
        "source-instruction-boundary", "source-caller", "source-target-exclusion", "source-target-extent",
        "null-physical-target", "forwarder-byte-ownership", "memory-decoder-refusal", "forwarder-sequence",
        "memory-transfer", "unexpanded-relocation-writes", "slot-without-relocation", "competing-relocations",
        "relocation-runtime-membership", "slot-memory-ownership", "slot-file-storage", "inactive-symbol-table",
        "irelative-resolver", "relocation-type", "null-symbol-index", "relocation-write-coverage",
        "ifunc-runtime-implementation", "defined-symbol-reference", "symbol-import-identity", "symbol-version",
        "weak-runtime-target", "untyped-import-request")}
INVENTORY_ROWS = {
    "sections": (131072, {"index", "name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entrySize"}),
    "programHeaders": (65535, {"index", "type", "flags", "offset", "virtualAddress", "physicalAddress", "fileSize", "memorySize", "alignment"}),
    "dynamicEntries": (65536, {"index", "fileOffset", "tag", "value"}),
    "dynamicSymbols": (131072, {"tableSectionIndex", "symbolIndex", "locator", "nameOffset", "name", "info", "other", "type", "binding",
        "visibility", "rawSectionIndex", "resolvedSectionIndex", "sectionKind", "value", "size", "version"}),
    "relocations": (1000000, {"sectionIndex", "relocationIndex", "fileOffset", "locator", "symbolTableSectionIndex", "symbolIndex", "offset",
        "type", "addend", "dynamicTables", "slotFileOffset", "slotLoadIndices", "dispositions"}),
    "versionRequirements": (131072, {"sectionIndex", "stringSectionIndex", "recordOffset", "auxiliaryOffset", "providerRequest",
        "providerRequestOffset", "name", "nameOffset", "rawIndex", "index", "flags", "hash"}),
    "versionDefinitions": (131072, {"sectionIndex", "stringSectionIndex", "recordOffset", "rawIndex", "index", "flags", "hash", "name",
        "parentNames", "auxiliaryOffsets", "auxiliaryNameOffsets"}),
}
SYMBOL_VERSION_KEYS = {"sectionIndex", "fileOffset", "raw", "index", "hidden", "kind", "name", "providerRequest"}
SITE_KEYS = {"sourceOrdinal", "callerRoot", "callerCanonicalId", "callerRva", "instructionRva", "instructionBytes", "instructionLength",
    "returnAddress", "physicalClassification", "physicalTargetAddress", "sourceDisposition", "compositionDisposition", "targetBindingDisposition",
    "externalTargetId", "viaForwarder", "memoryProbe", "memoryTransfer", "relocationBinding", "negativeCompleteness"}
TRANSFER_KEYS = {"address", "length", "bytes", "classification", "pointerSlotAddress", "pointerWidthBytes", "relationship", "rawReadOpcode",
    "rawReadOpIndex", "rawTransferOpcode", "rawTransferOpIndex", "rawCopyOpIndices", "contextStatus", "unresolvedReason"}
TRANSFER_CLASSIFICATIONS = {"direct-call", "indirect-call", "direct-jump", "indirect-jump", "return", "ordinary", "unsupported-pcode",
    "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow"}
TRANSFER_CONTEXTS = {"language-default-no-commits-v1", "context-change", "unassessed-userop-context", "unassessed-pcode-context"}
TRANSFER_REFUSALS = {"pcode-bound", "unsupported-transfer-profile", "pcode-varnode-bound", "unsupported-pcode-or-userop",
    "competing-or-invalid-transfers", "internal-pcode-control", "missing-indirect-transfer", "trailing-pcode-after-transfer", "multiple-memory-loads",
    "unsupported-pointer-width", "nondefault-memory-space", "register-transfer", "nonmemory-indirect-value", "overlapping-value-write",
    "missing-value-definition", "unsupported-value-transform", "nondefault-load-space", "nonstatic-load-address", "pointer-slot-wrap",
    "memory-write-before-read", "typed-flow-disagreement", "not-indirect-transfer", "unsupported-context", "unsupported-pcode",
    "unsupported-trap-or-userop", "unsupported-flow"}


def verify_external_inventory(inventory: dict, namespace: dict, checksum: str, input_sha: str, base: str) -> tuple[dict, dict, dict]:
    """Closed retained metadata/identity checks; this does not reparse the ELF or re-execute decoding."""
    fields(inventory, {"schemaVersion", "kind", "authority", "inputSha256", "elfClass", "byteOrder", "elfType", "machine", "imageBase",
        "activeSymbolTableSectionIndex", "symbolPopulationBasis", "complete", "releaseEligible", "negativeCompleteness",
        "neededLibraries", "unsupportedReasons"} | set(INVENTORY_ROWS), "dynamic inventory")
    require(type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1 and
            inventory["kind"] == "independent-elf-dynamic-bindings-v1" and inventory["authority"] == "diagnostic-authenticated-elf-metadata" and
            inventory["symbolPopulationBasis"] == "section-declared-dynsym", "inventory boundary differs")
    false_authority(inventory)
    require(inventory["inputSha256"] == input_sha and inventory["imageBase"] == base and inventory["elfType"] in {"ET_EXEC", "ET_DYN"},
            "inventory input/profile differs")
    for key, value in (("elfClass", 2), ("byteOrder", 1), ("machine", 62)):
        require(type(inventory[key]) is int and inventory[key] == value, "inventory architecture differs")
    integer(inventory["activeSymbolTableSectionIndex"], 1, 131071)
    for key in ("neededLibraries", "unsupportedReasons"):
        require(type(inventory[key]) is list and len(inventory[key]) <= 65536, "inventory string list exceeds bound")
        for value in inventory[key]:
            require(type(value) is str and len(value) <= 16384 and "\0" not in value, "invalid metadata string")
    for key, (maximum, keys) in INVENTORY_ROWS.items():
        inventory_rows(inventory[key], keys, maximum, key)
    # Primitive closure also rules out nested, unrecognized authority objects in scalar fields.
    address_fields = {"flags", "address", "size", "alignment", "entrySize", "virtualAddress", "physicalAddress", "fileSize", "memorySize", "tag", "value"}
    string_fields = {"name", "locator", "sectionKind", "providerRequest"}
    list_fields = {"dynamicTables", "slotLoadIndices", "dispositions", "parentNames", "auxiliaryOffsets", "auxiliaryNameOffsets"}
    for group in INVENTORY_ROWS:
        for row in inventory[group]:
            for key, value in row.items():
                if key == "version":
                    continue  # Closed below with the version schema.
                if key in list_fields:
                    require(type(value) is list and len(value) <= 65535, "metadata array exceeds bound")
                    for item in value:
                        if key in {"slotLoadIndices", "auxiliaryOffsets", "auxiliaryNameOffsets"}:
                            integer(item, 0, (1 << 63) - 1)
                        else:
                            require(type(item) is str and len(item) <= 16384, "invalid metadata array string")
                elif key in string_fields:
                    require(type(value) is str and len(value) <= 16384 and "\0" not in value, "invalid metadata string")
                elif ((key in address_fields and not (key == "flags" and group in {"programHeaders", "versionRequirements", "versionDefinitions"})) or
                        (key == "offset" and group in {"programHeaders", "relocations"})):
                    address(value)
                elif key in {"slotFileOffset", "addend"} and value is None:
                    continue
                else:
                    integer(value, -(1 << 63) if key == "addend" else 0, (1 << 63) - 1)
    symbols, relocations, imports = {}, {}, {}
    namespace_entries = []
    for symbol in inventory["dynamicSymbols"]:
        key = (integer(symbol["tableSectionIndex"], 1, 131071), integer(symbol["symbolIndex"], 0, 131071))
        require(key not in symbols, "duplicate dynamic symbol")
        symbols[key] = symbol
        text(symbol["locator"])
        require(type(symbol["name"]) is str and len(symbol["name"]) <= 16384, "invalid dynamic symbol name")
        version = symbol["version"]
        if version is not None:
            fields(version, SYMBOL_VERSION_KEYS, "symbol version")
            require(type(version["hidden"]) is bool, "invalid version visibility")
            for name in ("sectionIndex", "fileOffset", "raw", "index"):
                integer(version[name], 0, (1 << 63) - 1)
            text(version["kind"], 128)
            for name in ("name", "providerRequest"):
                require(version[name] is None or type(version[name]) is str and len(version[name]) <= 16384, "invalid version request string")
    retained_symbol_populations(inventory, symbols)
    for key, symbol in symbols.items():
        version = symbol["version"]
        if key[1] != 0 and symbol["sectionKind"] == "undefined" and symbol["name"] and symbol["binding"] in (1, 2) and symbol["visibility"] == 0 and symbol["type"] in (0, 2, 10):
            identity = {"schemaVersion": 1, "namespace": "elf-static-import-request-v1", "inputSha256": input_sha,
                "symbolTableSectionIndex": key[0], "symbolIndex": key[1],
                **{name: symbol[name] for name in ("name", "type", "binding", "visibility")},
                "version": None if version is None else {name: version[name] for name in SYMBOL_VERSION_KEYS - {"sectionIndex", "fileOffset"}},
                "weakMayRemainNull": symbol["binding"] == 2, "ifuncImplementationUnresolved": symbol["type"] == 10,
                "runtimeProviderAvailable": False, "runtimeImplementationAvailable": False, "interpositionUnresolved": True}
            identifier = "ext-" + sha256(canonical_bytes(identity)).hexdigest()
            imports[key] = identifier
            namespace_entries.append({"id": identifier, "identity": identity})
    for relocation in inventory["relocations"]:
        locator = text(relocation["locator"])
        require(locator not in relocations, "duplicate relocation locator")
        require((relocation["symbolTableSectionIndex"], relocation["symbolIndex"]) in symbols, "missing relocation symbol")
        address(relocation["offset"])
        relocations[locator] = relocation
    expected_namespace = {"schemaVersion": 1, "kind": "elf-static-import-request-namespace-v1", "inputSha256": input_sha,
        "populationBasis": "eligible-section-declared-undefined-dynamic-symbols", "runtimeImplementationAvailable": False,
        "negativeCompleteness": False, "entries": namespace_entries}
    require(canonical_bytes(namespace) == canonical_bytes(expected_namespace) and checksum == sha256(canonical_bytes(namespace)).hexdigest(),
            "namespace identity/population/hash differs")
    return symbols, relocations, imports


def require_consistent_byte_ranges(ranges: list[tuple[int, int, bytes]], message: str) -> None:
    """Reject contradictory bytes in retained ranges that share the same storage."""
    ranges.sort(key=lambda row: (row[0], row[1], len(row[2])))
    owner = None
    cluster_start = cluster_end = 0
    cluster = bytearray()
    for current_owner, start, data in ranges:
        end = start + len(data)
        if current_owner != owner or start > cluster_end:
            owner, cluster_start, cluster_end, cluster = current_owner, start, end, bytearray(data)
            continue
        overlap = min(max(0, cluster_end - start), len(data))
        offset = start - cluster_start
        require(cluster[offset:offset + overlap] == data[:overlap], message)
        if end > cluster_end:
            cluster.extend(data[overlap:])
            cluster_end = end


def retained_symbol_populations(inventory: dict, symbols: dict) -> None:
    """Bind every retained symbol/name/version entry to its declared section storage."""
    sections = {row["index"]: row for row in inventory["sections"]}
    require(len(sections) == len(inventory["sections"]), "duplicate retained section index")
    tables = {index: row for index, row in sections.items() if row["type"] == 11}
    populations = {index: [] for index in tables}
    versions = {}
    name_ranges = []
    for section in sections.values():
        if section["type"] == 0x6fffffff:
            link = section["link"]
            require(link in tables and link not in versions, "retained VERSYM table linkage/uniqueness differs")
            versions[link] = section
    require(list(symbols) == sorted(symbols), "retained DYNSYM symbols are not ordered")
    for (table_index, index), symbol in symbols.items():
        require(table_index in tables, "retained symbol lacks a DYNSYM section")
        table = tables[table_index]
        strings = sections.get(table["link"])
        require(strings is not None and strings["type"] == 3, "retained symbol string offset/linkage differs")
        assert strings is not None
        string_size = address(strings["size"])
        assert string_size is not None
        encoded_name = symbol["name"].encode("utf-8")
        require(symbol["nameOffset"] <= 0xffffffff and symbol["nameOffset"] < string_size and
                symbol["nameOffset"] + len(encoded_name) + 1 <= string_size and
                (symbol["nameOffset"] != 0 or symbol["name"] == ""),
                "retained symbol name exceeds linked string table")
        require(symbol["info"] <= 255 and symbol["other"] <= 255 and symbol["type"] == symbol["info"] & 15 and
                symbol["binding"] == symbol["info"] >> 4 and symbol["visibility"] == symbol["other"] & 3 and
                (symbol["binding"] == 0) == (index < table["info"]), "retained DYNSYM local-symbol boundary/encoding differs")
        populations[table_index].append(index)
        name_ranges.append((table["link"], symbol["nameOffset"], encoded_name + b"\0"))
        if index == 0:
            require(all(symbol[key] == 0 for key in ("nameOffset", "info", "other", "rawSectionIndex", "resolvedSectionIndex")) and
                    symbol["name"] == "" and symbol["sectionKind"] == "undefined" and
                    symbol["value"] == symbol["size"] == "0x0", "retained DYNSYM null symbol differs")
        version, owner = symbol["version"], versions.get(table_index)
        require((version is not None) == (owner is not None), "retained symbol version presence differs from VERSYM metadata")
        if version is not None:
            assert owner is not None
            require(version["sectionIndex"] == owner["index"] and version["fileOffset"] == owner["offset"] + index * 2 and
                    version["raw"] <= 65535 and version["index"] == version["raw"] & 0x7fff and
                    version["hidden"] == bool(version["raw"] & 0x8000) and (index != 0 or version["raw"] == 0),
                    "retained VERSYM entry ownership/encoding differs")
    require_consistent_byte_ranges(name_ranges, "retained symbol names conflict in linked string table")
    for index, table in tables.items():
        items = populations[index]
        require(address(table["entrySize"]) == 24 and address(table["size"]) == len(items) * 24 and
                1 <= table["info"] <= len(items) and items == list(range(len(items))),
                "retained DYNSYM section population/width differs")
        if index in versions:
            owner = versions[index]
            require(address(owner["entrySize"]) == 2 and address(owner["size"]) == len(items) * 2,
                    "retained VERSYM section population/width differs")


def retained_dynamic_section(inventory: dict, sections: dict) -> dict:
    """Require complete section-backed entries from one matching SHT/PT_DYNAMIC pair."""
    owners = [row for row in sections.values() if row["type"] == 6]
    programs = [row for row in inventory["programHeaders"] if row["type"] == 2]
    require(len(owners) == len(programs) == 1, "retained dynamic section/program uniqueness differs")
    owner, program = owners[0], programs[0]
    size, file_size, memory_size, start = address(owner["size"]), address(program["fileSize"]), address(program["memorySize"]), address(program["virtualAddress"])
    assert size is not None and file_size is not None and memory_size is not None and start is not None
    require(owner["address"] == program["virtualAddress"] and owner["offset"] == address(program["offset"]) and
            size == file_size <= memory_size and start + memory_size <= (1 << 64) - 1 and
            address(owner["entrySize"]) == 16 and size == len(inventory["dynamicEntries"]) * 16 and size > 0,
            "retained dynamic section/program population/width differs")
    for index, entry in enumerate(inventory["dynamicEntries"]):
        require(entry["index"] == index and entry["fileOffset"] == owner["offset"] + index * 16,
                "retained dynamic entry index/file offset differs")
    return owner


def retained_relocation_tables(inventory: dict, sections: dict) -> tuple[bool, dict]:
    """Reconstruct runtime membership/uncertainty, never trusting derived annotations.

    Mirrors BoundedElfDynamicBindingsV1's closed tag policy and REL/RELA/JMPREL
    section coverage. This checks retained metadata consistency, not original ELF bytes.
    """
    dynamic = retained_dynamic_section(inventory, sections)
    known = set(range(35)) | {0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa, 0x6ffffffb,
                              0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff}
    singletons = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 18, 19, 20, 23, 35, 36, 37,
                  0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff}
    reasons = {"runtime-provider-and-interposition-unresolved", "dynamic-hash-population-not-reconciled"}
    tags = {}
    terminated = False
    for entry in inventory["dynamicEntries"]:
        tag, value = address(entry["tag"]), address(entry["value"])
        require(not terminated or tag == value == 0, "non-null retained entries after DT_NULL")
        terminated |= tag == 0
        if tag in singletons:
            require(tag not in tags, "duplicate retained dynamic singleton tag")
            tags[tag] = value
        if tag in {35, 36, 37}:
            reasons.add("packed-relr-relocations-not-expanded")
        elif tag in {0x6000000f, 0x60000010, 0x60000011, 0x60000012, 0x6fffe000, 0x6fffe001, 0x6fffe003}:
            reasons.add("android-packed-relocations-not-expanded")
        elif tag in {0x7ffffffd, 0x7fffffff}:
            reasons.add("dynamic-filter-provider-selection-unresolved")
        elif tag not in known:
            reasons.add("unclassified-dynamic-tag")
    require(terminated, "unterminated retained dynamic entries")
    active = [section for section in sections.values() if section["type"] == 11 and address(section["address"]) == tags.get(6)]
    require(len(active) == 1 and active[0]["index"] == inventory["activeSymbolTableSectionIndex"] and
            address(active[0]["entrySize"]) == tags.get(11) == 24, "retained active symbol table differs from raw tags")
    strings = sections.get(active[0]["link"])
    require(strings is not None and strings["type"] == 3, "retained dynamic string tags/linkage differ")
    assert strings is not None
    string_size = address(strings["size"])
    assert string_size is not None
    require(dynamic["link"] == strings["index"] and string_size > 0 and
            tags.get(5) == address(strings["address"]) and tags.get(10) == string_size,
            "retained dynamic string tags/linkage differ")
    active_versions = [section for section in sections.values()
                       if section["type"] == 0x6fffffff and section["link"] == inventory["activeSymbolTableSectionIndex"]]
    require((0x6ffffff0 in tags) == bool(active_versions) and
            (not active_versions or len(active_versions) == 1 and address(active_versions[0]["address"]) == tags[0x6ffffff0]),
            "retained DT_VERSYM presence/pointer differs from version sections")
    for pointer, count, kind in ((0x6ffffffe, 0x6fffffff, 0x6ffffffe), (0x6ffffffc, 0x6ffffffd, 0x6ffffffd)):
        owners = [section for section in sections.values() if section["type"] == kind and section["link"] == active[0]["link"]]
        require((pointer in tags) == (count in tags) and (pointer in tags) == bool(owners) and
                (not owners or len(owners) == 1 and address(owners[0]["address"]) == tags[pointer] and owners[0]["info"] == tags[count]),
                "retained GNU version tag presence/pointer/count differs from sections")
    if any(section["type"] == 11 and section["index"] != inventory["activeSymbolTableSectionIndex"] for section in sections.values()):
        reasons.add("inactive-dynsym-table-retained")
    require(inventory["unsupportedReasons"] == sorted(reasons), "retained unsupported reasons differ from dynamic metadata")
    ranges = []

    def add_range(name: str, start: int, size: int, kind: int, width: int) -> None:
        end = start + size
        require(end <= (1 << 64) - 1 and size % width == 0, "invalid retained dynamic relocation range")
        pieces = []
        for section in sections.values():
            if section["type"] != kind:
                continue
            begin, length = address(section["address"]), address(section["size"])
            require(begin + length <= (1 << 64) - 1, "retained relocation section address overflow")
            if size and length and begin < end and begin + length > start:
                pieces.append((begin, section["index"], begin + length))
        covered = start
        for begin, index, section_end in sorted(pieces):
            section = sections[index]
            require(address(section["entrySize"]) == width and section["link"] == inventory["activeSymbolTableSectionIndex"] and
                    address(section["flags"]) & 2 != 0 and address(section["flags"]) & 0x800 == 0,
                    "retained dynamic relocation section metadata differs")
            piece_start, piece_end = max(start, begin), min(end, section_end)
            require(piece_start == covered and (piece_start - begin) % width == (piece_end - begin) % width == 0,
                    "retained dynamic relocation range has gaps, overlap or split entries")
            covered = piece_end
        require(covered == end, "retained dynamic relocation range lacks section coverage")
        ranges.append((name, start, end, kind))

    for name, pointer, size, entry_size, kind, width in (("rela", 7, 8, 9, 4, 24), ("rel", 17, 18, 19, 9, 16)):
        if any(tag in tags for tag in (pointer, size, entry_size)):
            require(pointer in tags and size in tags and tags.get(entry_size) == width,
                    "incomplete or inconsistent retained dynamic relocation tags")
            add_range(name, tags[pointer], tags[size], kind, width)
    if any(tag in tags for tag in (23, 2, 20)):
        require(all(tag in tags for tag in (23, 2, 20)) and tags[20] in {7, 17}, "invalid retained JMPREL tags")
        add_range("jmprel", tags[23], tags[2], 4 if tags[20] == 7 else 9, 24 if tags[20] == 7 else 16)
    memberships, identities, counts = {}, set(), {}
    relative_tables = {"rela": [], "rel": []}
    for row in inventory["relocations"]:
        section = sections.get(row["sectionIndex"])
        if section is None or section["type"] not in {4, 9}:
            raise VerificationError("missing retained relocation section")
        width = 24 if section["type"] == 4 else 16
        identity = (row["sectionIndex"], row["relocationIndex"])
        size = address(section["size"])
        require(identity not in identities and address(section["entrySize"]) == width and size % width == 0 and
                row["relocationIndex"] < size // width and row["fileOffset"] == section["offset"] + row["relocationIndex"] * width and
                row["symbolTableSectionIndex"] == section["link"], "retained relocation section/entry identity differs")
        identities.add(identity)
        counts[section["index"]] = counts.get(section["index"], 0) + 1
        location = address(section["address"]) + row["relocationIndex"] * width
        require(location <= (1 << 64) - 1, "retained relocation entry address overflow")
        tables = [name for name, start, end, kind in ranges if kind == section["type"] and start <= location < end]
        require(row["dynamicTables"] == tables, "retained dynamic relocation membership differs from raw tags")
        memberships[row["locator"]] = tables
        for name, rows in relative_tables.items():
            if name in tables:
                rows.append((location, row))
    for section in sections.values():
        linked = sections.get(section["link"])
        if section["type"] in {4, 9} and linked is not None and linked["type"] == 11:
            width = 24 if section["type"] == 4 else 16
            require(address(section["entrySize"]) == width and address(section["size"]) % width == 0 and
                    counts.get(section["index"], 0) == address(section["size"]) // width,
                    "retained relocation section population differs")
    for tag, name in ((0x6ffffff9, "rela"), (0x6ffffffa, "rel")):
        if tag not in tags:
            continue
        count = tags[tag]
        ordered = sorted(relative_tables[name], key=lambda item: item[0])
        require(count <= len(ordered), "relative relocation prefix exceeds its retained table")
        require(all(row["type"] == 8 and row["symbolIndex"] == 0 for _, row in ordered[:count]),
                "relative relocation prefix contains a non-relative symbol reference")
    uncertain = bool(reasons & {"packed-relr-relocations-not-expanded", "android-packed-relocations-not-expanded", "unclassified-dynamic-tag"})
    return uncertain, memberships


def unique_intersecting_interval(rows: list, starts: list, ends: list, prefix_ends: list,
        start: int, end: int):
    """Return the sole retained interval intersecting an inclusive range, if any."""
    if end < start or bisect_right(starts, end) - bisect_left(ends, start) != 1:
        return None
    index = bisect_left(prefix_ends, start)
    return rows[index] if index < len(rows) else None


class RetainedLoadIndex:
    """Index retained LOAD intervals once for version and metadata ownership checks."""
    def __init__(self, inventory: dict, input_bytes: int):
        self.loads, self.load_positions, self.load_prefix_ends = [], {}, []
        load_headers = [row for row in inventory["programHeaders"] if row["type"] == 1]
        for row in load_headers:
            start, size, file_size, offset = (address(row[key]) for key in ("virtualAddress", "memorySize", "fileSize", "offset"))
            require(file_size <= size and start + size <= (1 << 64) - 1 and offset + file_size <= input_bytes,
                    "retained load bounds differ")
            if size:
                self.loads.append((start, row["index"], start + size - 1, file_size, offset))
        self.loads.sort()
        for index, row in enumerate(self.loads):
            require(row[1] not in self.load_positions, "duplicate retained load index")
            self.load_positions[row[1]] = index
            self.load_prefix_ends.append(max(row[2], self.load_prefix_ends[-1] if self.load_prefix_ends else 0))
        self.load_starts = [row[0] for row in self.loads]
        self.load_ends = sorted(row[2] for row in self.loads)
        self.load_flags = {row["index"]: row["flags"] for row in load_headers}

    def unique_intersecting(self, start: int, end_exclusive: int) -> tuple | None:
        if end_exclusive <= start:
            return None
        return unique_intersecting_interval(self.loads, self.load_starts, self.load_ends,
            self.load_prefix_ends, start, end_exclusive - 1)


def retained_version_records(inventory: dict, sections: dict, input_bytes: int, load_index: RetainedLoadIndex) -> dict:
    """Validate retained Verneed/Verdef provenance, not the original ELF strings/bytes."""
    requirements, keys, owners, populations = {}, set(), {}, {}
    storage_ranges, record_headers = {}, set()

    def elf_hash(name: str) -> int:
        result = 0
        for byte in name.encode("utf-8"):
            result = ((result << 4) + byte) & 0xffffffff
            high = result & 0xf0000000
            result = (result ^ (high >> 24)) & ~high
        return result

    def owner_for(row: dict, kind: int) -> dict:
        owner = sections.get(row["sectionIndex"])
        strings = sections.get(row["stringSectionIndex"])
        if (owner is None or owner["type"] != kind or owner["link"] != row["stringSectionIndex"] or
                strings is None or strings["type"] != 3):
            raise VerificationError("retained GNU version record ownership differs")
        if owner["index"] not in owners:
            start, size, flags = (address(owner[key]) for key in ("address", "size", "flags"))
            require(flags & 2 != 0 and flags & 0x800 == 0 and start + size <= (1 << 64) - 1 and
                    owner["offset"] + size <= input_bytes and address(owner["entrySize"]) == 0 and owner["info"] > 0,
                    "retained GNU version section bounds/metadata differs")
            load = load_index.unique_intersecting(start, start + size)
            if load is None:
                raise VerificationError("retained GNU version section lacks unique LOAD ownership")
            begin, _, _, file_size, file_offset = load
            require(begin <= start and start + size <= begin + file_size and
                    file_offset + start - begin == owner["offset"], "retained GNU version section mapping differs")
            owners[owner["index"]] = owner
        return owner

    def within(owner: dict, offset: int, width: int) -> bool:
        return owner["offset"] <= offset and offset + width <= owner["offset"] + address(owner["size"])

    string_ranges: list[tuple[int, int, bytes]] = []

    def retain_linked_string(string_section_index: int, offset: int, value: str) -> None:
        strings = sections.get(string_section_index)
        if strings is None:
            raise VerificationError("retained GNU version string table is absent")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise VerificationError("retained GNU version string is not UTF-8 encodable") from error
        size = address(strings["size"])
        offset = integer(offset, 0, (1 << 32) - 1)
        require("\0" not in value and offset < size and len(encoded) + 1 <= size - offset and
                (offset != 0 or not value), "retained GNU version string exceeds linked string table")
        string_ranges.append((string_section_index, offset, encoded + b"\0"))

    for symbol in inventory["dynamicSymbols"]:
        table = sections.get(symbol["tableSectionIndex"])
        if table is None or table["type"] != 11:
            raise VerificationError("retained dynamic symbol table is absent")
        retain_linked_string(table["link"], symbol["nameOffset"], symbol["name"])
    active_table = sections.get(inventory["activeSymbolTableSectionIndex"])
    if active_table is None or active_table["type"] != 11:
        raise VerificationError("retained active dynamic symbol table is absent")
    needed_entries = [entry for entry in inventory["dynamicEntries"] if address(entry["tag"]) == 1]
    require(len(needed_entries) == len(inventory["neededLibraries"]), "retained DT_NEEDED population differs")
    for entry, library in zip(needed_entries, inventory["neededLibraries"], strict=True):
        retain_linked_string(active_table["link"], address(entry["value"]), library)

    record_ends = {}
    for group, kind, width in (("versionRequirements", 0x6ffffffe, 16), ("versionDefinitions", 0x6ffffffd, 20)):
        offsets_by_owner = {}
        for row in inventory[group]:
            owner = owner_for(row, kind)
            offsets_by_owner.setdefault(owner["index"], set()).add(row["recordOffset"])
        for owner_index, offsets in offsets_by_owner.items():
            owner = owners[owner_index]
            section_end = owner["offset"] + address(owner["size"])
            ordered_offsets = sorted(offsets)
            for offset, next_offset in zip(ordered_offsets, [*ordered_offsets[1:], section_end], strict=True):
                require(offset + width <= next_offset, "retained GNU version record header crosses the next record")
                record_ends[(owner_index, offset)] = next_offset

    for group, kind, width in (("versionRequirements", 0x6ffffffe, 16), ("versionDefinitions", 0x6ffffffd, 20)):
        rows = inventory[group]
        order = [(row["sectionIndex"], row["recordOffset"], *([row["auxiliaryOffset"]] if group == "versionRequirements" else [])) for row in rows]
        require(order == sorted(order), "retained GNU version record order differs")
        provider_by_verneed = {}
        for row in rows:
            owner = owner_for(row, kind)
            if group == "versionRequirements":
                retain_linked_string(row["stringSectionIndex"], row["nameOffset"], row["name"])
                retain_linked_string(row["stringSectionIndex"], row["providerRequestOffset"], row["providerRequest"])
            else:
                require(len(row["auxiliaryNameOffsets"]) == len(row["parentNames"]) + 1,
                        "retained Verdaux string-offset population differs")
                for offset, value in zip(row["auxiliaryNameOffsets"], [row["name"], *row["parentNames"]], strict=True):
                    retain_linked_string(row["stringSectionIndex"], offset, value)
            index, raw = row["index"], row["rawIndex"]
            key = (row["stringSectionIndex"], index)
            require(0 <= raw <= 65535 and (2 if group == "versionRequirements" else 1) <= index <= 32767 and
                    index == raw & 0x7fff and key not in keys and 0 <= row["flags"] <= 65535 and
                    bool(row["name"]) and row["hash"] == elf_hash(row["name"]), "retained GNU version identity/hash differs")
            keys.add(key)
            record_end = record_ends[(owner["index"], row["recordOffset"])]
            require(within(owner, row["recordOffset"], width) and row["recordOffset"] + width <= record_end,
                    "retained GNU version record bounds differ")
            header = (owner["index"], row["recordOffset"])
            if header not in record_headers:
                storage_ranges.setdefault(owner["index"], []).append((row["recordOffset"], row["recordOffset"] + width))
                record_headers.add(header)
            records = populations.setdefault(owner["index"], set())
            require(group == "versionRequirements" or row["recordOffset"] not in records, "duplicate retained Verdef record")
            records.add(row["recordOffset"])
            if group == "versionRequirements":
                offsets, auxiliary_width = [row["auxiliaryOffset"]], 16
                verneed = (row["sectionIndex"], row["recordOffset"])
                provider_identity = (row["providerRequest"], row["providerRequestOffset"])
                provider = provider_by_verneed.setdefault(verneed, provider_identity)
                require(provider == provider_identity, "retained Verneed provider request differs within header")
                requirements.setdefault(key, []).append(row)
            else:
                offsets, auxiliary_width = row["auxiliaryOffsets"], 8
                require(len(offsets) == len(row["parentNames"]) + 1 and all(row["parentNames"]) and
                        offsets == sorted(set(offsets)) and all(b - a >= 8 for a, b in pairwise(offsets)),
                        "retained Verdaux population/order differs")
            for offset in offsets:
                require(offset >= row["recordOffset"] + width and offset + auxiliary_width <= record_end and
                        within(owner, offset, auxiliary_width),
                        "retained GNU version auxiliary bounds/order differs")
                storage_ranges.setdefault(owner["index"], []).append((offset, offset + auxiliary_width))
    require_consistent_byte_ranges(string_ranges, "retained GNU version strings conflict in linked table")
    for ranges in storage_ranges.values():
        ordered = sorted(ranges)
        require(all(right[0] >= left[1] for left, right in pairwise(ordered)),
                "retained GNU version record storage overlaps")
    for owner in sections.values():
        if owner["type"] in {0x6ffffffe, 0x6ffffffd}:
            require(owner["index"] in owners and owner["info"] == len(populations.get(owner["index"], set())),
                    "retained GNU version section record population differs")
    return requirements


class RetainedRelocationIndex:
    """Recheck positive metadata claims; no ELF reads or instruction decoding occur here.

    Widths mirror ElfRelocationWriteCoverageV1. Sorting once and prefix maximum ends
    make each candidate's competing-write check constant time, excluding itself.
    """
    def __init__(self, inventory: dict, symbols: dict, input_bytes: int):
        self.inventory = inventory
        self.sections = {row["index"]: row for row in inventory["sections"]}
        require(len(self.sections) == len(inventory["sections"]), "duplicate retained section index")
        self.mechanism_uncertain, self.memberships = retained_relocation_tables(inventory, self.sections)
        self.version_sections = {}
        for section in self.sections.values():
            if section["type"] == 0x6fffffff:
                table = self.sections.get(section["link"])
                if table is None or table["type"] != 11 or table["index"] in self.version_sections:
                    raise VerificationError("retained VERSYM table linkage/uniqueness differs")
                self.version_sections[table["index"]] = section
        for symbol in symbols.values():
            require((symbol["version"] is not None) == (symbol["tableSectionIndex"] in self.version_sections),
                    "retained symbol version presence differs from VERSYM metadata")
        self.load_index = RetainedLoadIndex(inventory, input_bytes)
        self.requirements = retained_version_records(inventory, self.sections, input_bytes, self.load_index)
        self.supported_versions = {key for key, symbol in symbols.items() if self.import_version(symbol)}
        self.validate_metadata_storage(input_bytes)
        self.code_sections, self.code_prefix_ends = [], []
        for section in self.sections.values():
            start, size = address(section["address"]), address(section["size"])
            if address(section["flags"]) & 2 and size:
                require(start + size <= (1 << 64) - 1, "retained allocated section address overflow")
                self.code_sections.append((start, section["index"], start + size - 1))
        self.code_sections.sort()
        self.code_starts = [row[0] for row in self.code_sections]
        self.code_ends = sorted(row[2] for row in self.code_sections)
        for row in self.code_sections:
            self.code_prefix_ends.append(max(row[2], self.code_prefix_ends[-1] if self.code_prefix_ends else 0))
        self.input_bytes, self.code_lengths, self.code_file_offsets = input_bytes, {}, {}
        self.slot_counts, self.active, self.positions = {}, {}, {}
        self.unknown = self.overflow = False
        self.writes = []
        identities = set()
        for row in inventory["relocations"]:
            slot = address(row["offset"])
            self.slot_counts[slot] = self.slot_counts.get(slot, 0) + 1
            if not self.memberships[row["locator"]] or row["symbolTableSectionIndex"] != inventory["activeSymbolTableSectionIndex"]:
                continue
            identity = (row["sectionIndex"], row["relocationIndex"])
            require(identity not in identities, "duplicate active relocation identity")
            identities.add(identity)
            kind = row["type"]
            width = 0 if kind == 0 else 8 if kind in {1, 6, 7, 8, 16, 17, 18, 33, 37, 38} else 4 if kind in {2, 10, 32} else 16 if kind == 36 else None
            if kind == 5:
                symbol = symbols[(row["symbolTableSectionIndex"], row["symbolIndex"])]
                raw_section = integer(symbol["rawSectionIndex"], 0, 65535)
                resolved_section = integer(symbol["resolvedSectionIndex"], 0, 131071)
                if raw_section == 0:
                    section_consistent = symbol["sectionKind"] == "undefined" and resolved_section == 0
                elif raw_section == 0xfff1:
                    section_consistent = symbol["sectionKind"] == "absolute" and resolved_section == raw_section
                elif raw_section == 0xffff:
                    # SHN_XINDEX companion words are not retained, so their resolved COPY index is unverifiable offline.
                    section_consistent = False
                else:
                    section_consistent = (0 < raw_section < 0xff00 and raw_section in self.sections and
                        symbol["sectionKind"] == "defined" and resolved_section == raw_section)
                require(section_consistent, "active COPY relocation symbol raw/resolved section index differs")
                section = self.sections.get(resolved_section)
                if symbol["sectionKind"] == "defined" and address(symbol["value"]) == slot and section is not None and address(section["flags"]) & 2:
                    width = address(symbol["size"])
            self.active[row["locator"]] = (slot, width)
            if width is None:
                self.unknown = True
            elif width and slot + width - 1 > (1 << 64) - 1:
                self.overflow = True
            elif width:
                self.writes.append((slot, *identity, row["locator"], slot + width - 1))
        self.writes.sort()
        self.prefix_ends = []
        for index, row in enumerate(self.writes):
            self.positions[row[3]] = index
            self.prefix_ends.append(max(row[4], self.prefix_ends[-1] if self.prefix_ends else 0))

    def validate_metadata_storage(self, input_bytes: int) -> None:
        """Reconcile retained metadata storage, without opening original-host ELF paths.

        Mirror metadataSection()/metadata(): required dynamic tables are allocated,
        uncompressed file storage; each nonempty range has exactly one intersecting
        LOAD, fully backs onto that LOAD's file bytes, and agrees on file offsets.
        Reuse the LOAD interval index so adversarial overlaps do not cause a scan
        per metadata section.
        """
        # retained_relocation_tables() has already authenticated the active index.
        active = self.sections[self.inventory["activeSymbolTableSectionIndex"]]
        strings = self.sections.get(active["link"])
        if strings is None or strings["type"] != 3:
            raise VerificationError("retained dynamic metadata string table is missing")
        required = {active["index"], strings["index"]}
        for section in self.sections.values():
            kind, flags = section["type"], address(section["flags"])
            assert flags is not None
            if kind in {6, 0x6fffffff, 0x6ffffffe, 0x6ffffffd} or kind in {11, 4, 9} and flags & 2:
                required.add(section["index"])
            if kind in {0x6ffffffe, 0x6ffffffd}:
                linked = self.sections.get(section["link"])
                if linked is None or linked["type"] != 3:
                    raise VerificationError("retained dynamic metadata version string table is missing")
                required.add(linked["index"])
        metadata_ranges = []
        for index in sorted(required):
            section = self.sections[index]
            start, size, flags = (address(section[key]) for key in ("address", "size", "flags"))
            # Nonnullable address() calls guarantee integers; make that contract
            # explicit for analyzers that do not narrow through require().
            assert start is not None and size is not None and flags is not None
            require(flags & 2 != 0 and not flags & 0x800 and section["type"] != 8 and
                    start + size <= (1 << 64) - 1 and section["offset"] + size <= input_bytes,
                    "retained dynamic metadata is not allocated uncompressed file storage within bounds")
            if not size:
                continue  # As in the producer, an empty table requires no LOAD owner.
            metadata_ranges.append((section["offset"], section["offset"] + size))
            end = start + size - 1
            load = self.load_index.unique_intersecting(start, start + size)
            if load is None:
                raise VerificationError("retained dynamic metadata lacks unique LOAD ownership")
            require(load[0] <= start and end < load[0] + load[3] and
                    load[4] + start - load[0] == section["offset"],
                    "retained dynamic metadata file and LOAD mappings disagree")
        previous_end = 0
        for range_start, range_end in sorted(metadata_ranges):
            require(range_start >= previous_end, "retained dynamic metadata sections overlap")
            previous_end = range_end
        self.metadata_file_ranges = tuple(metadata_ranges)

    def code_window(self, location: int) -> tuple[int, int] | None:
        length = self.code_window_length(location)
        if length is None:
            return None
        file_offset = self.code_file_offsets[location]
        assert file_offset is not None
        return length, file_offset

    def code_window_length(self, location: int) -> int | None:
        """Unique executable section/LOAD ownership, mirroring codeWindowLength().

        Address-sorted intervals and prefix maxima bound even overlapping inventories;
        cache repeated PLT destinations rather than scanning all sections per call.
        """
        if location in self.code_lengths:
            return self.code_lengths[location]
        self.code_lengths[location] = None
        self.code_file_offsets[location] = None

        def unique_owner(rows: list, starts: list, ends: list, prefix_ends: list, start: int, end: int):
            row = unique_intersecting_interval(rows, starts, ends, prefix_ends, start, end)
            return row if row is not None and row[0] <= start and row[2] >= end else None

        section_row = unique_owner(self.code_sections, self.code_starts, self.code_ends, self.code_prefix_ends, location, location)
        load = unique_owner(self.load_index.loads, self.load_index.load_starts, self.load_index.load_ends,
            self.load_index.load_prefix_ends, location, location)
        if section_row is None or load is None:
            return None
        section = self.sections[section_row[1]]
        if (section["type"] != 1 or address(section["flags"]) & 6 != 6 or not self.load_index.load_flags[load[1]] & 1 or
                location >= load[0] + load[3] or section["offset"] + address(section["size"]) > self.input_bytes):
            return None
        length = min(15, section_row[2] - location + 1, load[0] + load[3] - location)
        end = location + length - 1
        if (unique_owner(self.code_sections, self.code_starts, self.code_ends, self.code_prefix_ends, location, end) != section_row or
                unique_owner(self.load_index.loads, self.load_index.load_starts, self.load_index.load_ends,
                    self.load_index.load_prefix_ends, location, end) != load):
            return None
        section_offset = section["offset"] + location - section_row[0]
        load_offset = load[4] + location - load[0]
        if section_offset != load_offset or load_offset > (1 << 63) - 1 or load_offset + length > self.input_bytes:
            return None
        self.code_lengths[location] = length
        self.code_file_offsets[location] = load_offset
        return length

    def safe_slot(self, locator: str, slot: int) -> bool:
        if self.unknown or self.overflow or self.active.get(locator) != (slot, 8) or slot > (1 << 64) - 8:
            return False
        index = self.positions[locator]
        return ((index == 0 or self.prefix_ends[index - 1] < slot) and
                (index + 1 == len(self.writes) or self.writes[index + 1][0] > slot + 7))

    def owned_slot(self, relocation: dict, slot: int) -> bool:
        if len(relocation["slotLoadIndices"]) != 1 or relocation["slotFileOffset"] is None:
            return False
        index = self.load_index.load_positions.get(relocation["slotLoadIndices"][0])
        if index is None:
            return False
        start, _, end, file_size, offset = self.load_index.loads[index]
        return (start <= slot and slot + 7 <= end and slot + 8 <= start + file_size and
                offset + slot - start == relocation["slotFileOffset"] and
                (index == 0 or self.load_index.load_prefix_ends[index - 1] < slot) and
                (index + 1 == len(self.load_index.loads) or self.load_index.loads[index + 1][0] > slot + 7))

    def import_version(self, symbol: dict) -> bool:
        version = symbol["version"]
        versym = self.version_sections.get(symbol["tableSectionIndex"])
        if version is None:
            return versym is None
        table = self.sections.get(symbol["tableSectionIndex"])
        if (table is None or table["type"] != 11 or versym is None or version["sectionIndex"] != versym["index"] or
                address(versym["entrySize"]) != 2 or version["fileOffset"] != versym["offset"] + symbol["symbolIndex"] * 2 or
                symbol["symbolIndex"] * 2 + 2 > address(versym["size"])):
            return False
        raw, index = version["raw"], version["index"]
        if not 0 <= raw <= 65535 or index != raw & 0x7fff or version["hidden"] is not bool(raw & 0x8000):
            return False
        if index <= 1:
            return (version["kind"] == ("local" if index == 0 else "global-unversioned") and
                    version["name"] is None and version["providerRequest"] is None)
        requirements = self.requirements.get((table["link"], index), [])
        return (version["kind"] == "required-version" and bool(version["name"]) and bool(version["providerRequest"]) and
                len(requirements) == 1 and requirements[0]["name"] == version["name"] and
                requirements[0]["providerRequest"] == version["providerRequest"] and requirements[0]["rawIndex"] & 0x7fff == index)

    def static_import(self, relocation: dict, symbol: dict, slot: int) -> bool:
        return (not self.mechanism_uncertain and self.slot_counts[slot] == 1 and len(self.memberships[relocation["locator"]]) == 1 and
                self.owned_slot(relocation, slot) and relocation["symbolTableSectionIndex"] == self.inventory["activeSymbolTableSectionIndex"] and
                relocation["type"] in {6, 7} and relocation["symbolIndex"] != 0 and self.safe_slot(relocation["locator"], slot) and
                symbol["sectionKind"] == "undefined" and symbol["rawSectionIndex"] == 0 and symbol["resolvedSectionIndex"] == 0 and
                symbol["binding"] == 1 and symbol["type"] == 2 and symbol["visibility"] == 0 and
                symbol["info"] == 18 and symbol["other"] & 3 == 0 and bool(symbol["name"]) and
                (symbol["tableSectionIndex"], symbol["symbolIndex"]) in self.supported_versions)


def verify_external_bindings(evidence: dict, request: dict, report: dict, source: dict,
        source_request_bytes: bytes, source_report_bytes: bytes, source_request: dict, source_report: dict) -> None:
    fields(request, {"schemaVersion", "kind", "richFile", "sourceReport", "sourceRequest", "runtime", "outputPath", "limits", "metadataPolicy"}, "external request")
    require(type(request["schemaVersion"]) is int and request["schemaVersion"] == 1 and request["kind"] == "independent-external-call-request-v1",
            "external request schema differs")
    informational_path(request["outputPath"])
    runtime = fields(request["runtime"], RUNTIME | RUNTIME_PATHS | RUNTIME_SNAPSHOTS, "external request runtime")
    for key in RUNTIME_PATHS:
        informational_path(runtime[key])
    for key, digest_key in (("bridgeSnapshot", "bridgeSha256"), ("bundleManifestSnapshot", "bundleManifestSha256")):
        snapshot = fields(runtime[key], {"path", "bytes", "sha256"}, f"external runtime {key}")
        informational_path(snapshot["path"])
        integer(snapshot["bytes"], 1, MAX_BYTES)
        digest(snapshot["sha256"])
        require(snapshot["sha256"] == runtime[digest_key], f"external runtime {key} digest differs")
    require({key: runtime[key] for key in RUNTIME} == evidence["runtime"], "external request runtime commitment differs")
    limits = fields(request["limits"], set(EXTERNAL_LIMITS), "external request limits")
    for key, ceiling in EXTERNAL_LIMITS.items():
        integer(limits[key], 1, ceiling)
    require(request["metadataPolicy"] == "elf-dynamic-binding-default-limits-v1", "unsupported metadata policy")
    require(evidence["inputs"]["rich"] == source["inputs"]["rich"], "source evidence rich input differs")
    expected_inputs = {"richFile": evidence["inputs"]["rich"], "sourceReport": {"bytes": len(source_report_bytes), "sha256": sha256(source_report_bytes).hexdigest()},
        "sourceRequest": {"bytes": len(source_request_bytes), "sha256": sha256(source_request_bytes).hexdigest()}}
    for key, expected in expected_inputs.items():
        reference = fields(request[key], {"path", "bytes", "sha256"}, "external request input")
        informational_path(reference["path"])
        require(type(reference["bytes"]) is int and reference["bytes"] == expected["bytes"] and reference["sha256"] == expected["sha256"],
                "external request input/source commitment differs")
    paths = [request[key]["path"] for key in expected_inputs]
    require(len(set(paths)) == 3 and request["outputPath"] not in paths, "external request paths overlap")
    fields(report, {"schemaVersion", "kind", "scope", "decoderAuthentication", "complete", "releaseEligible", "negativeCompleteness",
        "sourceCallRecordsEnumerated", "sourceCallPopulationComplete", "limits", "metadataPolicy", "inputSha256", "inputBytes", "imageBase",
        "sourceReportSha256", "sourceRequestSha256", "externalNamespaceSha256", "externalNamespace", "sourceCanonicalPopulation", "dynamicInventory",
        "sites", "counts", "requestSha256", "runtime", "containmentStatus"}, "external report")
    require(type(report["schemaVersion"]) is int and report["schemaVersion"] == 1 and report["kind"] == "independent-external-call-component-v1" and
            report["scope"] == "component" and report["decoderAuthentication"] == "authenticated-bundled-worker-v1" and
            report["containmentStatus"] == "external-owner-required", "external report boundary differs")
    false_authority(report)
    require(report["sourceCallRecordsEnumerated"] is True and report["sourceCallPopulationComplete"] is False, "source population authority differs")
    report_runtime = fields(report["runtime"], RUNTIME | RUNTIME_PATHS, "external report runtime")
    for key in RUNTIME_PATHS:
        informational_path(report_runtime[key])
    expected_report_runtime = {key: runtime[key] for key in RUNTIME | RUNTIME_PATHS}
    require(report["requestSha256"] == evidence["payloads"]["request"]["sha256"] and
            canonical_bytes(report_runtime) == canonical_bytes(expected_report_runtime) and
            canonical_bytes(report["limits"]) == canonical_bytes(limits) and
            report["metadataPolicy"] == request["metadataPolicy"], "external report request/runtime/policy commitment differs")
    require(type(report["inputBytes"]) is int and report["inputBytes"] == request["richFile"]["bytes"] and report["inputSha256"] == request["richFile"]["sha256"] and
            report["sourceReportSha256"] == request["sourceReport"]["sha256"] and report["sourceRequestSha256"] == request["sourceRequest"]["sha256"],
            "external report input/source commitment differs")
    require(report["imageBase"] == source_report["imageBase"], "source image base differs")
    base = address(report["imageBase"])
    expected_canonical = [{key: row[key] for key in ("id", "rva", "exclusion")} for row in source_report["canonicalPopulation"]]
    require(report["sourceCanonicalPopulation"] == expected_canonical, "source canonical population differs")
    canonical_by_id = {row["id"]: row for row in expected_canonical}
    canonical_addresses = {base + address(row["rva"]) for row in expected_canonical if row["rva"] is not None}
    symbols, relocations, imports = verify_external_inventory(report["dynamicInventory"], report["externalNamespace"],
        report["externalNamespaceSha256"], report["inputSha256"], report["imageBase"])
    relocation_index = RetainedRelocationIndex(report["dynamicInventory"], symbols, report["inputBytes"])
    sites = inventory_rows(report["sites"], SITE_KEYS, limits["maximumCalls"], "external sites")
    require(len(sites) == len(source_report["calls"]), "source physical calls were omitted or duplicated")
    counts = {}
    byte_ranges = []
    for ordinal, (site, call) in enumerate(zip(sites, source_report["calls"], strict=True)):
        require(type(site["sourceOrdinal"]) is int and site["sourceOrdinal"] == ordinal and site["negativeCompleteness"] is False and
                type(site["viaForwarder"]) is bool, "site identity/authority differs")
        for key in ("callerRoot", "callerCanonicalId", "callerRva", "instructionRva", "instructionBytes", "instructionLength"):
            require(type(site[key]) is type(call[key]) and site[key] == call[key], "source physical site differs")
        require(site["physicalClassification"] == call["classification"] and site["physicalTargetAddress"] == call["directTargetAddress"] and
                site["sourceDisposition"] == call["disposition"] and site["returnAddress"] == call["fallthroughAddress"], "source physical transfer differs")
        classification = site["physicalClassification"]
        target = address(site["physicalTargetAddress"], nullable=True)
        require(classification in {"direct-call", "indirect-call"} and (classification == "direct-call") == (target is not None),
                "physical call classification/target differs")
        location = base + address(site["instructionRva"])
        instruction_length = integer(site["instructionLength"], 1, 15)
        require(location <= (1 << 64) - 1 and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", site["instructionBytes"]) is not None and
                len(site["instructionBytes"]) == 2 * instruction_length and
                address(site["returnAddress"]) == location + instruction_length, "invalid source instruction coordinates")
        source_window = relocation_index.code_window(location)
        if source_window is None or source_window[0] < instruction_length:
            raise VerificationError("source call instruction lacks uniquely owned executable file-backed bytes")
        instruction_bytes = bytes.fromhex(site["instructionBytes"])
        byte_ranges.append((0, location, instruction_bytes))
        byte_ranges.append((1, source_window[1], instruction_bytes))
        status = site["compositionDisposition"]
        require(status in EXTERNAL_STATUSES and site["targetBindingDisposition"] in EXTERNAL_STATUSES, "unknown external disposition")
        caller = canonical_by_id.get(site["callerCanonicalId"])
        if site["sourceDisposition"] == "unresolved-instruction-overlap":
            expected_status = "unresolved-source-instruction-boundary"
        elif caller is None or caller["exclusion"] is not None:
            expected_status = "unresolved-source-caller"
        elif site["sourceDisposition"] == "unresolved-target-canonical-exclusion":
            expected_status = "unresolved-source-target-exclusion"
        elif site["sourceDisposition"] == "unresolved-target-extent":
            expected_status = "unresolved-source-target-extent"
        else:
            expected_status = site["targetBindingDisposition"]
        require(status == expected_status, "source disposition authority differs")
        if site["sourceDisposition"] == "unresolved-instruction-overlap" or target in canonical_addresses:
            expected_binding = "unresolved-source-instruction-boundary" if site["sourceDisposition"] == "unresolved-instruction-overlap" else "retained-canonical-target"
            require(site["targetBindingDisposition"] == expected_binding and site["viaForwarder"] is False and
                    all(site[key] is None for key in ("memoryProbe", "memoryTransfer", "relocationBinding", "externalTargetId")),
                    "canonical/source-boundary site gained external evidence")
        else:
            require(site["targetBindingDisposition"] not in {"retained-canonical-target", "unresolved-source-instruction-boundary"},
                    "noncanonical physical destination has canonical/source-boundary binding")
            probe_location = target if classification == "direct-call" else location
            require(site["viaForwarder"] is (probe_location != location), "forwarding mode differs from physical call destination")
        counts[status] = counts.get(status, 0) + 1
        verify_external_site(site, location, symbols, relocations, imports, relocation_index)
        probe = site["memoryProbe"]
        if probe is not None:
            probe_location = address(probe["address"])
            probe_window = relocation_index.code_window(probe_location)
            if probe_window is None or probe_window[0] != len(probe["availableBytes"]) // 2:
                raise VerificationError("retained probe lacks uniquely owned executable file-backed bytes")
            probe_bytes = bytes.fromhex(probe["availableBytes"])
            byte_ranges.append((0, probe_location, probe_bytes))
            byte_ranges.append((1, probe_window[1], probe_bytes))
    for coordinate_space, file_offset, data in byte_ranges:
        if coordinate_space != 1:
            continue
        file_end = file_offset + len(data)
        require(all(file_end <= metadata_start or metadata_end <= file_offset
                    for metadata_start, metadata_end in relocation_index.metadata_file_ranges),
                "retained executable file bytes alias dynamic metadata storage")
    require_consistent_byte_ranges(byte_ranges,
        "retained source/probe byte windows conflict at overlapping executable addresses or file ranges")
    expected_counts = {"sourcePhysicalSites": len(sites), "composedSiteRecords": len(sites), "namespaceEntries": len(imports), "dispositions": counts}
    fields(report["counts"], EXTERNAL_COUNTS, "external report counts")
    require(canonical_bytes(report["counts"]) == canonical_bytes(expected_counts) == canonical_bytes(evidence["counts"]),
            "external counts differ from retained populations")


def verify_external_site(site: dict, location: int, symbols: dict, relocations: dict, imports: dict, relocation_index: RetainedRelocationIndex) -> None:
    probe, transfer, binding = (site[key] for key in ("memoryProbe", "memoryTransfer", "relocationBinding"))
    if site["targetBindingDisposition"] == "static-import-request-reference":
        require(binding is not None and site["externalTargetId"] is not None, "static import disposition has no binding")
    if probe is None:
        require(transfer is None and binding is None and site["externalTargetId"] is None, "proof without byte probe")
        if site["targetBindingDisposition"] not in {"retained-canonical-target", "unresolved-source-instruction-boundary"}:
            probe_location = address(site["physicalTargetAddress"]) if site["physicalClassification"] == "direct-call" else location
            expected = "unresolved-null-physical-target" if probe_location == 0 else "unresolved-forwarder-byte-ownership"
            require(site["targetBindingDisposition"] == expected and relocation_index.code_window_length(probe_location) is None,
                    "absent byte probe disposition/ownership differs")
        return
    fields(probe, {"address", "availableBytes", "refusal"}, "memory probe")
    probe_address = address(probe["address"])
    expected_address = address(site["physicalTargetAddress"]) if site["physicalClassification"] == "direct-call" else location
    require(site["viaForwarder"] is (expected_address != location), "forwarding mode differs from physical call destination")
    require(probe_address == expected_address and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", probe["availableBytes"]) is not None, "memory probe coordinates differ")
    require(relocation_index.code_window_length(probe_address) == len(probe["availableBytes"]) // 2,
            "memory probe executable byte-window ownership/length differs")
    if probe["refusal"] is not None:
        require(re.fullmatch(r"[a-z0-9-]{1,128}", text(probe["refusal"], 128)) is not None and transfer is None and binding is None and
                site["externalTargetId"] is None and site["targetBindingDisposition"] == "unresolved-memory-decoder-refusal",
                "decoder refusal contains proof or inconsistent disposition")
        return
    fields(transfer, TRANSFER_KEYS, "memory transfer")
    require(transfer["classification"] in TRANSFER_CLASSIFICATIONS and transfer["contextStatus"] in TRANSFER_CONTEXTS, "unknown transfer classification/context")
    require(address(transfer["address"]) == probe_address and type(transfer["bytes"]) is str and
            re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", transfer["bytes"]) is not None and
            len(transfer["bytes"]) == 2 * integer(transfer["length"], 1, 15) and probe["availableBytes"].startswith(transfer["bytes"]), "memory transfer byte commitment differs")
    if not site["viaForwarder"]:
        require(transfer["length"] == site["instructionLength"] and transfer["bytes"] == site["instructionBytes"] and
                transfer["classification"] == site["physicalClassification"], "same-instruction memory receipt differs from physical call")
    require(type(transfer["rawCopyOpIndices"]) is list and len(transfer["rawCopyOpIndices"]) <= 4096 and
            transfer["rawCopyOpIndices"] == sorted(set(transfer["rawCopyOpIndices"])), "invalid copy opcode inventory")
    for index in transfer["rawCopyOpIndices"]:
        integer(index, 0, 4095)
    transfer_opcode, transfer_index = transfer["rawTransferOpcode"], transfer["rawTransferOpIndex"]
    expected_opcode = {"indirect-call": "CALLIND", "indirect-jump": "BRANCHIND"}.get(transfer["classification"])
    require((transfer_opcode is None) == (transfer_index is None), "transfer opcode/index pairing differs")
    if transfer_opcode is not None:
        require(type(transfer_opcode) is str and transfer_opcode == expected_opcode, "transfer opcode/classification differs")
        integer(transfer_index, 0, 4095)
    slot = address(transfer["pointerSlotAddress"], nullable=True)
    if slot is None:
        desired = "indirect-jump" if site["viaForwarder"] else "indirect-call"
        expected = "unresolved-memory-transfer" if transfer["classification"] == desired else "unresolved-forwarder-sequence"
        require(site["targetBindingDisposition"] == expected, "unresolved transfer disposition differs")
        require(transfer["relationship"] == "unresolved" and transfer["pointerWidthBytes"] is None and transfer["unresolvedReason"] in TRANSFER_REFUSALS and
                transfer["rawReadOpcode"] is None and transfer["rawReadOpIndex"] is None and not transfer["rawCopyOpIndices"] and
                binding is None and site["externalTargetId"] is None, "unresolved transfer contains slot proof")
        return
    require(transfer["pointerWidthBytes"] == 8 and type(transfer["pointerWidthBytes"]) is int and slot <= (1 << 64) - 8 and
            transfer["contextStatus"] == "language-default-no-commits-v1" and transfer["unresolvedReason"] is None and
            transfer["relationship"] in {"static-ram-varnode-exact-transfer-v1", "single-static-load-exact-transfer-v1"}, "invalid static slot proof")
    require(transfer["classification"] in {"indirect-call", "indirect-jump"} and
            transfer["rawTransferOpcode"] == ("CALLIND" if transfer["classification"] == "indirect-call" else "BRANCHIND"), "transfer opcode/classification differs")
    read_index = integer(transfer["rawReadOpIndex"], 0, 4095)
    transfer_index = integer(transfer["rawTransferOpIndex"], read_index, 4095)
    copies = transfer["rawCopyOpIndices"]
    require(all(read_index <= index < transfer_index for index in copies), "copy opcode is outside transfer chain")
    if transfer["relationship"] == "single-static-load-exact-transfer-v1":
        require(transfer["rawReadOpcode"] == "LOAD" and read_index < transfer_index and all(index > read_index for index in copies), "invalid LOAD chain")
    elif transfer["rawReadOpcode"] == "COPY":
        require(bool(copies) and copies[0] == read_index and read_index < transfer_index, "invalid implicit memory COPY chain")
    else:
        require(transfer["rawReadOpcode"] == transfer["rawTransferOpcode"] and read_index == transfer_index and not copies, "invalid implicit memory transfer")
    if binding is None:
        require(site["externalTargetId"] is None, "external identity without relocation binding")
        return
    fields(binding, {"slotAddress", "relocationLocator", "relocationType", "relocationAddend", "dynamicTables", "slotLoadIndices", "slotFileOffset",
        "relocationDispositions", "writeCoverage", "symbolTableSectionIndex", "symbolIndex", "symbolLocator", "runtimeImplementationAvailable",
        "runtimeProviderAvailable"}, "relocation binding")
    require(binding["runtimeImplementationAvailable"] is False and binding["runtimeProviderAvailable"] is False and address(binding["slotAddress"]) == slot,
            "binding grants runtime authority or differs from slot")
    relocation = relocations.get(binding["relocationLocator"])
    if relocation is None or address(relocation["offset"]) != slot:
        raise VerificationError("missing slot relocation")
    for target, source in (("relocationType", "type"), ("relocationAddend", "addend"), ("relocationDispositions", "dispositions"),
            ("dynamicTables", "dynamicTables"), ("slotLoadIndices", "slotLoadIndices"), ("slotFileOffset", "slotFileOffset"),
            ("symbolTableSectionIndex", "symbolTableSectionIndex"), ("symbolIndex", "symbolIndex")):
        require(canonical_bytes(binding[target]) == canonical_bytes(relocation[source]), "relocation binding differs from inventory")
    key = (relocation["symbolTableSectionIndex"], relocation["symbolIndex"])
    require(binding["symbolLocator"] == symbols[key]["locator"] and site["externalTargetId"] == imports.get(key), "external symbol identity differs")
    coverage = fields(binding["writeCoverage"], {"kind", "slotAddress", "candidateLocator", "candidateActive", "candidateCoversSlot", "slotAddressOverflow",
        "unknownWriteWidth", "writeAddressOverflow", "overlappingWrite", "overlapLocator", "unknownWidthLocator", "overflowLocator",
        "safeForStaticSlotAssociation", "negativeCompleteness"}, "relocation write coverage")
    require(coverage["kind"] == "elf-relocation-slot-write-coverage-v1" and coverage["slotAddress"] == binding["slotAddress"] and
            coverage["candidateLocator"] == binding["relocationLocator"] and coverage["negativeCompleteness"] is False, "write coverage boundary differs")
    flags = ("candidateActive", "candidateCoversSlot", "slotAddressOverflow", "unknownWriteWidth", "writeAddressOverflow", "overlappingWrite", "safeForStaticSlotAssociation")
    require(all(type(coverage[key]) is bool for key in flags), "write coverage flags must be booleans")
    for flag, locator in (("overlappingWrite", "overlapLocator"), ("unknownWriteWidth", "unknownWidthLocator"), ("writeAddressOverflow", "overflowLocator")):
        if coverage[locator] is not None:
            text(coverage[locator])
        require(coverage[flag] is (coverage[locator] is not None), "write coverage flag/witness differs")
    safe = coverage["candidateActive"] and coverage["candidateCoversSlot"] and not any(coverage[key] for key in flags[2:6])
    require(coverage["safeForStaticSlotAssociation"] is safe, "write coverage summary differs")
    if site["targetBindingDisposition"] == "static-import-request-reference":
        require(safe and site["externalTargetId"] is not None and relocation_index.static_import(relocation, symbols[key], slot) and
                transfer["classification"] == ("indirect-jump" if site["viaForwarder"] else "indirect-call"),
                "static import disposition contradicts retained binding")


def verify_envelope(evidence: dict, kind: str) -> None:
    fields(evidence, {"schemaVersion", "kind", "authority", "complete", "releaseEligible", "negativeCompleteness", "containmentStatus",
        "counts", "inputs", "payloads", "producerJar", "runtime", "source"} | ({"sourceEvidence"} if kind == EXTERNAL_KIND else set()), "evidence")
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["kind"] == kind and
            evidence["authority"] == "component-only" and evidence["containmentStatus"] == "external-owner-required", "unsupported evidence boundary")
    false_authority(evidence)
    fields(evidence["counts"], EXTERNAL_COUNTS if kind == EXTERNAL_KIND else COUNTS, "evidence counts")
    for key, value in evidence["counts"].items():
        if key == "dispositions":
            require(type(value) is dict, "invalid disposition counts")
            for disposition, count in value.items():
                text(disposition, 128)
                integer(count, 1, 100000)
        else:
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
    inputs = fields(evidence["inputs"], {"rich"} if kind == EXTERNAL_KIND else {"artifactManifest", "canonicalOracle", "rich"}, "evidence inputs")
    for reference in inputs.values():
        file_reference(reference)


def read_payloads(evidence: dict, load) -> tuple[bytes, bytes, dict, dict]:
    """load consumes a relative payload reference, never an original-host request path."""
    payloads = fields(evidence["payloads"], {"report", "request"}, "evidence payloads")
    file_reference(payloads["request"])
    file_reference(payloads["report"], stored=True)
    require(payloads["report"]["path"] != payloads["request"]["path"], "payload paths overlap")
    request_bytes = load(payloads["request"], MAX_CONTROL_BYTES)
    verify_bytes(request_bytes, payloads["request"])
    report_reference = payloads["report"]
    report_stored = load({"path": report_reference["path"], "bytes": report_reference["storedBytes"],
                          "sha256": report_reference["storedSha256"]}, MAX_BYTES)
    verify_bytes(report_stored, payloads["report"], stored=True)
    report_bytes = inflate_report(report_stored)
    verify_bytes(report_bytes, payloads["report"])
    request, report = parse_canonical(request_bytes, MAX_CONTROL_BYTES), parse_canonical(report_bytes)
    return request_bytes, report_bytes, request, report


def verify_source(evidence: dict, expected_paths: set[str]) -> str:
    source = fields(evidence["source"], {"commit", "tree", "files"}, "source provenance")
    commit, tree = digest(source["commit"], 40), digest(source["tree"], 40)
    try:
        verify_git_object(commit, "commit")
    except VerificationError as error:
        raise VerificationError(f"recorded source commit {commit} is unavailable or invalid; fetch that commit's history before offline verification") from error
    verify_git_object(tree, "tree")
    require(git(["show", "-s", "--format=%T", commit], 64) == (tree + "\n").encode(), "recorded source commit/tree disagree")
    raw_source_files = source["files"]
    if type(raw_source_files) is not list:
        raise VerificationError("incomplete source inventory")
    source_files = cast(list[dict], raw_source_files)
    require(len(source_files) == len(expected_paths), "incomplete source inventory")
    for reference in source_files:
        file_reference(reference)
    require([item["path"] for item in source_files] == sorted(expected_paths), "source inventory is not exact and ordered")
    for reference in [*source_files, *evidence["inputs"].values()]:
        verify_git_blob(commit, reference)
    return commit


def verify_machine_evidence(evidence: dict, load) -> tuple[bytes, bytes, dict, dict]:
    # Intentionally single-level: an external manifest cannot be used as source evidence.
    verify_envelope(evidence, MACHINE_KIND)
    payloads = read_payloads(evidence, load)
    _request_bytes, report_bytes, request, report = payloads
    verify_report_bindings(evidence, request, report)
    require(len(report_bytes) <= request["limits"]["maximumOutputBytes"], "report exceeds committed output limit")
    verify_source(evidence, SOURCE_PATHS)
    return payloads


def verify_evidence(evidence_path: Path) -> tuple[bytes, dict]:
    evidence_path = repository_path(evidence_path, existing=True)
    evidence = parse_canonical(read_file(evidence_path, MAX_CONTROL_BYTES), MAX_CONTROL_BYTES)
    def load(reference: dict, maximum: int) -> bytes:
        return read_file(evidence_path.parent / reference["path"], maximum)
    if evidence.get("kind") == MACHINE_KIND:
        _, report_bytes, _, _ = verify_machine_evidence(evidence, load)
    else:
        verify_envelope(evidence, EXTERNAL_KIND)
        commit = verify_source(evidence, EXTERNAL_SOURCE_PATHS)
        source_reference = file_reference(evidence["sourceEvidence"])
        source = parse_canonical(read_git_blob(commit, source_reference, MAX_CONTROL_BYTES), MAX_CONTROL_BYTES)
        parent = PurePosixPath(source_reference["path"]).parent

        def load_source(reference: dict, maximum: int) -> bytes:
            path = relative_path(str(parent / relative_path(reference["path"])))
            return read_git_blob(commit, reference | {"path": path}, maximum)

        source_request_bytes, source_report_bytes, source_request, source_report = verify_machine_evidence(source, load_source)
        _, report_bytes, request, report = read_payloads(evidence, load)
        verify_external_bindings(evidence, request, report, source, source_request_bytes, source_report_bytes, source_request, source_report)
        require(len(report_bytes) <= request["limits"]["maximumOutputBytes"], "report exceeds committed output limit")
    return report_bytes, evidence["counts"]


def extract_report(destination: Path, report_bytes: bytes) -> None:
    with open_repository_parent(destination, existing=False) as (parent, leaf):
        try:
            descriptor = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=parent)
        except FileExistsError as error:
            raise VerificationError("extraction destination already exists") from error
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(report_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(leaf, dir_fd=parent)
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
    if "physicalCallSites" in counts:
        print(f"verified retained component payloads and recorded Git blobs: {counts['physicalCallSites']} call sites, "
              f"{counts['positiveInternalCallSites']} positive internal sites")
    else:
        print(f"verified retained component payloads and recorded Git blobs: {counts['sourcePhysicalSites']} source call sites, "
              f"{counts['namespaceEntries']} static import requests")
    print("Component-only; no production qualification. Producer JAR identity is a recorded build observation; "
          "its bytes and source-to-binary attestation are not verified.")
    if arguments.extract_report is not None:
        print(f"recovered exact report: {arguments.extract_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
