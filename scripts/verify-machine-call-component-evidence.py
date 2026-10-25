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


def address(value: object, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    require(type(value) is str and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", value) is not None,
            "invalid canonical unsigned address")
    return int(value, 16)


def inventory_rows(value: object, keys: set[str], maximum: int, label: str) -> list[dict]:
    require(type(value) is list and len(value) <= maximum, f"{label}: inventory exceeds bound")
    for item in value:
        fields(item, keys, label)
    return value


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
    "versionRequirements": (131072, {"sectionIndex", "stringSectionIndex", "recordOffset", "auxiliaryOffset", "providerRequest", "name",
        "rawIndex", "index", "flags", "hash"}),
    "versionDefinitions": (131072, {"sectionIndex", "stringSectionIndex", "recordOffset", "rawIndex", "index", "flags", "hash", "name",
        "parentNames", "auxiliaryOffsets"}),
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
    list_fields = {"dynamicTables", "slotLoadIndices", "dispositions", "parentNames", "auxiliaryOffsets"}
    for group in INVENTORY_ROWS:
        for row in inventory[group]:
            for key, value in row.items():
                if key == "version":
                    continue  # Closed below with the version schema.
                if key in list_fields:
                    require(type(value) is list and len(value) <= 65535, "metadata array exceeds bound")
                    for item in value:
                        if key in {"slotLoadIndices", "auxiliaryOffsets"}:
                            integer(item, 0, (1 << 63) - 1)
                        else:
                            require(type(item) is str and len(item) <= 16384, "invalid metadata array string")
                elif key in string_fields:
                    require(type(value) is str and len(value) <= 16384 and "\0" not in value, "invalid metadata string")
                elif key in address_fields and not (key == "flags" and group in {"programHeaders", "versionRequirements", "versionDefinitions"}):
                    address(value)
                elif key == "offset" and group in {"programHeaders", "relocations"}:
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


def verify_external_bindings(evidence: dict, request: dict, report: dict, source: dict,
        source_request_bytes: bytes, source_report_bytes: bytes, source_request: dict, source_report: dict) -> None:
    fields(request, {"schemaVersion", "kind", "richFile", "sourceReport", "sourceRequest", "runtime", "outputPath", "limits", "metadataPolicy"}, "external request")
    require(type(request["schemaVersion"]) is int and request["schemaVersion"] == 1 and request["kind"] == "independent-external-call-request-v1",
            "external request schema differs")
    informational_path(request["outputPath"])
    runtime = fields(request["runtime"], RUNTIME | RUNTIME_PATHS, "external request runtime")
    for key in RUNTIME_PATHS:
        informational_path(runtime[key])
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
    require(report["requestSha256"] == evidence["payloads"]["request"]["sha256"] and canonical_bytes(report["runtime"]) == canonical_bytes(runtime) and
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
    sites = inventory_rows(report["sites"], SITE_KEYS, limits["maximumCalls"], "external sites")
    require(len(sites) == len(source_report["calls"]), "source physical calls were omitted or duplicated")
    counts = {}
    for ordinal, (site, call) in enumerate(zip(sites, source_report["calls"])):
        require(type(site["sourceOrdinal"]) is int and site["sourceOrdinal"] == ordinal and site["negativeCompleteness"] is False and
                type(site["viaForwarder"]) is bool, "site identity/authority differs")
        for key in ("callerRoot", "callerCanonicalId", "callerRva", "instructionRva", "instructionBytes", "instructionLength"):
            require(type(site[key]) is type(call[key]) and site[key] == call[key], "source physical site differs")
        require(site["physicalClassification"] == call["classification"] and site["physicalTargetAddress"] == call["directTargetAddress"] and
                site["sourceDisposition"] == call["disposition"] and site["returnAddress"] == call["fallthroughAddress"], "source physical transfer differs")
        location = base + address(site["instructionRva"])
        require(location <= (1 << 64) - 1 and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", site["instructionBytes"]) is not None and
                len(site["instructionBytes"]) == 2 * integer(site["instructionLength"], 1, 15) and
                address(site["returnAddress"]) == location + site["instructionLength"], "invalid source instruction coordinates")
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
        if site["sourceDisposition"] == "unresolved-instruction-overlap" or address(site["physicalTargetAddress"], nullable=True) in canonical_addresses:
            expected_binding = "unresolved-source-instruction-boundary" if site["sourceDisposition"] == "unresolved-instruction-overlap" else "retained-canonical-target"
            require(site["targetBindingDisposition"] == expected_binding and site["viaForwarder"] is False and
                    all(site[key] is None for key in ("memoryProbe", "memoryTransfer", "relocationBinding", "externalTargetId")),
                    "canonical/source-boundary site gained external evidence")
        counts[status] = counts.get(status, 0) + 1
        verify_external_site(site, location, symbols, relocations, imports)
    expected_counts = {"sourcePhysicalSites": len(sites), "composedSiteRecords": len(sites), "namespaceEntries": len(imports), "dispositions": counts}
    fields(report["counts"], EXTERNAL_COUNTS, "external report counts")
    require(canonical_bytes(report["counts"]) == canonical_bytes(expected_counts) == canonical_bytes(evidence["counts"]),
            "external counts differ from retained populations")


def verify_external_site(site: dict, location: int, symbols: dict, relocations: dict, imports: dict) -> None:
    probe, transfer, binding = (site[key] for key in ("memoryProbe", "memoryTransfer", "relocationBinding"))
    if site["targetBindingDisposition"] == "static-import-request-reference":
        require(binding is not None and site["externalTargetId"] is not None, "static import disposition has no binding")
    if probe is None:
        require(transfer is None and binding is None and site["externalTargetId"] is None, "proof without byte probe")
        return
    fields(probe, {"address", "availableBytes", "refusal"}, "memory probe")
    probe_address = address(probe["address"])
    expected_address = address(site["physicalTargetAddress"]) if site["viaForwarder"] else location
    require(probe_address == expected_address and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", probe["availableBytes"]) is not None, "memory probe coordinates differ")
    if probe["refusal"] is not None:
        require(re.fullmatch(r"[a-z0-9-]{1,128}", text(probe["refusal"], 128)) is not None and transfer is None and binding is None and
                site["externalTargetId"] is None, "decoder refusal contains proof")
        return
    fields(transfer, TRANSFER_KEYS, "memory transfer")
    require(transfer["classification"] in TRANSFER_CLASSIFICATIONS and transfer["contextStatus"] in TRANSFER_CONTEXTS, "unknown transfer classification/context")
    require(address(transfer["address"]) == probe_address and type(transfer["bytes"]) is str and
            re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", transfer["bytes"]) is not None and
            len(transfer["bytes"]) == 2 * integer(transfer["length"], 1, 15) and probe["availableBytes"].startswith(transfer["bytes"]), "memory transfer byte commitment differs")
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
    require(relocation is not None and address(relocation["offset"]) == slot, "missing slot relocation")
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
        require(safe and site["externalTargetId"] is not None and symbols[key]["binding"] == 1 and symbols[key]["type"] == 2,
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
    require(type(source["files"]) is list and len(source["files"]) == len(expected_paths), "incomplete source inventory")
    for reference in source["files"]:
        file_reference(reference)
    require([item["path"] for item in source["files"]] == sorted(expected_paths), "source inventory is not exact and ordered")
    for reference in [*source["files"], *evidence["inputs"].values()]:
        verify_git_blob(commit, reference)
    return commit


def verify_machine_evidence(evidence: dict, load) -> tuple[bytes, bytes, dict, dict]:
    # Intentionally single-level: an external manifest cannot be used as source evidence.
    verify_envelope(evidence, MACHINE_KIND)
    payloads = read_payloads(evidence, load)
    request_bytes, report_bytes, request, report = payloads
    verify_report_bindings(evidence, request, report)
    require(len(report_bytes) <= request["limits"]["maximumOutputBytes"], "report exceeds committed output limit")
    verify_source(evidence, SOURCE_PATHS)
    return payloads


def verify_evidence(evidence_path: Path) -> tuple[bytes, dict]:
    evidence_path = repository_path(evidence_path, existing=True)
    evidence = parse_canonical(read_file(evidence_path, MAX_CONTROL_BYTES), MAX_CONTROL_BYTES)
    load = lambda reference, maximum: read_file(evidence_path.parent / reference["path"], maximum)
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
