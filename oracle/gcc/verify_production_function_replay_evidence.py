"""Bounded offline integrity checks for retained GCC selected-function evidence.

No serialized receipt, hash, Actions label, or result returned here recreates a live
production capability. Source identity is checked at the recorded commit, never HEAD.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
import zlib


MAX_DECODED_BYTES = 32 * 1024 * 1024
MAX_TOTAL_DECODED_BYTES = 96 * 1024 * 1024
MAX_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
MAX_COMMIT_BYTES = 64 * 1024
MAX_CANONICAL_NODES = 2_000_000
DOMAINS = ["model-provenance", "function-boundaries", "surviving-symbol-identities"]
UNAVAILABLE = ["interfaces", "calls", "globals", "types", "calibration"]
ROLES = frozenset(("model", "qualification", "result", "accuracy", "boundary-score",
    "boundary-observation", "full-export-binding", "replay-request", "replay-output",
    "replay-capture", "replay-execution", "replay-attachment", "start-authorized",
    "export-execution", "export-attachment", "export-assessment", "intent", "tree-manifest",
    "launcher-summary", "invocation", "actions-log", "launcher-invocation", "launcher-result"))


class EvidenceError(ValueError):
    """The retained evidence is malformed, inconsistent, or outside its bounds."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _object(value: Any, fields: set[str] | None = None) -> dict:
    _require(type(value) is dict, "expected an object")
    if fields is not None:
        _require(value.keys() == fields, "object has missing or unknown fields")
    return value


def _integer(value: Any, maximum: int, minimum: int = 0) -> int:
    _require(type(value) is int and minimum <= value <= maximum, "integer is outside its bound")
    return value


def _digest(value: Any, length: int = 64) -> str:
    _require(type(value) is str and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None,
             "invalid digest")
    return value


def _relative(value: Any) -> str:
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096,
             "invalid relative path")
    path = PurePosixPath(value)
    _require(not path.is_absolute() and str(path) == value and
             all(part not in (".", "..", "") for part in value.split("/")) and
             "\\" not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value),
             "path contains traversal or an alias")
    return value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class _CanonicalBudget:
    """Charge occurrences, not unique objects, before expanding or encoding JSON."""

    def __init__(self) -> None:
        self.bytes = 0
        self.nodes = 0

    def charge(self, size: int, nodes: int = 0) -> None:
        self.bytes += size
        self.nodes += nodes
        _require(self.bytes <= MAX_DECODED_BYTES, "canonical JSON byte budget exceeded")
        _require(self.nodes <= MAX_CANONICAL_NODES, "canonical JSON node budget exceeded")

    def add(self, value: Any, depth: int = 0) -> None:
        _require(depth <= 64, "canonical JSON depth exceeds its bound")
        self.charge(0, 1)
        if type(value) in (dict, list):
            count = len(value)
            self.charge(2)  # Braces or brackets.
            if count:
                # Entry indentation, commas and newlines (indent=2). The final
                # newline replaces the absent comma after the last entry.
                self.charge(count * (2 * (depth + 1) + 2) + 2 * depth)
            if type(value) is dict:
                self.charge(2 * count)  # Colon and space for each member.
                for key, child in value.items():
                    _require(type(key) is str, "canonical JSON key is not a string")
                    self.add(key, depth + 1)
                    self.add(child, depth + 1)
            else:
                for child in value:
                    self.add(child, depth + 1)
        elif type(value) is str:
            self.charge(2)  # Quotes; only bounded fragments are escaped here.
            for start in range(0, len(value), 4096):
                try:
                    escaped = json.dumps(value[start:start + 4096], ensure_ascii=False)
                    self.charge(len(escaped.encode("utf-8", "strict")) - 2)
                except UnicodeError as error:
                    raise EvidenceError("canonical JSON is not strict UTF-8") from error
        elif value is None or type(value) in (bool, int, float):
            if type(value) is int:
                _require(value.bit_length() <= 426 and len(str(value)) <= 128,
                         "canonical JSON integer exceeds its bound")
            if type(value) is float:
                _require(math.isfinite(value), "non-finite canonical JSON number")
            self.charge(len(json.dumps(value, allow_nan=False)))
        else:
            raise EvidenceError("unsupported canonical JSON value")


def _canonical(value: Any) -> bytes:
    budget = _CanonicalBudget()
    budget.add(value)
    budget.charge(1)  # Final newline is part of every canonical commitment.
    # Preflight bounds even an individual encoder chunk; streaming also avoids
    # materializing the complete Unicode encoding alongside the UTF-8 result.
    encoded = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
    for chunk in encoder.iterencode(value):
        data = chunk.encode("utf-8", "strict")
        _require(len(encoded) + len(data) < MAX_DECODED_BYTES, "canonical JSON byte budget exceeded")
        encoded.extend(data)
    encoded.extend(b"\n")
    return bytes(encoded)


def _json(payload: bytes) -> dict:
    # Bound depth and token allocation before json.loads constructs its object tree.
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("JSON is not strict UTF-8") from error
    depth = tokens = 0
    quoted = escaped = False
    previous = ""
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
            tokens += 1
        elif char in "[{":
            depth += 1
            tokens += 1
            _require(depth <= 64, "JSON depth exceeds its bound")
        elif char in "]}":
            depth -= 1
        elif char in "-0123456789tfn" and previous in "[:,":
            tokens += 1
        if not char.isspace():
            previous = char
        _require(tokens <= 2_000_000, "JSON token allocation exceeds its bound")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(unused: str) -> None:
        raise EvidenceError("non-finite JSON number")

    def integer(token: str) -> int:
        _require(len(token) <= 128, "JSON integer token exceeds its bound")
        return int(token)

    def floating(token: str) -> float:
        _require(len(token) <= 128, "JSON floating token exceeds its bound")
        value = float(token)
        _require(math.isfinite(value), "non-finite JSON number")
        return value

    try:
        document = _object(json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                                      parse_int=integer, parse_float=floating))
        pending = [document]
        while pending:
            value = pending.pop()
            if type(value) is dict:
                pending.extend(value.keys())
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
            elif type(value) is str:
                value.encode("utf-8", "strict")
        return document
    except EvidenceError:
        raise
    except (ValueError, OverflowError, RecursionError) as error:
        raise EvidenceError("malformed or trailing JSON") from error


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _snapshot(path: Path, maximum: int, seen: set[tuple[int, int]]) -> bytes:
    """Walk every component without following links, then read one stable bounded file."""
    _require(path.is_absolute() and ".." not in path.parts, "snapshot path is not absolute and normalized")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors: list[int] = []
    ancestry: list[tuple[int, str, int, tuple]] = []
    try:
        parent = os.open("/", flags | os.O_DIRECTORY)
        descriptors.append(parent)
        for name in path.parts[1:-1]:
            child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
            descriptors.append(child)
            ancestry.append((parent, name, child, _directory_identity(os.fstat(child))))
            parent = child
        descriptor = os.open(path.name, flags, dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 "snapshot must be a single-link regular file")
        _require(0 < before.st_size <= maximum, "snapshot byte bound exceeded")
        key = before.st_dev, before.st_ino
        _require(key not in seen, "snapshot aliases another retained input")
        seen.add(key)
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size - len(data)))
            _require(bool(chunk), "snapshot ended before its pinned size")
            data.extend(chunk)
        _require(not os.read(descriptor, 1), "snapshot grew while reading")
        _require(_identity(os.fstat(descriptor)) == _identity(before) ==
                 _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 "snapshot identity or metadata changed")
        for parent_fd, name, child_fd, expected in ancestry:
            _require(_directory_identity(os.fstat(child_fd)) == expected ==
                     _directory_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                     "snapshot ancestor changed")
        return bytes(data)
    except OSError as error:
        raise EvidenceError(f"cannot read a safe retained snapshot: {path.name}") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _commitment(value: dict, maximum: int) -> tuple[str, int, str]:
    _object(value, {"path", "bytes", "sha256"})
    return _relative(value["path"]), _integer(value["bytes"], maximum, 1), _digest(value["sha256"])


def _committed_snapshot(base: Path, value: dict, maximum: int, seen: set) -> bytes:
    path, size, digest = _commitment(value, maximum)
    data = _snapshot(base / path, maximum, seen)
    _require(len(data) == size and _sha(data) == digest, "retained commitment differs from exact bytes")
    return data


def _gunzip(data: bytes, expected_bytes: int) -> bytes:
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(data, expected_bytes + 1)
        _require(len(decoded) == expected_bytes and decoder.eof and
                 not decoder.unused_data and not decoder.unconsumed_tail,
                 "gzip is oversized, incomplete, concatenated, or has trailing bytes")
        return decoded
    except zlib.error as error:
        raise EvidenceError("malformed gzip") from error


def _git_oid(kind: bytes, body: bytes) -> str:
    return hashlib.sha1(kind + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def _inventory_tree(inventory: bytes) -> tuple[str, dict]:
    _require(inventory.endswith(b"\0"), "source inventory is not NUL terminated")
    records = inventory[:-1].split(b"\0")
    _require(0 < len(records) <= 100000, "source inventory count exceeds its bound")
    root: dict = {}
    entries = {}
    for record in records:
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        _require((mode in (b"100644", b"100755", b"120000") and kind == b"blob") or
                 (mode == b"160000" and kind == b"commit"), "invalid source inventory mode/type")
        _digest(oid.decode("ascii"), 40)
        parts = name.split(b"/")
        _require(0 < len(parts) <= 64 and len(name) <= 4096 and
                 all(part not in (b"", b".", b"..") for part in parts) and name not in entries,
                 "source inventory has duplicate or aliased paths")
        entries[name] = (mode, kind, oid)
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
            _require(type(directory) is dict, "source inventory file/directory collision")
        _require(parts[-1] not in directory, "source inventory duplicate entry")
        directory[parts[-1]] = (mode, oid)

    def tree(directory: dict) -> str:
        body = bytearray()
        for name, value in sorted(directory.items(), key=lambda row: row[0] + (b"/" if type(row[1]) is dict else b"\0")):
            mode, oid = (b"40000", tree(value).encode()) if type(value) is dict else value
            body.extend(mode + b" " + name + b"\0" + bytes.fromhex(oid.decode()))
        return _git_oid(b"tree", bytes(body))

    rendered = bytearray()
    def render(directory: dict, prefix: bytes = b"") -> None:
        for name, value in sorted(directory.items(), key=lambda row: row[0] + (b"/" if type(row[1]) is dict else b"\0")):
            path = prefix + name
            if type(value) is dict:
                render(value, path + b"/")
            else:
                mode, kind, oid = entries[path]
                rendered.extend(mode + b" " + kind + b" " + oid + b"\t" + path + b"\0")
    render(root)
    _require(bytes(rendered) == inventory, "source inventory is not the exact canonical ls-tree representation")
    return tree(root), entries


def _source(base: Path, source: dict, oracle_path: str,
            oracle: bytes, seen: set) -> None:
    _object(source, {"commit", "commitObject", "treeSha1", "inventory", "checkoutCommit", "checkoutCommitObject"})
    commit = _digest(source["commit"], 40)
    tree = _digest(source["treeSha1"], 40)
    original = _committed_snapshot(base, source["commitObject"], MAX_COMMIT_BYTES, seen)
    _require(_git_oid(b"commit", original) == commit, "original source Git commit identity differs")
    original_headers = original.split(b"\n\n", 1)[0].split(b"\n")
    _require([line[5:] for line in original_headers if line.startswith(b"tree ")] == [tree.encode()],
             "original source commit tree differs")
    inventory = _committed_snapshot(base, source["inventory"], MAX_INVENTORY_BYTES, seen)
    calculated, entries = _inventory_tree(inventory)
    _require(calculated == tree, "source inventory differs from its original commit tree")
    _require(oracle_path.encode() in entries, "oracle is absent from the original source tree")
    mode, kind, blob = entries[oracle_path.encode()]
    _require(mode in (b"100644", b"100755") and kind == b"blob" and
             _git_oid(b"blob", oracle).encode() == blob,
             "oracle bytes differ from the original source blob")
    checkout = _committed_snapshot(base, source["checkoutCommitObject"], MAX_COMMIT_BYTES, seen)
    _require(_git_oid(b"commit", checkout) ==
             _digest(source["checkoutCommit"], 40), "checkout Git object identity differs")
    headers = checkout.split(b"\n\n", 1)[0].split(b"\n")
    _require([line[5:] for line in headers if line.startswith(b"tree ")] == [tree.encode()] and
             b"parent " + commit.encode() in headers, "checkout is not the recorded source tree and parent")


def _rows(value: Any, maximum: int = 131072) -> list:
    _require(type(value) is list and len(value) <= maximum, "record population exceeds its bound")
    return value


def _rva(value: Any) -> int:
    _require(type(value) is str and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", value) is not None,
             "invalid canonical address")
    return int(value, 16)


def rederive_measurements(model: dict, oracle: dict, observation: dict) -> dict:
    """Derive exact starts and every surviving alias from raw model and oracle records."""
    _require(observation["twin"] == "stripped", "only the selected stripped-twin checkpoint is supported")
    base = _rva(observation["selectedModelImageBase"])
    _require(model["inputSha256"] == observation["inputSha256"] == oracle["artifacts"]["stripped"]["inputSha256"],
             "model/oracle selected input differs")
    recovered = {}
    recovered_ids = set()
    for function in _rows(model["functions"]):
        rva = _rva(function["address"]) - base
        _require(rva >= 0 and rva not in recovered and function["id"] not in recovered_ids,
                 "duplicate or below-image recovered function")
        _require(function["extractionStatus"] in ("recovered", "partial", "failed", "synthetic"),
                 "unknown recovered status")
        recovered[rva] = function
        recovered_ids.add(function["id"])
    references, exclusions, oracle_ids = {}, {}, set()
    for function in _rows(oracle["functions"], 20000):
        _require(function["id"] not in oracle_ids, "duplicate oracle identity")
        oracle_ids.add(function["id"])
        rva = None if function["rva"] is None else _rva(function["rva"])
        exclusion = function["exclusion"]
        if exclusion is None:
            _require(rva is not None and rva not in references, "invalid or duplicate oracle start")
            references[rva] = function
        else:
            _require(exclusion["kind"] in ("compiler-generated", "inlined") and
                     (exclusion["kind"] == "inlined") == (rva is None), "invalid oracle exclusion")
            exclusions[function["id"]] = function
    compiler = {_rva(f["rva"]): f for f in exclusions.values() if f["exclusion"]["kind"] == "compiler-generated"}
    _require(len(compiler) == sum(f["exclusion"]["kind"] == "compiler-generated" for f in exclusions.values()) and
             not references.keys() & compiler.keys(), "overlapping oracle starts")
    ignored = recovered.keys() & compiler.keys()
    selected = recovered.keys() - ignored
    exact = selected & references.keys()
    parts = observation["result"]
    seen_recovered, seen_oracle = set(), set()
    observed_excluded = {}
    for row in _rows(observation["excludedFunctions"], 20000):
        identifier = row["oracleId"]
        _require(identifier not in observed_excluded and identifier in exclusions, "unknown/duplicate exclusion")
        function = exclusions[identifier]
        _require(row == {"oracleId": identifier, "rva": function["rva"], "aliases": function["aliases"],
                         **function["exclusion"]}, "exclusion differs from the raw oracle")
        observed_excluded[identifier] = row
    _require(observed_excluded.keys() == exclusions.keys(), "excluded oracle population is incomplete")

    def candidate(row: dict) -> int:
        rva = _rva(row["recoveredRva"])
        _require(rva in recovered and rva not in seen_recovered, "unknown/duplicate recovered partition")
        function = recovered[rva]
        _require((row["recoveredId"], row["recoveredName"], row["recoveredStatus"]) ==
                 (function["id"], function["name"], function["extractionStatus"]), "recovered partition substitutes model identity")
        seen_recovered.add(rva)
        return rva

    def reference(row: dict) -> int:
        rva = _rva(row["oracleRva"])
        _require(rva in references and rva not in seen_oracle, "unknown/duplicate oracle partition")
        function = references[rva]
        aliases = [{**a, "availability": a["availability"]["stripped"]} for a in function["aliases"]]
        _require(row["oracleId"] == function["id"] and row["oracleAliases"] == aliases,
                 "oracle partition substitutes an identity or alias")
        seen_oracle.add(rva)
        return rva

    observed_exact = set()
    for row in _rows(parts["exactMatches"]):
        rr, oo = candidate(row), reference(row)
        _require(rr == oo and row["matchKind"] == "exact" and type(row["deltaBytes"]) is int and
                 row["deltaBytes"] == 0, "non-exact start credited as exact")
        observed_exact.add(rr)
    _require(observed_exact == exact, "exact start intersection differs from the raw populations")
    near_bound = _integer(observation["nearMissBytes"], 4096, 1)
    for row in _rows(parts["nearMisses"]):
        rr, oo = candidate(row), reference(row)
        _require(rr not in ignored and 0 < abs(rr - oo) <= near_bound and
                 row["matchKind"] == "near" and type(row["deltaBytes"]) is int and
                 row["deltaBytes"] == rr - oo, "invalid near-only partition")
    unmatched_recovered = selected - exact
    for row in _rows(parts["falsePositives"]):
        _require(candidate(row) in unmatched_recovered, "invalid false-positive partition")
    for row in _rows(parts["falseNegatives"]):
        _require(reference(row) not in exact, "invalid false-negative partition")
    observed_ignored = set()
    for row in _rows(parts["ignoredExcludedRecoveries"]):
        rr = candidate(row)
        _require(rr in ignored and row["oracleId"] == compiler[rr]["id"] and
                 row["exclusionKind"] == compiler[rr]["exclusion"]["kind"] and
                 row["exclusionReason"] == compiler[rr]["exclusion"]["reason"], "invalid ignored recovered owner")
        observed_ignored.add(rr)
    _require(seen_recovered == recovered.keys() and seen_oracle == references.keys() and observed_ignored == ignored,
             "function partitions omit an eligible identity")
    statuses = {name: 0 for name in ("recovered", "partial", "failed", "synthetic")}
    statuses.update(Counter(f["extractionStatus"] for f in recovered.values()))
    _require(_canonical(observation["recoveredOutcomeCounts"]) == _canonical(statuses), "recovered status census differs")
    counts = {"referenceCount": len(references), "rawRecoveredCount": len(recovered), "scoredRecoveredCount": len(selected),
              "ignoredExcludedCount": len(ignored), "exactMatches": len(exact), "nearMisses": len(parts["nearMisses"]),
              "truePositives": len(exact) + len(parts["nearMisses"]), "falsePositives": len(parts["falsePositives"]),
              "falseNegatives": len(parts["falseNegatives"]),
              "nearMissDistanceBytes": sum(abs(row["deltaBytes"]) for row in parts["nearMisses"])}
    _require(all(type(parts["boundaries"][key]) is int and parts["boundaries"][key] == value
                 for key, value in counts.items()), "boundary count summary differs from complete raw partitions")
    symbols = []
    projection_budget = _CanonicalBudget()
    for function in sorted(oracle["functions"], key=lambda f: (f["rva"] is None, _rva(f["rva"]) if f["rva"] else 0, f["id"])):
        names = set()
        for alias in sorted(_rows(function["aliases"], 256), key=lambda a: a["name"]):
            name = alias["name"]
            _require(type(name) is str and 0 < len(name) <= 4096 and name not in names, "invalid/duplicate oracle alias")
            names.add(name)
            availability = alias["availability"]["stripped"]
            _require(availability in ("surviving", "removed", "not-observable"), "invalid symbol availability")
            if availability != "surviving":
                continue
            _require(function["rva"] is not None, "surviving alias lacks an exact start")
            found = recovered.get(_rva(function["rva"]))
            outcome = "missing" if found is None else "exact" if found["name"] == name else "name-mismatch"
            row = {"oracleId": function["id"], "name": name, "rva": function["rva"],
                "oracleExcluded": function["exclusion"] is not None, "exclusion": function["exclusion"], "outcome": outcome,
                "recoveredId": found["id"] if found else None, "recoveredRva": function["rva"] if found else None,
                "recoveredName": found["name"] if found else None, "recoveredStatus": found["extractionStatus"] if found else None}
            # The row is at depth three in measurements. Charge every repeated
            # field, including nested exclusions, before growing the population.
            projection_budget.add(row, depth=3)
            projection_budget.charge(8)  # Parent-list indentation, comma, newline.
            symbols.append(row)
    outcomes = Counter(s["outcome"] for s in symbols)
    return {"provider": "structural-function-accuracy-v1", "schemaVersion": 1, "twin": "stripped",
        "sourcePartitions": {**{name: "/result/" + name for name in ("exactMatches", "nearMisses", "falsePositives", "falseNegatives", "ignoredExcludedRecoveries")}, "excludedFunctions": "/excludedFunctions"},
        "oraclePopulation": {"totalFunctions": len(oracle_ids), "scoreableFunctions": len(references),
            "excludedFunctions": len(exclusions), "compilerGenerated": len(compiler), "inlined": len(exclusions) - len(compiler)},
        "functionStarts": {"referenceCount": len(references), "rawRecoveredCount": len(recovered),
            "scoredRecoveredCount": len(selected), "ignoredExcludedCount": len(ignored), "exactMatches": len(exact),
            "nearMisses": len(parts["nearMisses"]), "falsePositives": len(selected) - len(exact),
            "falseNegatives": len(references) - len(exact), "precision": {"numerator": len(exact), "denominator": len(selected)},
            "recall": {"numerator": len(exact), "denominator": len(references)}},
        "survivingSymbolIdentity": {"populationDefinition": "all selected-twin surviving oracle aliases, including excluded functions, looked up at the exact oracle RVA",
            "population": len(symbols), "exact": outcomes["exact"], "nameMismatch": outcomes["name-mismatch"], "missing": outcomes["missing"],
            "identityRecovery": {"numerator": outcomes["exact"], "denominator": len(symbols)}, "symbols": symbols}}


def verify_accuracy(accuracy: dict, measurements: dict) -> dict:
    _require(_canonical(accuracy["score"]["measurements"]) == _canonical(measurements),
             "reported measurements differ from the complete raw populations")
    starts, symbols = measurements["functionStarts"], measurements["survivingSymbolIdentity"]
    precision = starts["scoredRecoveredCount"] > 0 and starts["exactMatches"] * 20 >= starts["scoredRecoveredCount"] * 19
    recall = starts["referenceCount"] > 0 and starts["exactMatches"] * 20 >= starts["referenceCount"] * 19
    identity = symbols["population"] > 0 and symbols["exact"] == symbols["population"]
    acceptance = {"functionStarts": {"minimumPercent": 95, "precisionAccepted": precision, "recallAccepted": recall,
        "accepted": precision and recall}, "survivingSymbolIdentity": {"requiredPercent": 100, "accepted": identity}}
    _require(_canonical(accuracy["acceptance"]) == _canonical(acceptance) and
             accuracy["benchmarkAccepted"] is (precision and recall and identity),
             "threshold outcome credits non-exact or missing identities")
    return {"functionStarts": {**starts, **acceptance["functionStarts"]},
            "survivingSymbolIdentity": {"numerator": symbols["exact"], "denominator": symbols["population"], **acceptance["survivingSymbolIdentity"]}}


def _false(document: dict, *fields: str) -> None:
    _require(all(document[field] is False for field in fields), "retained evidence widens its authority scope")


def _provider(document: dict, expected: str) -> None:
    _require(document["provider"] == expected, "unexpected retained provider")


def _self_digest(document: dict, field: str) -> None:
    _require(document[field] == _sha(_canonical({k: v for k, v in document.items() if k != field})),
             f"retained {field} differs from its canonical content")


def _verify_target(binding: dict, observation: dict, oracle: dict, assessment: dict) -> None:
    target = binding["targetDescriptor"]
    _require(binding["targetDescriptorSha256"] == _sha(_canonical(target)), "target descriptor digest differs")
    artifact = oracle["artifacts"]["stripped"]
    _require(target["imageBase"] == observation["selectedModelImageBase"] == artifact["elfImageBase"] and
             target["elfType"] == artifact["elfType"], "target descriptor substitutes the selected image base/type")
    ranges = [{"start": row["start"], "endExclusive": row["endExclusive"]} for row in artifact["executableRvaRanges"]]
    _require(observation["executableRvaRanges"] == ranges, "selected executable ranges differ from the raw oracle")
    range_document = {"schemaVersion": 1, "imageBase": target["imageBase"],
                      "ranges": [{"startRva": row["start"], "endExclusiveRva": row["endExclusive"]} for row in ranges]}
    _require(target["executableRangesSha256"] == _sha(_canonical(range_document)), "target executable range digest differs")
    _require(target["ghidraLanguage"] == assessment["language"] == "x86:LE:64:default" and
             target["ghidraCompilerSpec"] == assessment["compilerSpec"] == "gcc" and
             target["id"] == "sysv-amd64-elf-v1" and target["architecture"] == "x86_64" and
             target["abi"] == "sysv-amd64" and target["machine"] == 62 and target["pointerBits"] == 64 and
             target["elfClass"] == "ELF64" and target["dataEncoding"] == "little-endian",
             "target descriptor differs from the retained loader/benchmark target")


def _verify_export_inputs(binding: dict, assessment: dict, intent: dict) -> None:
    _false(assessment, "complete", "releaseEligible")
    artifacts = {}
    for artifact in _rows(intent["artifacts"], 256):
        _require(artifact["role"] not in artifacts, "intent repeats an input artifact role")
        artifacts[artifact["role"]] = artifact
    for bound_name, field, role in (("inputBinary", "input", "engine-binary"),
                                    ("exporter", "exporter", "exporter-source"),
                                    ("ghidraArchive", "analysisTool", "ghidra-archive")):
        bound, artifact = binding[bound_name], artifacts[role]
        _require(type(assessment[field + "Bytes"]) is int and
                 assessment[field + "Bytes"] == bound["bytes"] == artifact["bytes"] and
                 assessment[field + "Sha256"] == bound["sha256"] == artifact["sha256"],
                 "assessment input/exporter/runtime differs from its bound intent artifact")
    _require(assessment["recoveryMode"] == binding["exporter"]["recoveryMode"] == "full",
             "export assessment is not a full model capture")


def _links(documents: dict[str, dict], payloads: dict[str, bytes], oracle_bytes: bytes, oracle: dict) -> None:
    d = documents
    hashes = {role: _sha(payload) for role, payload in payloads.items()}
    result, score, accuracy = d["result"], d["boundary-score"], d["accuracy"]
    observation, binding, intent = d["boundary-observation"], d["full-export-binding"], d["intent"]
    model, request, output = d["model"], d["replay-request"], d["replay-output"]
    qualification, measured = d["qualification"], accuracy["score"]
    _require(qualification["engine"] == "driver", "qualification selects a different engine")
    for role, provider in {
        "result": "gcc-bundled-cli-full-export-result-v3",
        "boundary-score": "structural-selected-boundary-production-score-v1",
        "accuracy": "gcc-driver-production-function-accuracy-v1",
        "boundary-observation": "selected-twin-boundary-observation-v1",
        "full-export-binding": "gcc-compiler-engine-structural-full-export-binding-v2",
        "replay-request": "structural-boundary-replay-request-v1",
        "replay-output": "structural-boundary-replay-output-v1",
        "replay-capture": "descriptor-structural-boundary-replay-capture-v1",
        "start-authorized": "structural-replay-start-authorized-v1",
        "invocation": "gcc-bundled-cli-invocation-v1",
        "qualification": "gcc-driver-live-full-export-capture-v1",
        "launcher-invocation": "installed-gcc-cli-test-invocation-v1",
        "launcher-result": "installed-gcc-cli-test-result-v2",
    }.items():
        _provider(d[role], provider)
    _provider(measured, "structural-selected-function-accuracy-score-v1")
    _require(score["admittedDomains"] == DOMAINS and score["unavailableDomains"] == UNAVAILABLE,
             "selected structural domain population differs")
    _require(score["productionVerified"] is True and score["scored"] is True and
             measured["productionVerified"] is True and measured["scored"] is True,
             "retained selected score does not describe the admitted live result")
    for document in (score, measured, accuracy):
        _false(document, "complete", "releaseEligible")
    for role in ("result", "qualification", "boundary-observation"):
        _false(d[role], "complete", "scored", "releaseEligible")
    _false(qualification, "benchmarkAccepted")
    _false(output, "productionVerified", "scored", "complete", "releaseEligible")
    _require(output["authority"] == "untrusted-worker-computation", "worker output widens its authority")
    _false(d["replay-capture"], "complete", "releaseEligible")
    _require(accuracy["scope"] == measured["scope"] == "selected-function-starts-and-surviving-symbol-identities" and
             score["scope"] == "model-provenance-and-selected-function-boundaries", "selected scope differs")
    _require(score["profileId"] == measured["profileId"] == binding["profileId"] == "gcc-driver-16.2.0",
             "selected benchmark profile differs")
    _require(score["boundaryObservation"] == observation and score["fullExportBinding"] == binding,
             "selected score embeds a different captured observation or binding")
    for document in (result, score, measured, qualification, observation):
        _require(document["programModelSha256"] == hashes["model"] and
                 document["programModelBytes"] == len(payloads["model"]), "paired model commitment differs")
    _require(binding["programModel"] == {"bytes": len(payloads["model"]), "sha256": hashes["model"],
                                        "functionCount": len(model["functions"])}, "full export model inventory differs")
    for document in (score, measured, observation, request, output):
        _require(document["inputSha256"] == model["inputSha256"] and
                 document["functionOracleSha256"] == _sha(oracle_bytes), "selected input/oracle commitment differs")
    _require(binding["inputBinary"]["sha256"] == model["inputSha256"], "full export binds a different input")
    for document in (score, measured, qualification):
        _require(document["boundaryObservationSha256"] == hashes["boundary-observation"], "boundary observation hash differs")
    for document in (score, measured, request, output, d["start-authorized"]):
        _require(document["fullExportBindingSha256"] == hashes["full-export-binding"], "full export binding hash differs")
    _require(result["structuralBindingSha256"] == hashes["full-export-binding"] and
             measured["boundaryScoreSha256"] == hashes["boundary-score"] and
             qualification["productionBoundaryScoreSha256"] == hashes["boundary-score"] and
             qualification["productionFunctionAccuracySha256"] == hashes["accuracy"], "selected report commitment differs")
    for field, role in (("boundaryScore", "boundary-score"), ("functionAccuracy", "accuracy")):
        pointer = _object(result[field], {"path", "bytes", "sha256", "scope"})
        _require(pointer["bytes"] == len(payloads[role]) and pointer["sha256"] == hashes[role] and
                 pointer["scope"] == d[role]["scope"], "result report pointer differs")
    for role, field in (("replay-request", "replayRequestSha256"), ("replay-output", "replayMetadataSha256"),
                        ("replay-capture", "replayCaptureSha256"), ("replay-execution", "replayExecutionSha256"),
                        ("replay-attachment", "replayAttachmentSha256")):
        _require(score[field] == hashes[role], "boundary replay receipt hash differs")
    for document in (request, output):
        _require(document["modelSha256"] == hashes["model"] and document["modelBytes"] == len(payloads["model"]) and
                 document["functionOracleBytes"] == len(oracle_bytes) and
                 document["imageBase"] == observation["selectedModelImageBase"] and
                 document["operationRequestSha256"] == hashes["intent"], "replay substituted its frozen inputs")
    for document in (output, d["replay-capture"]):
        _require(document["requestSha256"] == hashes["replay-request"] and
                 document["observationSha256"] == hashes["boundary-observation"] and
                 document["observationBytes"] == len(payloads["boundary-observation"]), "replay output commitment differs")
    _require(d["replay-capture"]["metadataSha256"] == hashes["replay-output"] and
             d["replay-capture"]["modelSha256"] == hashes["model"], "replay captured metadata differs")
    start = d["start-authorized"]
    _require(start["requestSha256"] == hashes["replay-request"] and
             start["operationRequestSha256"] == hashes["intent"] and
             start["attachmentSha256"] == hashes["replay-attachment"], "child start does not bind replay attachment")
    operation_id = _digest(intent["operationId"])
    _require(intent["engineId"] == "driver" and intent["runKind"] == "fresh-control" and
             intent["cliInvocation"] == d["invocation"] and d["invocation"]["engineId"] == "driver" and
             d["invocation"]["resumeMode"] == "fresh" and d["invocation"]["resumeAfterCheckpoint"] is None,
             "retained invocation differs from the fresh driver selection")
    for document in (result, qualification):
        _require(document["operationId"] == operation_id and document["requestSha256"] == hashes["intent"] and
                 document["functionCount"] == len(model["functions"]), "result operation/census differs")
    for role, field, provider in (("export-execution", "execution", "gcc-bundled-command-executed-v1"),
                                  ("export-attachment", "attachment", "gcc-bundled-command-attached-v1"),
                                  ("export-assessment", "assessment", "gcc-bundled-command-export-assessed-v1")):
        receipt = d[role]
        _provider(receipt, provider)
        _false(receipt, "complete", "releaseEligible")
        _require(receipt["operationId"] == operation_id and receipt["intentSha256"] == hashes["intent"],
                 "export receipt belongs to another operation")
        _self_digest(receipt, "recordSha256")
        _require(receipt[field + "Sha256"] == _sha(_canonical(receipt[field])), "export receipt payload hash differs")
    _require(result["executionReceiptSha256"] == hashes["export-execution"] and
             result["exportAssessmentReceiptSha256"] == hashes["export-assessment"] and
             d["export-assessment"]["previousSha256"] == hashes["export-execution"], "export receipt chain differs")
    for execution, attachment, attachment_hash in (
        (d["replay-execution"], d["replay-attachment"], hashes["replay-attachment"]),
        (d["export-execution"]["execution"], d["export-attachment"]["attachment"],
         _sha(_canonical(d["export-attachment"]["attachment"]))),
    ):
        _provider(execution, "kotlin-lease-contained-command-execution-v1")
        _provider(attachment, "kotlin-lease-contained-command-attachment-v1")
        _self_digest(execution, "executionSha256")
        _self_digest(attachment, "attachmentSha256")
        _require(execution["childExitCode"] == 0 and type(execution["childExitCode"]) is int and
                 all(execution[f] is True for f in ("unitAbsent", "cgroupAbsent", "processesAbsent")) and
                 execution["attachmentSha256"] == attachment_hash and
                 execution["requestSha256"] == attachment["requestSha256"], "contained execution lacks matching successful absence evidence")
        _false(execution, "releaseEligible")
        _false(attachment, "releaseEligible")
    _require(d["replay-attachment"]["nonce"] == hashes["replay-request"], "replay attachment nonce differs")
    assessment = d["export-assessment"]["assessment"]
    _self_digest(assessment, "assessmentSha256")
    _verify_target(binding, observation, oracle, assessment)
    _verify_export_inputs(binding, assessment, intent)
    _require(assessment["programModelSha256"] == hashes["model"] and
             assessment["programModelBytes"] == len(payloads["model"]) and
             assessment["functionCount"] == len(model["functions"]) and
             assessment["inputSha256"] == model["inputSha256"], "export assessment substitutes model/input")
    for document in (result, qualification, binding, assessment):
        _require(document["outputTreeSha256"] == d["tree-manifest"]["outputTreeSha256"], "output tree binding differs")
    _require(result["outputTreeManifestSha256"] == hashes["tree-manifest"] and
             d["tree-manifest"]["outputTreeSha256"] == _sha(_canonical(d["tree-manifest"]["tree"])),
             "tree manifest digest differs")
    lineage = binding["receiptLineage"]
    _require(binding["receiptLineageSha256"] == _sha(_canonical(lineage)) and
             lineage["operationId"] == operation_id and lineage["engineId"] == "driver" and
             lineage["intentSha256"] == hashes["intent"] and
             lineage["executionReceiptSha256"] == hashes["export-execution"] and
             lineage["exportAssessmentReceiptSha256"] == hashes["export-assessment"] and
             lineage["executionPayloadSha256"] == _sha(_canonical(d["export-execution"]["execution"])) and
             lineage["exportAssessmentSha256"] == assessment["assessmentSha256"], "full export lineage differs")
    for role in ("launcher-summary", "launcher-invocation", "launcher-result"):
        _false(d[role], "productionVerified")
    _require(d["launcher-summary"]["invocationSha256"] == hashes["launcher-invocation"] and
             d["launcher-summary"]["resultSha256"] == hashes["launcher-result"] and
             d["launcher-result"]["invocationSha256"] == hashes["launcher-invocation"] and
             type(d["launcher-result"]["exitCode"]) is int and d["launcher-result"]["exitCode"] == 0 and
             d["launcher-invocation"]["argv"][1:] == d["invocation"]["argv"], "diagnostic launcher records do not join the invocation")


def verify(manifest_path: Path, repository_root: Path | None = None) -> dict:
    """Verify one explicitly selected retained checkpoint; never confer live authority."""
    try:
        repository = (repository_root or Path(__file__).resolve().parents[2]).absolute()
        manifest = Path(manifest_path).absolute()
        _require(".." not in repository.parts and ".." not in manifest.parts and manifest.is_relative_to(repository),
                 "manifest must be an explicit normalized repository path")
        seen: set[tuple[int, int]] = set()
        root = _json(_snapshot(manifest, MAX_MANIFEST_BYTES, seen))
        _object(root, {"schemaVersion", "provider", "source", "actions", "oracle", "payloads", "scope"})
        _require(type(root["schemaVersion"]) is int and root["schemaVersion"] == 1 and
                 root["provider"] == "gcc-driver-production-function-replay-evidence-v1", "unsupported evidence manifest")
        _object(root["scope"], {"productionDomains", "fullStructuralScored", "complete", "releaseEligible"})
        _require(root["scope"]["productionDomains"] == DOMAINS, "manifest selected domains differ")
        _false(root["scope"], "fullStructuralScored", "complete", "releaseEligible")
        actions = _object(root["actions"], {"runId", "jobId", "artifactId", "artifactName", "headSha", "runConclusion", "jobConclusion"})
        for key in ("runId", "jobId", "artifactId"):
            _integer(actions[key], (1 << 63) - 1, 1)
        _require(type(actions["artifactName"]) is str and 0 < len(actions["artifactName"]) <= 256 and
                 actions["runConclusion"] == actions["jobConclusion"] == "success" and
                 _digest(actions["headSha"], 40) == root["source"]["commit"], "Actions metadata differs from successful selected source")
        oracle_path, _, _ = _commitment(root["oracle"], MAX_DECODED_BYTES)
        oracle_bytes = _committed_snapshot(repository, root["oracle"], MAX_DECODED_BYTES, seen)
        _source(manifest.parent, root["source"], oracle_path, oracle_bytes, seen)
        rows = _rows(root["payloads"], len(ROLES))
        roles, paths = set(), set()
        decoded_total, compressed_total = len(oracle_bytes), 0
        for row in rows:
            _object(row, {"role", "path", "bytes", "sha256", "gzipBytes", "gzipSha256"})
            role, path = row["role"], _relative(row["path"])
            _require(role in ROLES and role not in roles and path not in paths and path.endswith(".gz"),
                     "missing, duplicate, unknown, or aliased payload role/path")
            roles.add(role); paths.add(path)
            decoded_total += _integer(row["bytes"], MAX_DECODED_BYTES, 1)
            compressed_total += _integer(row["gzipBytes"], MAX_COMPRESSED_BYTES, 1)
            _digest(row["sha256"]); _digest(row["gzipSha256"])
        _require(roles == ROLES and decoded_total <= MAX_TOTAL_DECODED_BYTES and compressed_total <= MAX_COMPRESSED_BYTES,
                 "payload role census or aggregate byte bound differs")
        payloads = {}
        for row in rows:
            compressed = _snapshot(manifest.parent / row["path"], row["gzipBytes"], seen)
            _require(len(compressed) == row["gzipBytes"] and _sha(compressed) == row["gzipSha256"], "compressed payload commitment differs")
            decoded = _gunzip(compressed, row["bytes"])
            _require(_sha(decoded) == row["sha256"], "decoded payload commitment differs")
            payloads[row["role"]] = decoded
        documents = {role: _json(payload) for role, payload in payloads.items() if role != "actions-log"}
        oracle = _json(oracle_bytes)
        _links(documents, payloads, oracle_bytes, oracle)
        measurements = rederive_measurements(documents["model"], oracle, documents["boundary-observation"])
        thresholds = verify_accuracy(documents["accuracy"], measurements)
        return {"provider": "gcc-production-function-replay-offline-verification-v1", "schemaVersion": 1,
                "offlineIntegrityVerified": True, "rederivedThresholds": thresholds,
                "sourceCommit": root["source"]["commit"], "sourceTreeSha1": root["source"]["treeSha1"],
                "payloadCount": len(payloads), "decodedBytes": decoded_total, "compressedBytes": compressed_total,
                "fullStructuralScored": False, "complete": False, "releaseEligible": False}
    except EvidenceError:
        raise
    except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError) as error:
        raise EvidenceError(f"malformed retained evidence: {type(error).__name__}") from error
