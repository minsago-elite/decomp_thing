"""Closed historical v1/current v2 byte-window admission and validation; no scoring authority."""
from __future__ import annotations

import json
import re
from typing import Any

_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})\Z")
_HEX = re.compile(r"[0-9a-f]+\Z")
COLLECTION_OMISSIONS = (
    "global_window_limit", "model_window_limit", "model_requested_byte_limit", "reference_work_limit",
)
_FIELDS = {
    "evidence": {"schemaVersion", "windows", "omissionReason"},
    "window": {"address", "requestedLength", "origin", "availability", "segments"},
    "origin": {"instructionAddress", "referenceAddress", "operandIndex", "widthBasis"},
    "segment": {"offset", "length", "availability", "hex", "reason"},
}
# Only containing fields that introduce/reset an evidence traversal are tracked here.
# Each boundary set has one possible key; ordinary generic keys retain the strict hook.
_BOUNDARY_FIELDS = {"root": {"globals"}, "global": {"byteEvidence"}}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("referenced byte evidence: " + message)


def admit_program_model_bytes(payload: bytes) -> None:
    """Inspect bounded lexical tokens before JSON allocates evidence trees/strings.

    The normal duplicate-key/JSON decoder remains responsible for full syntax.
    Schema field order cannot bypass admission, including historical documents.
    """
    stack: list[dict[str, Any]] = []
    depth = windows = requested = 0
    position = 3 if payload.startswith(b"\xef\xbb\xbf") else 0
    length = len(payload)
    while position < length and payload[position] in b" \t\r\n":
        position += 1
    _require(position < length and payload[position] == ord('{'), "program model root must be an object")
    while position < length:
        c = payload[position]
        if c in b" \t\r\n:":
            position += 1
            continue
        if c == ord(','):
            if stack and stack[-1]["object"]:
                stack[-1]["key"] = True
            position += 1
            continue
        if c in b"}]":
            if stack and stack.pop()["role"] == "evidence":
                depth -= 1
            position += 1
            continue
        parent = stack[-1] if stack else None
        key = bool(parent and parent["object"] and parent["key"])
        if parent and not parent["object"]:
            parent["entries"] += 1
            if parent["role"] == "windows":
                windows += 1
                _require(parent["entries"] <= 32 and windows <= 4096, "window bound exceeded")
            if parent["role"] == "collectionOmissions":
                _require(parent["entries"] <= 2, "collection omission bound exceeded")
                _require(c == ord('"'), "collection omissions must be scalar strings")
            if parent["role"] == "segments":
                _require(parent["entries"] <= 256, "segment bound exceeded")
        if parent and parent["role"] == "global" and parent["field"] == "byteEvidence" and not key:
            exact_null = payload[position:position + 4] == b"null" and (
                position + 4 == length or payload[position + 4] in b",} \t\r\n")
            _require(c == ord('{') or exact_null, "byteEvidence must be an object or exact null")
        if parent and parent["role"] == "evidence" and parent["field"] == "collectionOmissions" and not key:
            _require(c == ord('['), "collectionOmissions must be an array")
        if c in b"{[":
            role = "other"
            if parent is None:
                role = "root"
            elif parent["role"] == "root" and parent["field"] == "globals" and c == ord('['):
                role = "globals"
            elif parent["role"] == "globals" and c == ord('{'):
                role = "global"
            elif parent["role"] == "global" and parent["field"] == "byteEvidence" and c == ord('{'):
                role = "evidence"
            elif parent["role"] == "evidence" and parent["field"] == "collectionOmissions" and c == ord('['):
                role = "collectionOmissions"
            elif parent["role"] == "evidence" and parent["field"] == "windows" and c == ord('['):
                role = "windows"
            elif parent["role"] == "windows" and c == ord('{'):
                role = "window"
            elif parent["role"] == "window" and parent["field"] == "origin" and c == ord('{'):
                role = "origin"
            elif parent["role"] == "window" and parent["field"] == "segments" and c == ord('['):
                role = "segments"
            elif parent["role"] == "segments" and c == ord('{'):
                role = "segment"
            _require(not depth or role != "other", "unexpected container")
            if role == "evidence":
                depth += 1
            _require(len(stack) < 32, "document nesting bound exceeded")
            stack.append({"role": role, "object": c == ord('{'), "key": True, "field": None, "entries": 0,
                "seen": set() if role in _FIELDS or role in _BOUNDARY_FIELDS else None})
            position += 1
            continue
        if c == ord('"'):
            start = position
            position += 1
            decoded = 0
            while position < length and payload[position] != ord('"'):
                decoded += 1
                _require(not depth or decoded <= (32 if key or parent["role"] == "collectionOmissions" else 512), "string bound exceeded")
                if key:
                    _require(position - start < 24576, "field name bound exceeded")
                if payload[position] == ord('\\'):
                    position += 1
                    if position < length and payload[position] == ord('u'):
                        position += 4
                position += 1
            if key and position < length:
                field = json.loads(payload[start:position + 1])
                if depth:
                    fields = _FIELDS.get(parent["role"], set())
                    if parent["role"] == "evidence":
                        fields = fields | {"collectionOmissions"}
                    _require(field in fields, "unexpected field")
                if depth or field in _BOUNDARY_FIELDS.get(parent["role"], set()):
                    # Closed vocabularies bound these sets; reject before scanning values.
                    _require(field not in parent["seen"], "duplicate byte evidence field or containing boundary")
                    parent["seen"].add(field)
                parent["field"] = field
                parent["key"] = False
            position += 1
            continue
        start = position
        while position < length and payload[position] not in b",]} \t\r\n":
            position += 1
            _require(not depth or position - start <= 64, "number bound exceeded")
        if parent and parent["role"] == "window" and parent["field"] == "requestedLength":
            token = payload[start:position]
            if token != b"null":
                _require(bool(re.fullmatch(rb"(?:0|[1-9][0-9]*)", token)), "invalid requestedLength")
                width = int(token)
                _require(1 <= width <= 256, "requested byte bound exceeded")
                requested += width
                _require(requested <= 65536, "model requested byte bound exceeded")


def decode_program_model_bytes(payload: bytes) -> dict[str, Any]:
    """Strict archival decoder; admission precedes duplicate-aware JSON allocation."""
    _require(0 < len(payload) <= 512 * 1024 * 1024, "document byte bound exceeded")
    admit_program_model_bytes(payload)
    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=unique_fields)


def validate_evidence(value: Any, budget: list[int], *, schema_version: int = 1) -> None:
    """Validate the expected nested generation (historical1 by default) and charge payload budgets."""
    _require(type(schema_version) is int and schema_version in (1, 2), "invalid expected evidence generation")
    def obj(item: Any, role: str) -> dict[str, Any]:
        fields = _FIELDS[role] | ({"collectionOmissions"} if role == "evidence" and schema_version == 2 else set())
        _require(type(item) is dict and set(item) == fields, "invalid " + role + " fields")
        return item

    def integer(item: Any, minimum: int, maximum: int) -> int:
        _require(type(item) is int and minimum <= item <= maximum, "invalid integer")
        return item

    def address(item: Any) -> int:
        _require(type(item) is str and bool(_ADDRESS.fullmatch(item)), "invalid address")
        return int(item, 16)

    evidence = obj(value, "evidence")
    integer(evidence["schemaVersion"], schema_version, schema_version)
    omissions = evidence["collectionOmissions"] if schema_version == 2 else []
    _require(type(omissions) is list and len(omissions) <= 2 and
        all(type(reason) is str and reason in COLLECTION_OMISSIONS for reason in omissions), "invalid collection omissions")
    _require(len(set(omissions)) == len(omissions) and
        omissions == sorted(omissions, key=COLLECTION_OMISSIONS.index) and
        sum(reason != "global_window_limit" for reason in omissions) <= 1, "noncanonical collection omissions")
    windows = evidence["windows"]
    _require(type(windows) is list and (1 if schema_version == 1 else 0) <= len(windows) <= 32, "global window bound exceeded or empty")
    _require(bool(windows) or any(reason != "global_window_limit" for reason in omissions), "empty windows require aggregate collection omission")
    _require("global_window_limit" not in omissions or len(windows) == 32, "global window omission requires exactly 32 retained windows")
    budget[0] += len(windows)
    _require(budget[0] <= 4096, "model window bound exceeded")
    identities: set[tuple[Any, ...]] = set()
    unknown = False
    for raw in windows:
        window = obj(raw, "window")
        origin = obj(window["origin"], "origin")
        start = address(window["address"])
        instruction = address(origin["instructionAddress"])
        target = address(origin["referenceAddress"])
        _require(start == target, "window must start at reference target")
        operand = origin["operandIndex"]
        if operand is not None:
            integer(operand, 0, (1 << 31) - 1)
        basis = origin["widthBasis"]
        _require(type(basis) is str and basis in {"pcode_load", "pcode_store", "pcode_direct_read", "pcode_direct_write", "unknown_width"}, "invalid width basis")
        width = window["requestedLength"]
        segments = window["segments"]
        _require(type(segments) is list and len(segments) <= 256, "segment bound exceeded")
        if width is None:
            unknown = True
            _require(basis == "unknown_width" and window["availability"] == "unknown" and not segments, "invalid unknown-width window")
        else:
            integer(width, 1, 256)
            budget[1] += width
            _require(budget[1] <= 65536, "model requested byte bound exceeded")
            _require(basis != "unknown_width" and start <= (1 << 64) - width, "invalid width/address overflow")
            _require(bool(segments), "missing segments")
            offset = available = 0
            previous: tuple[Any, Any] | None = None
            for raw_segment in segments:
                segment = obj(raw_segment, "segment")
                integer(segment["offset"], offset, offset)
                count = integer(segment["length"], 1, width - offset)
                availability, reason, encoded = segment["availability"], segment["reason"], segment["hex"]
                if availability == "available":
                    _require(reason is None and type(encoded) is str and len(encoded) == count * 2 and bool(_HEX.fullmatch(encoded)), "invalid available segment")
                    available += count
                else:
                    _require(availability == "unavailable" and encoded is None and type(reason) is str and reason in {"unmapped", "unreadable", "uninitialized", "read_failed"}, "invalid unavailable segment")
                    _require(previous != ("unavailable", reason), "unavailable segments must coalesce")
                previous = (availability, reason)
                offset += count
            _require(offset == width, "invalid segment coverage")
            _require(window["availability"] == ("available" if available == width else "unavailable" if available == 0 else "partial"), "contradictory availability")
        identity = (start, instruction, target, operand, basis, width) if schema_version == 1 else (target, instruction, operand)
        _require(identity not in identities, "duplicate/conflicting window identity")
        identities.add(identity)
    _require(evidence["omissionReason"] == ("unknown_access_width" if unknown else None), "invalid omissionReason")
