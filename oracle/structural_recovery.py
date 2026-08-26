"""Program-neutral structural recovery scoring.

The scorer consumes already-normalized facts.  It never parses source-language
declarations, guesses identities from names, or contains a target-specific ABI
classifier.  Function identities and internal call endpoints come from a
selected function-boundary mapping.  Other entity identities come from a
separately reviewed mapping artifact.  ABI equivalence is evaluated only from
the projection vocabulary declared by the selected target descriptor.

Production recovered evidence needs an adapter which replays and authenticates
the exporter/loader invocation.  This module deliberately implements only the
digest-bound fixture entry point; a fixture report is never production verified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping, Sequence


MAX_JSON_INPUT_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 192 * 1024 * 1024
MAX_ENTITIES = 50_000
MAX_FACTS = 500_000
MAX_FACTS_PER_ENTITY = 20_000
MAX_EVIDENCE_PER_FACT = 32
MAX_MAPPINGS = 100_000
MAX_TOTAL_ENTITIES = 50_000
MAX_TOTAL_FACTS = 600_000
MAX_TOTAL_EVIDENCE = 2_000_000
MAX_REPORT_ENTRIES = 600_000
MAX_PROJECTED_REPORT_BYTES = 96 * 1024 * 1024
MAX_TEXT_CHARACTERS = 16_384
MAX_IDENTIFIER_CHARACTERS = 4_096
MAX_ABI_CLASSES = 256
MAX_CALLING_CONVENTIONS = 128
MAX_REGISTERS = 256
MAX_ADDRESS = (1 << 64) - 1
MAX_JSON_NUMBER_CHARACTERS = 128
BOUNDARY_PROJECTION_ADAPTER_ID = "function-recovery-score-elf"
BOUNDARY_PROJECTION_ADAPTER_VERSION = "1"
NORMALIZATION_PROFILE_ID = "structural-source-normalization"
NORMALIZATION_PROFILE_VERSION = "1"

# This canonical document is the scorer-v1 normalization contract.  Its digest
# is repeated in both inputs and the report; producers cannot select a private
# configuration while retaining the checked profile identity.
NORMALIZATION_PROFILE_CONFIGURATION: dict[str, Any] = {
    "schemaVersion": 1,
    "profile": {
        "id": NORMALIZATION_PROFILE_ID,
        "version": NORMALIZATION_PROFILE_VERSION,
    },
    "tokenPattern": "[A-Za-z0-9_][A-Za-z0-9._:/@+\\-]{0,4094}",
    "canonicalAddressPattern": "0x(?:0|[1-9a-f][0-9a-f]{0,15})",
    "dimensionSourceForms": {
        "function.prototype": ["prototype:<canonical-shape-token>"],
        "function.calling-convention": [
            "convention:<target-descriptor-id-or-alias>"
        ],
        "function.variadic": ["boolean"],
        "function.parameter-abi-class": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
        "function.return-abi-class": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
        "call.internal": ["function:<stable-entity-id>"],
        "call.external": ["external:<canonical-external-id>"],
        "call.indirect": ["signature:<canonical-shape-token>"],
        "global.reference": ["global:<stable-entity-id>"],
        "global.storage": [
            "static-rva:<canonical-address>",
            "tls-offset:<canonical-address>",
            "external-storage:<canonical-id>",
            "register:<canonical-id>",
        ],
        "global.linkage": [
            "internal",
            "external",
            "weak",
            "common",
            "unique",
            "none",
        ],
        "global.type": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
        "type.aggregate.kind": ["record", "overlay", "variant", "sequence"],
        "type.aggregate.size-bits": ["nonnegative-integer-64"],
        "type.aggregate.alignment-bits": ["nonnegative-integer-64"],
        "type.aggregate.member-offset-bits": ["nonnegative-integer-64"],
        "type.aggregate.member-type": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
        "type.enum.underlying-abi-class": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
        "type.enum.enumerator-value": ["signed-integer-magnitude-64"],
        "type.typedef.target": [
            "type-token:<canonical-token>",
            "type-entity:<stable-entity-id>",
        ],
    },
}
NORMALIZATION_PROFILE_CONFIGURATION_BYTES = json.dumps(
    NORMALIZATION_PROFILE_CONFIGURATION,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("ascii")
NORMALIZATION_PROFILE_CONFIGURATION_SHA256 = hashlib.sha256(
    NORMALIZATION_PROFILE_CONFIGURATION_BYTES
).hexdigest()

OUTCOMES = (
    "exact",
    "abi-equivalent",
    "recovered-unknown",
    "oracle-unobservable",
    "contradicted",
    "fabricated",
)

DIMENSIONS = (
    "function.prototype",
    "function.calling-convention",
    "function.variadic",
    "function.parameter-abi-class",
    "function.return-abi-class",
    "call.internal",
    "call.external",
    "call.indirect",
    "global.reference",
    "global.storage",
    "global.linkage",
    "global.type",
    "type.aggregate.kind",
    "type.aggregate.size-bits",
    "type.aggregate.alignment-bits",
    "type.aggregate.member-offset-bits",
    "type.aggregate.member-type",
    "type.enum.underlying-abi-class",
    "type.enum.enumerator-value",
    "type.typedef.target",
)

if tuple(NORMALIZATION_PROFILE_CONFIGURATION["dimensionSourceForms"]) != DIMENSIONS:
    raise RuntimeError("checked normalization profile does not cover the scorer dimensions")

IDENTITY_SELECTION_POLICY = (
    "function and internal-call endpoint identities come only from the selected "
    "function-boundary report; global and type identities come only from the "
    "separately reviewed identity map; facts align by canonical dimension and slot"
)
ABI_EQUIVALENCE_POLICY = (
    "exact requires identical source and ABI projections; ABI-equivalent requires "
    "different source projections and identical non-null projections validated by "
    "the selected target descriptor"
)
SOURCE_NORMALIZATION_POLICY = (
    "language-neutral tagged source projections interpreted only under the exact "
    "normalization-profile ID, version, and configuration digest; adapter-local "
    "declarations and display names are forbidden"
)


def _report_limits() -> dict[str, int]:
    return {
        "maxJsonInputBytes": MAX_JSON_INPUT_BYTES,
        "maxReportBytes": MAX_REPORT_BYTES,
        "maxTotalInputBytes": MAX_TOTAL_INPUT_BYTES,
        "maxEntities": MAX_ENTITIES,
        "maxFacts": MAX_FACTS,
        "maxFactsPerEntity": MAX_FACTS_PER_ENTITY,
        "maxEvidencePerFact": MAX_EVIDENCE_PER_FACT,
        "maxMappings": MAX_MAPPINGS,
        "maxTextCharacters": MAX_TEXT_CHARACTERS,
        "maxJsonNumberCharacters": MAX_JSON_NUMBER_CHARACTERS,
        "maxTotalEntities": MAX_TOTAL_ENTITIES,
        "maxTotalFacts": MAX_TOTAL_FACTS,
        "maxTotalEvidence": MAX_TOTAL_EVIDENCE,
        "maxReportEntries": MAX_REPORT_ENTRIES,
        "maxProjectedReportBytes": MAX_PROJECTED_REPORT_BYTES,
    }

_DIMENSION_ENTITY_KIND = {
    dimension: (
        "function"
        if dimension.startswith("function.")
        or dimension.startswith("call.")
        or dimension == "global.reference"
        else "global"
        if dimension.startswith("global.")
        else "type"
    )
    for dimension in DIMENSIONS
}

_STRING_SOURCE_DIMENSIONS = frozenset(
    {
        "function.prototype",
        "function.calling-convention",
        "function.parameter-abi-class",
        "function.return-abi-class",
        "call.internal",
        "call.external",
        "call.indirect",
        "global.reference",
        "global.storage",
        "global.linkage",
        "global.type",
        "type.aggregate.kind",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    }
)
_INTEGER_SOURCE_DIMENSIONS = frozenset(
    {
        "type.aggregate.size-bits",
        "type.aggregate.alignment-bits",
        "type.aggregate.member-offset-bits",
        "type.enum.enumerator-value",
    }
)

_ABI_EQUIVALENT_DIMENSIONS = frozenset(
    {
        "function.calling-convention",
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    }
)

_ADDRESS_PATTERN = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]{0,15})$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PARAMETER_SLOT = re.compile(r"^parameter:(0|[1-9][0-9]{0,8})$")
_CALL_SLOT = re.compile(
    r"^call:(0x(?:0|[1-9a-f][0-9a-f]{0,15})):(internal|external|indirect)$"
)
_GLOBAL_REFERENCE_SLOT = re.compile(
    r"^global-ref:(0x(?:0|[1-9a-f][0-9a-f]{0,15}))$"
)
_MEMBER_SLOT = re.compile(
    r"^member:(0|[1-9][0-9]{0,8}):(offset|type)$"
)
_ENUMERATOR_SLOT = re.compile(r"^enumerator:[A-Za-z_][A-Za-z0-9_]{0,1023}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,4095}$")
_NORMALIZED_TOKEN = r"[A-Za-z0-9_][A-Za-z0-9._:/@+\-]{0,4094}"
_PROTOTYPE_SOURCE = re.compile(rf"^prototype:{_NORMALIZED_TOKEN}$")
_CONVENTION_SOURCE = re.compile(rf"^convention:{_NORMALIZED_TOKEN}$")
_TYPE_SOURCE = re.compile(rf"^(?:type-token|type-entity):{_NORMALIZED_TOKEN}$")
_FUNCTION_SOURCE = re.compile(rf"^function:{_NORMALIZED_TOKEN}$")
_EXTERNAL_SOURCE = re.compile(rf"^external:{_NORMALIZED_TOKEN}$")
_INDIRECT_SOURCE = re.compile(rf"^signature:{_NORMALIZED_TOKEN}$")
_GLOBAL_SOURCE = re.compile(rf"^global:{_NORMALIZED_TOKEN}$")
_STORAGE_SOURCE = re.compile(
    rf"^(?:static-rva|tls-offset):0x(?:0|[1-9a-f][0-9a-f]{{0,15}})$"
    rf"|^(?:external-storage|register):{_NORMALIZED_TOKEN}$"
)
_LINKAGE_SOURCES = frozenset({"internal", "external", "weak", "common", "unique", "none"})
_AGGREGATE_KIND_SOURCES = frozenset({"record", "overlay", "variant", "sequence"})


class StructuralScoringError(ValueError):
    """Raised when an input violates the closed scoring contract."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    sha256: str


@dataclass(frozen=True)
class TargetAbiDescriptor:
    snapshot: Snapshot
    document: Mapping[str, Any]
    identifier: str
    address_bits: int
    maximum_address: int
    object_format: str
    calling_conventions: frozenset[str]
    convention_aliases: Mapping[str, str]
    abi_classes: frozenset[str]


@dataclass(frozen=True)
class StructuralOracle:
    snapshot: Snapshot
    document: Mapping[str, Any]


@dataclass(frozen=True)
class BoundaryMapping:
    snapshot: Snapshot
    document: Mapping[str, Any]
    twin: str
    projection_adapter_id: str
    projection_adapter_version: str
    object_format: str
    input_sha256: str
    model_image_base: int
    executable_rva_ranges: tuple[tuple[int, int], ...]
    oracle_to_recovered: Mapping[str, str]
    recovered_to_oracle: Mapping[str, str]
    oracle_function_ids: frozenset[str]
    recovered_function_ids: frozenset[str]
    excluded_oracle_ids: frozenset[str]
    ignored_recovered_ids: frozenset[str]


@dataclass(frozen=True)
class IdentityMap:
    snapshot: Snapshot
    document: Mapping[str, Any]
    recovered_to_oracle: Mapping[tuple[str, str], str]
    oracle_to_recovered: Mapping[tuple[str, str], str]


@dataclass(frozen=True)
class RecoveredStructure:
    snapshot: Snapshot
    document: Mapping[str, Any]
    payload_sha256: str


def _reject_constant(value: str) -> None:
    raise StructuralScoringError(f"non-finite JSON number is forbidden: {value}")


def _bounded_integer(value: str) -> int:
    if len(value) > 21 or len(value.lstrip("-")) > 20:
        raise StructuralScoringError("JSON integer token exceeds the lexical bound")
    try:
        parsed = int(value)
    except ValueError as error:
        raise StructuralScoringError("invalid bounded JSON integer") from error
    if abs(parsed) > MAX_ADDRESS:
        raise StructuralScoringError("JSON integer magnitude exceeds the 64-bit bound")
    return parsed


def _reject_float(value: str) -> None:
    raise StructuralScoringError(f"JSON floating-point values are forbidden: {value}")


def _bounded_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARACTERS:
        raise StructuralScoringError("JSON floating-point token exceeds the lexical bound")
    try:
        parsed = float(value)
    except ValueError as error:
        raise StructuralScoringError("invalid bounded JSON floating-point value") from error
    if not math.isfinite(parsed) or abs(parsed) > MAX_ADDRESS:
        raise StructuralScoringError("JSON floating-point magnitude exceeds the finite bound")
    return parsed


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StructuralScoringError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _snapshot_regular_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int = MAX_JSON_INPUT_BYTES,
) -> Snapshot:
    try:
        before = path.lstat()
    except OSError as error:
        raise StructuralScoringError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(before.st_mode):
        raise StructuralScoringError(f"{label} must be a regular file, not a symlink")
    if before.st_size > maximum_bytes:
        raise StructuralScoringError(
            f"{label} exceeds the {maximum_bytes}-byte input limit"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StructuralScoringError(f"cannot open {label}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise StructuralScoringError(f"{label} must be a regular file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise StructuralScoringError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as error:
        raise StructuralScoringError(f"cannot read {label}: {error}") from error
    finally:
        os.close(descriptor)
    if len(data) > maximum_bytes:
        raise StructuralScoringError(
            f"{label} exceeds the {maximum_bytes}-byte input limit"
        )
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or len(data) != opened.st_size
    ):
        raise StructuralScoringError(f"{label} changed while it was read")
    return Snapshot(path=path, data=data, sha256=hashlib.sha256(data).hexdigest())


def _decode_json(
    snapshot: Snapshot,
    label: str,
    *,
    allow_floats: bool = False,
) -> Mapping[str, Any]:
    try:
        text = snapshot.data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StructuralScoringError(f"{label} must be UTF-8 JSON") from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_bounded_integer,
            parse_float=_bounded_float if allow_floats else _reject_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, MemoryError) as error:
        raise StructuralScoringError(f"invalid bounded {label} JSON: {error}") from error
    if not isinstance(document, dict):
        raise StructuralScoringError(f"{label} root must be an object")
    return document


def _object(value: Any, path: str, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StructuralScoringError(f"{path} must be an object")
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise StructuralScoringError(
            f"{path} has a closed shape; missing={missing}, extra={extra}"
        )
    return value


def _array(value: Any, path: str, maximum: int, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list):
        raise StructuralScoringError(f"{path} must be an array")
    if not minimum <= len(value) <= maximum:
        raise StructuralScoringError(
            f"{path} must contain between {minimum} and {maximum} items"
        )
    return value


def _string(
    value: Any,
    path: str,
    *,
    maximum: int = MAX_IDENTIFIER_CHARACTERS,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise StructuralScoringError(f"{path} must be a string")
    if (not allow_empty and not value) or len(value) > maximum:
        raise StructuralScoringError(f"{path} has an invalid length")
    return value


def _identifier(value: Any, path: str) -> str:
    text = _string(value, path, maximum=MAX_IDENTIFIER_CHARACTERS)
    if _IDENTIFIER_PATTERN.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must be a canonical ASCII identifier")
    return text


def _integer(value: Any, path: str, *, minimum: int = 0, maximum: int = MAX_ADDRESS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StructuralScoringError(f"{path} must be an integer")
    if value < minimum or value > maximum:
        raise StructuralScoringError(f"{path} is outside the allowed range")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise StructuralScoringError(f"{path} must be a boolean")
    return value


def _nullable_string(
    value: Any,
    path: str,
    *,
    maximum: int = MAX_IDENTIFIER_CHARACTERS,
) -> str | None:
    if value is None:
        return None
    return _string(value, path, maximum=maximum)


def _sha256(value: Any, path: str) -> str:
    text = _string(value, path, maximum=64)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must be a lowercase SHA-256 digest")
    return text


def _address(value: Any, path: str, *, maximum: int = MAX_ADDRESS) -> int:
    text = _string(value, path, maximum=18)
    if _ADDRESS_PATTERN.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must be a canonical hexadecimal address")
    address = int(text, 16)
    if address > maximum:
        raise StructuralScoringError(f"{path} exceeds the selected target address width")
    return address


def _schema_version(root: Mapping[str, Any], label: str) -> None:
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise StructuralScoringError(f"{label}.schemaVersion must be the integer 1")


def _canonical_payload(document: Mapping[str, Any]) -> bytes:
    payload = {key: value for key, value in document.items() if key != "attestation"}
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, MemoryError) as error:
        raise StructuralScoringError(f"cannot canonicalize attestation payload: {error}") from error
    if len(encoded) > MAX_JSON_INPUT_BYTES:
        raise StructuralScoringError("canonical attestation payload exceeds the input limit")
    return encoded


def _validate_tool_identity(value: Any, path: str) -> None:
    item = _object(
        value,
        path,
        {"id", "version", "executableSha256", "configurationSha256"},
    )
    _identifier(item["id"], f"{path}.id")
    _identifier(item["version"], f"{path}.version")
    _sha256(item["executableSha256"], f"{path}.executableSha256")
    _sha256(item["configurationSha256"], f"{path}.configurationSha256")


def _validate_normalization_profile(value: Any, path: str) -> dict[str, str]:
    """Validate the complete contract that gives normalized tokens meaning."""

    item = _object(value, path, {"id", "version", "configurationSha256"})
    normalized = {
        "id": _identifier(item["id"], f"{path}.id"),
        "version": _identifier(item["version"], f"{path}.version"),
        "configurationSha256": _sha256(
            item["configurationSha256"],
            f"{path}.configurationSha256",
        ),
    }
    expected = {
        "id": NORMALIZATION_PROFILE_ID,
        "version": NORMALIZATION_PROFILE_VERSION,
        "configurationSha256": NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
    }
    if normalized != expected:
        raise StructuralScoringError(
            f"{path} does not select the checked scorer-v1 normalization profile"
        )
    return normalized


def load_target_abi_descriptor(path: Path) -> TargetAbiDescriptor:
    snapshot = _snapshot_regular_file(path, "target ABI descriptor")
    root = _object(
        _decode_json(snapshot, "target ABI descriptor"),
        "target ABI descriptor",
        {
            "schemaVersion",
            "id",
            "target",
            "callingConventions",
            "abiClasses",
            "scalarWidthsBits",
        },
    )
    _schema_version(root, "target ABI descriptor")
    identifier = _identifier(root["id"], "target ABI descriptor.id")
    target = _object(
        root["target"],
        "target ABI descriptor.target",
        {"architecture", "endianness", "addressBits", "objectFormat"},
    )
    _identifier(target["architecture"], "target ABI descriptor.target.architecture")
    endianness = _string(target["endianness"], "target ABI descriptor.target.endianness")
    if endianness not in {"little", "big"}:
        raise StructuralScoringError("target ABI descriptor endianness is invalid")
    address_bits = _integer(
        target["addressBits"],
        "target ABI descriptor.target.addressBits",
        minimum=8,
        maximum=64,
    )
    object_format = _identifier(
        target["objectFormat"],
        "target ABI descriptor.target.objectFormat",
    )

    classes: set[str] = set()
    for index, value in enumerate(
        _array(root["abiClasses"], "target ABI descriptor.abiClasses", MAX_ABI_CLASSES, minimum=1)
    ):
        name = _string(value, f"target ABI descriptor.abiClasses[{index}]", maximum=128)
        if name in classes:
            raise StructuralScoringError(f"duplicate ABI class: {name}")
        classes.add(name)

    conventions: set[str] = set()
    aliases: dict[str, str] = {}
    for index, value in enumerate(
        _array(
            root["callingConventions"],
            "target ABI descriptor.callingConventions",
            MAX_CALLING_CONVENTIONS,
            minimum=1,
        )
    ):
        item_path = f"target ABI descriptor.callingConventions[{index}]"
        item = _object(
            value,
            item_path,
            {
                "id",
                "aliases",
                "integerArgumentRegisters",
                "floatingArgumentRegisters",
                "integerReturnRegisters",
                "floatingReturnRegisters",
                "stackAlignmentBytes",
                "redZoneBytes",
                "variadicRegisterCountRegister",
            },
        )
        convention_id = _string(item["id"], f"{item_path}.id", maximum=128)
        if convention_id in conventions or convention_id in aliases:
            raise StructuralScoringError(f"duplicate calling convention: {convention_id}")
        conventions.add(convention_id)
        aliases[convention_id] = convention_id
        for alias_index, raw_alias in enumerate(
            _array(item["aliases"], f"{item_path}.aliases", 128)
        ):
            alias = _string(raw_alias, f"{item_path}.aliases[{alias_index}]", maximum=128)
            if alias in aliases or alias in conventions:
                raise StructuralScoringError(f"duplicate calling-convention alias: {alias}")
            aliases[alias] = convention_id
        for register_key in (
            "integerArgumentRegisters",
            "floatingArgumentRegisters",
            "integerReturnRegisters",
            "floatingReturnRegisters",
        ):
            seen_registers: set[str] = set()
            for register_index, raw_register in enumerate(
                _array(item[register_key], f"{item_path}.{register_key}", MAX_REGISTERS)
            ):
                register = _string(
                    raw_register,
                    f"{item_path}.{register_key}[{register_index}]",
                    maximum=128,
                )
                if register in seen_registers:
                    raise StructuralScoringError(
                        f"duplicate register in {item_path}.{register_key}: {register}"
                    )
                seen_registers.add(register)
        _integer(item["stackAlignmentBytes"], f"{item_path}.stackAlignmentBytes", minimum=1, maximum=4096)
        _integer(item["redZoneBytes"], f"{item_path}.redZoneBytes", maximum=65536)
        _nullable_string(
            item["variadicRegisterCountRegister"],
            f"{item_path}.variadicRegisterCountRegister",
            maximum=128,
        )

    widths = _object(
        root["scalarWidthsBits"],
        "target ABI descriptor.scalarWidthsBits",
        {"pointer", "size", "ptrdiff", "boolean"},
    )
    for key, value in widths.items():
        _integer(value, f"target ABI descriptor.scalarWidthsBits.{key}", minimum=1, maximum=1024)

    return TargetAbiDescriptor(
        snapshot=snapshot,
        document=root,
        identifier=identifier,
        address_bits=address_bits,
        maximum_address=(1 << address_bits) - 1,
        object_format=object_format,
        calling_conventions=frozenset(conventions),
        convention_aliases=dict(aliases),
        abi_classes=frozenset(classes),
    )


def _validate_evidence(value: Any, path: str) -> None:
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(
        _array(value, path, MAX_EVIDENCE_PER_FACT, minimum=1)
    ):
        item_path = f"{path}[{index}]"
        item = _object(raw, item_path, {"kind", "locator"})
        kind = _string(item["kind"], f"{item_path}.kind", maximum=128)
        locator = _string(item["locator"], f"{item_path}.locator", maximum=MAX_TEXT_CHARACTERS)
        key = (kind, locator)
        if key in seen:
            raise StructuralScoringError(f"duplicate evidence in {path}")
        seen.add(key)


def _validate_abi_projection(
    value: Any,
    path: str,
    target: TargetAbiDescriptor,
) -> None:
    if value is None:
        return
    item = _object(
        value,
        path,
        {"callingConvention", "classes", "sizeBits", "alignmentBits", "variadic"},
    )
    convention = _nullable_string(item["callingConvention"], f"{path}.callingConvention")
    if convention is not None and convention not in target.calling_conventions:
        raise StructuralScoringError(
            f"{path}.callingConvention is absent from the target descriptor"
        )
    classes = _array(item["classes"], f"{path}.classes", MAX_ABI_CLASSES)
    for index, raw_class in enumerate(classes):
        abi_class = _string(raw_class, f"{path}.classes[{index}]", maximum=128)
        if abi_class not in target.abi_classes:
            raise StructuralScoringError(
                f"{path}.classes[{index}] is absent from the target descriptor"
            )
    for key in ("sizeBits", "alignmentBits"):
        if item[key] is not None:
            _integer(item[key], f"{path}.{key}", minimum=1, maximum=MAX_ADDRESS)
    if item["variadic"] is not None:
        _boolean(item["variadic"], f"{path}.variadic")
    if (
        convention is None
        and not classes
        and item["sizeBits"] is None
        and item["alignmentBits"] is None
        and item["variadic"] is None
    ):
        raise StructuralScoringError(f"{path} must carry at least one ABI datum")


def _validate_value(
    value: Any,
    path: str,
    dimension: str,
    target: TargetAbiDescriptor,
) -> None:
    item = _object(value, path, {"source", "abi"})
    source = item["source"]
    if dimension == "function.variadic":
        _boolean(source, f"{path}.source")
    elif dimension in _INTEGER_SOURCE_DIMENSIONS:
        if isinstance(source, bool) or not isinstance(source, int):
            raise StructuralScoringError(f"{path}.source must be an integer")
        if dimension == "type.enum.enumerator-value":
            if abs(source) > MAX_ADDRESS:
                raise StructuralScoringError(
                    f"{path}.source must have a signed 64-bit-bounded magnitude"
                )
        elif not 0 <= source <= MAX_ADDRESS:
            raise StructuralScoringError(f"{path}.source must be a nonnegative 64-bit value")
    elif dimension in _STRING_SOURCE_DIMENSIONS:
        source_text = _string(source, f"{path}.source", maximum=MAX_TEXT_CHARACTERS)
        _validate_normalized_source(source_text, f"{path}.source", dimension, target)
    else:
        raise StructuralScoringError(f"unsupported structural dimension: {dimension}")
    _validate_abi_projection(item["abi"], f"{path}.abi", target)
    abi = item["abi"]
    if dimension == "function.calling-convention":
        if abi is None or abi["callingConvention"] is None:
            raise StructuralScoringError(f"{path}.abi must identify a calling convention")
        source_convention = target.convention_aliases.get(
            str(source).removeprefix("convention:")
        )
        if source_convention is None:
            raise StructuralScoringError(
                f"{path}.source is absent from the target descriptor's convention vocabulary"
            )
        if source_convention != abi["callingConvention"]:
            raise StructuralScoringError(
                f"{path}.source and ABI calling convention are inconsistent"
            )
        _require_projection_shape(
            abi,
            path,
            allow_calling_convention=True,
        )
    elif dimension == "function.variadic":
        if abi is None or abi["variadic"] is None:
            raise StructuralScoringError(f"{path}.abi must carry variadic state")
        if source != abi["variadic"]:
            raise StructuralScoringError(f"{path}.source and ABI variadic state are inconsistent")
        _require_projection_shape(abi, path, allow_variadic=True)
    elif dimension in {
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    }:
        if abi is None or not abi["classes"]:
            raise StructuralScoringError(f"{path}.abi must carry at least one ABI class")
        _require_projection_shape(
            abi,
            path,
            allow_classes=True,
            allow_size=True,
            allow_alignment=True,
        )
    elif dimension == "type.aggregate.size-bits":
        if abi is None or abi["sizeBits"] != source:
            raise StructuralScoringError(f"{path}.abi.sizeBits must equal the source size")
        _require_projection_shape(abi, path, allow_size=True)
    elif dimension == "type.aggregate.alignment-bits":
        if abi is None or abi["alignmentBits"] != source:
            raise StructuralScoringError(f"{path}.abi.alignmentBits must equal the source alignment")
        _require_projection_shape(abi, path, allow_alignment=True)
    elif abi is not None:
        raise StructuralScoringError(
            f"{path}.abi is forbidden for a dimension without an explicit ABI equivalence relation"
        )


def _validate_normalized_source(
    source: str,
    path: str,
    dimension: str,
    target: TargetAbiDescriptor,
) -> None:
    """Validate the closed, language-neutral source projection vocabulary."""

    if dimension == "function.prototype":
        valid = _PROTOTYPE_SOURCE.fullmatch(source) is not None
    elif dimension == "function.calling-convention":
        valid = (
            _CONVENTION_SOURCE.fullmatch(source) is not None
            and source.removeprefix("convention:") in target.convention_aliases
        )
    elif dimension in {
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    }:
        valid = _TYPE_SOURCE.fullmatch(source) is not None
    elif dimension == "call.internal":
        valid = _FUNCTION_SOURCE.fullmatch(source) is not None
    elif dimension == "call.external":
        valid = _EXTERNAL_SOURCE.fullmatch(source) is not None
    elif dimension == "call.indirect":
        valid = _INDIRECT_SOURCE.fullmatch(source) is not None
    elif dimension == "global.reference":
        valid = _GLOBAL_SOURCE.fullmatch(source) is not None
    elif dimension == "global.storage":
        valid = _STORAGE_SOURCE.fullmatch(source) is not None
        if valid and source.startswith(("static-rva:", "tls-offset:")):
            _address(
                source.split(":", 1)[1],
                path,
                maximum=target.maximum_address,
            )
    elif dimension == "global.linkage":
        valid = source in _LINKAGE_SOURCES
    elif dimension == "type.aggregate.kind":
        valid = source in _AGGREGATE_KIND_SOURCES
    else:
        raise StructuralScoringError(f"{path} has no string normalization rule")
    if not valid:
        raise StructuralScoringError(
            f"{path} violates the closed normalization for {dimension}"
        )


def _require_projection_shape(
    abi: Mapping[str, Any],
    path: str,
    *,
    allow_calling_convention: bool = False,
    allow_classes: bool = False,
    allow_size: bool = False,
    allow_alignment: bool = False,
    allow_variadic: bool = False,
) -> None:
    forbidden = {
        "callingConvention": not allow_calling_convention and abi["callingConvention"] is not None,
        "classes": not allow_classes and bool(abi["classes"]),
        "sizeBits": not allow_size and abi["sizeBits"] is not None,
        "alignmentBits": not allow_alignment and abi["alignmentBits"] is not None,
        "variadic": not allow_variadic and abi["variadic"] is not None,
    }
    unexpected = sorted(key for key, present in forbidden.items() if present)
    if unexpected:
        raise StructuralScoringError(
            f"{path}.abi carries fields irrelevant to this dimension: {unexpected}"
        )


def _validate_slot(
    dimension: str,
    slot: Any,
    path: str,
    target: TargetAbiDescriptor,
) -> str:
    text = _string(slot, path, maximum=MAX_IDENTIFIER_CHARACTERS)
    fixed = {
        "function.prototype": "prototype",
        "function.calling-convention": "calling-convention",
        "function.variadic": "variadic",
        "function.return-abi-class": "return",
        "global.storage": "storage",
        "global.linkage": "linkage",
        "global.type": "type",
        "type.aggregate.kind": "aggregate-kind",
        "type.aggregate.size-bits": "aggregate-size",
        "type.aggregate.alignment-bits": "aggregate-alignment",
        "type.enum.underlying-abi-class": "enum-underlying",
        "type.typedef.target": "typedef-target",
    }
    if dimension in fixed and text != fixed[dimension]:
        raise StructuralScoringError(f"{path} must be {fixed[dimension]!r}")
    if dimension == "function.parameter-abi-class" and _PARAMETER_SLOT.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must identify a canonical parameter index")
    if dimension.startswith("call."):
        match = _CALL_SLOT.fullmatch(text)
        if match is None or f"call.{match.group(2)}" != dimension:
            raise StructuralScoringError(f"{path} must identify a canonical call site and endpoint kind")
        if int(match.group(1), 16) > target.maximum_address:
            raise StructuralScoringError(f"{path} exceeds the selected target address width")
    if dimension == "global.reference" and _GLOBAL_REFERENCE_SLOT.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must identify a canonical reference site")
    if dimension == "global.reference":
        match = _GLOBAL_REFERENCE_SLOT.fullmatch(text)
        assert match is not None
        if int(match.group(1), 16) > target.maximum_address:
            raise StructuralScoringError(f"{path} exceeds the selected target address width")
    if dimension.startswith("type.aggregate.member-"):
        match = _MEMBER_SLOT.fullmatch(text)
        expected = "offset" if dimension.endswith("offset-bits") else "type"
        if match is None or match.group(2) != expected:
            raise StructuralScoringError(f"{path} must identify a canonical aggregate member slot")
    if dimension == "type.enum.enumerator-value" and _ENUMERATOR_SLOT.fullmatch(text) is None:
        raise StructuralScoringError(f"{path} must identify a canonical enumerator slot")
    return text


def _validate_fact(
    value: Any,
    path: str,
    *,
    recovered: bool,
    entity_kind: str,
    target: TargetAbiDescriptor,
) -> tuple[str, str, str]:
    keys = {"id", "slot", "dimension", "evidence", "value"}
    keys.add("state" if recovered else "observability")
    item = _object(value, path, keys)
    identifier = _identifier(item["id"], f"{path}.id")
    dimension = _string(item["dimension"], f"{path}.dimension", maximum=128)
    if dimension not in DIMENSIONS:
        raise StructuralScoringError(f"{path}.dimension is unsupported")
    if _DIMENSION_ENTITY_KIND[dimension] != entity_kind:
        raise StructuralScoringError(
            f"{path}.dimension is incompatible with {entity_kind} entities"
        )
    slot = _validate_slot(dimension, item["slot"], f"{path}.slot", target)
    _validate_evidence(item["evidence"], f"{path}.evidence")
    state_key = "state" if recovered else "observability"
    state = _string(item[state_key], f"{path}.{state_key}", maximum=64)
    allowed = {"recovered", "recovered-unknown"} if recovered else {"observable", "oracle-unobservable"}
    if state not in allowed:
        raise StructuralScoringError(f"{path}.{state_key} is invalid")
    expects_value = state in {"recovered", "observable"}
    if expects_value != (item["value"] is not None):
        raise StructuralScoringError(
            f"{path}.value must be present exactly for a concrete {state_key}"
        )
    if item["value"] is not None:
        _validate_value(item["value"], f"{path}.value", dimension, target)
    return identifier, dimension, slot


def _validate_entities(value: Any, path: str, *, recovered: bool, target: TargetAbiDescriptor) -> None:
    entities = _array(value, path, MAX_ENTITIES, minimum=1)
    seen_entities: set[tuple[str, str]] = set()
    fact_count = 0
    for index, raw in enumerate(entities):
        item_path = f"{path}[{index}]"
        item = _object(raw, item_path, {"kind", "id", "facts"})
        kind = _string(item["kind"], f"{item_path}.kind", maximum=32)
        if kind not in {"function", "global", "type"}:
            raise StructuralScoringError(f"{item_path}.kind is invalid")
        identifier = _identifier(item["id"], f"{item_path}.id")
        entity_key = (kind, identifier)
        if entity_key in seen_entities:
            raise StructuralScoringError(f"duplicate entity identity: {entity_key}")
        seen_entities.add(entity_key)
        facts = _array(item["facts"], f"{item_path}.facts", MAX_FACTS_PER_ENTITY, minimum=1)
        fact_count += len(facts)
        if fact_count > MAX_FACTS:
            raise StructuralScoringError(f"{path} exceeds the global fact limit")
        seen_fact_ids: set[str] = set()
        seen_slots: set[tuple[str, str]] = set()
        for fact_index, fact in enumerate(facts):
            fact_id, dimension, slot = _validate_fact(
                fact,
                f"{item_path}.facts[{fact_index}]",
                recovered=recovered,
                entity_kind=kind,
                target=target,
            )
            if fact_id in seen_fact_ids:
                raise StructuralScoringError(f"duplicate fact ID in {item_path}: {fact_id}")
            seen_fact_ids.add(fact_id)
            slot_key = (dimension, slot)
            if slot_key in seen_slots:
                raise StructuralScoringError(f"duplicate fact slot in {item_path}: {slot_key}")
            seen_slots.add(slot_key)


def load_structural_oracle(path: Path, target: TargetAbiDescriptor) -> StructuralOracle:
    snapshot = _snapshot_regular_file(path, "structural oracle")
    root = _object(
        _decode_json(snapshot, "structural oracle"),
        "structural oracle",
        {
            "schemaVersion",
            "scope",
            "oracle",
            "artifact",
            "targetAbi",
            "normalizationProfile",
            "entities",
        },
    )
    _schema_version(root, "structural oracle")
    scope = _string(root["scope"], "structural oracle.scope", maximum=32)
    if scope not in {"fixture", "production"}:
        raise StructuralScoringError("structural oracle.scope is invalid")
    oracle = _object(
        root["oracle"],
        "structural oracle.oracle",
        {"id", "producer", "artifactManifestSha256", "boundaryOracle"},
    )
    _identifier(oracle["id"], "structural oracle.oracle.id")
    _validate_tool_identity(oracle["producer"], "structural oracle.oracle.producer")
    manifest_sha = oracle["artifactManifestSha256"]
    if scope == "production":
        _sha256(manifest_sha, "structural oracle.oracle.artifactManifestSha256")
    elif manifest_sha is not None:
        raise StructuralScoringError("fixture structural oracle cannot claim an artifact manifest")
    boundary = _object(
        oracle["boundaryOracle"],
        "structural oracle.oracle.boundaryOracle",
        {"id", "artifactManifestSha256"},
    )
    _identifier(boundary["id"], "structural oracle.oracle.boundaryOracle.id")
    if scope == "production":
        boundary_manifest = _sha256(
            boundary["artifactManifestSha256"],
            "structural oracle.oracle.boundaryOracle.artifactManifestSha256",
        )
        if boundary_manifest != manifest_sha:
            raise StructuralScoringError("production structural and boundary oracles use different manifests")
    elif boundary["artifactManifestSha256"] is not None:
        raise StructuralScoringError("fixture boundary oracle cannot claim an artifact manifest")

    artifact = _object(
        root["artifact"],
        "structural oracle.artifact",
        {"id", "inputSha256", "sizeBytes", "imageBase"},
    )
    _identifier(artifact["id"], "structural oracle.artifact.id")
    _sha256(artifact["inputSha256"], "structural oracle.artifact.inputSha256")
    _integer(artifact["sizeBytes"], "structural oracle.artifact.sizeBytes", minimum=1)
    _address(
        artifact["imageBase"],
        "structural oracle.artifact.imageBase",
        maximum=target.maximum_address,
    )
    target_binding = _object(
        root["targetAbi"],
        "structural oracle.targetAbi",
        {"id", "sha256"},
    )
    if target_binding["id"] != target.identifier:
        raise StructuralScoringError("structural oracle target ABI ID does not match the descriptor")
    if _sha256(target_binding["sha256"], "structural oracle.targetAbi.sha256") != target.snapshot.sha256:
        raise StructuralScoringError("structural oracle target ABI digest does not match the descriptor")
    _validate_normalization_profile(
        root["normalizationProfile"],
        "structural oracle.normalizationProfile",
    )
    _validate_entities(root["entities"], "structural oracle.entities", recovered=False, target=target)
    return StructuralOracle(snapshot=snapshot, document=root)


def _load_attested_fixture(path: Path, label: str) -> tuple[Snapshot, Mapping[str, Any], str]:
    snapshot = _snapshot_regular_file(path, label)
    document = _decode_json(snapshot, label)
    if document.get("scope") != "fixture":
        raise StructuralScoringError(
            f"{label} is production-scoped; a concrete adapter replay verifier is required"
        )
    if "attestation" not in document:
        raise StructuralScoringError(f"{label}.attestation is required")
    attestation = _object(
        document["attestation"],
        f"{label}.attestation",
        {"kind", "payloadSha256", "evidenceSha256", "verifier"},
    )
    if attestation["kind"] != "fixture-digest":
        raise StructuralScoringError(f"{label} fixture must use fixture-digest attestation")
    if attestation["evidenceSha256"] is not None:
        raise StructuralScoringError(
            f"{label} fixture cannot claim an authenticated replay-evidence digest"
        )
    verifier = _object(
        attestation["verifier"],
        f"{label}.attestation.verifier",
        {"id", "version"},
    )
    _identifier(verifier["id"], f"{label}.attestation.verifier.id")
    _identifier(verifier["version"], f"{label}.attestation.verifier.version")
    payload_sha = hashlib.sha256(_canonical_payload(document)).hexdigest()
    if _sha256(attestation["payloadSha256"], f"{label}.attestation.payloadSha256") != payload_sha:
        raise StructuralScoringError(f"{label} fixture payload digest does not verify")
    return snapshot, document, payload_sha


def _project_function_boundary_artifact(
    value: Any,
    path: str,
    target: TargetAbiDescriptor,
) -> tuple[str, str, int, tuple[tuple[int, int], ...]]:
    """Project the current #39 report into format-neutral boundary coordinates.

    The current #39 report is an ELF adapter contract.  Format-specific fields
    terminate here; the scorer consumes only the generic projection returned by
    this function.
    """

    item = _object(
        value,
        path,
        {
            "inputSha256",
            "elfType",
            "elfImageBase",
            "modelImageBase",
            "modelImageBaseEvidence",
            "modelImageBaseValidation",
            "executableRvaRanges",
        },
    )
    object_format = "ELF"
    if target.object_format != object_format:
        raise StructuralScoringError(
            "the selected function-boundary adapter object format does not match "
            "the target descriptor"
        )
    input_sha256 = _sha256(item["inputSha256"], f"{path}.inputSha256")
    if item["elfType"] not in {"ET_EXEC", "ET_DYN"}:
        raise StructuralScoringError(f"{path}.elfType is invalid")
    _address(item["elfImageBase"], f"{path}.elfImageBase", maximum=target.maximum_address)
    model_image_base = _address(
        item["modelImageBase"],
        f"{path}.modelImageBase",
        maximum=target.maximum_address,
    )
    ranges: list[tuple[int, int]] = []
    for index, raw_range in enumerate(
        _array(item["executableRvaRanges"], f"{path}.executableRvaRanges", 256, minimum=1)
    ):
        range_path = f"{path}.executableRvaRanges[{index}]"
        range_item = _object(raw_range, range_path, {"start", "endExclusive"})
        start = _address(range_item["start"], f"{range_path}.start", maximum=target.maximum_address)
        end = _address(
            range_item["endExclusive"],
            f"{range_path}.endExclusive",
            maximum=target.maximum_address,
        )
        if end <= start:
            raise StructuralScoringError(f"{range_path} is empty or reversed")
        if ranges and start < ranges[-1][1]:
            raise StructuralScoringError(f"{path}.executableRvaRanges overlap or are unsorted")
        ranges.append((start, end))
    return object_format, input_sha256, model_image_base, tuple(ranges)


def load_boundary_mapping(
    path: Path,
    *,
    twin: str,
    target: TargetAbiDescriptor,
) -> BoundaryMapping:
    if twin not in {"rich", "stripped"}:
        raise StructuralScoringError("boundary mapping twin must be rich or stripped")
    snapshot = _snapshot_regular_file(path, "function-boundary score report")
    root = _decode_json(snapshot, "function-boundary score report", allow_floats=True)
    _object(root, "function-boundary score report", {"schemaVersion", "oracle", "policy", "twins"})
    _schema_version(root, "function-boundary score report")
    oracle = _object(
        root["oracle"],
        "function-boundary score report.oracle",
        {
            "id",
            "scope",
            "source",
            "artifactManifestSha256",
            "verification",
            "functionRecordCount",
            "scoredFunctionCount",
            "exclusions",
            "excludedFunctions",
        },
    )
    _identifier(oracle["id"], "function-boundary score report.oracle.id")
    if oracle["scope"] not in {"fixture", "production"}:
        raise StructuralScoringError("function-boundary score report oracle scope is invalid")
    if oracle["source"] != "dwarf-and-symbols":
        raise StructuralScoringError("function-boundary score report source is invalid")
    policy = _object(
        root["policy"],
        "function-boundary score report.policy",
        {
            "addressNormalization",
            "nearMissBytes",
            "nearMissMatching",
            "nameComparison",
            "exclusionHandling",
            "limits",
        },
    )
    near_miss_bytes = _integer(
        policy["nearMissBytes"],
        "function-boundary score report.policy.nearMissBytes",
        minimum=1,
        maximum=4096,
    )
    twins = root["twins"]
    if not isinstance(twins, dict) or set(twins) != {"rich", "stripped"}:
        raise StructuralScoringError("function-boundary score report.twins must contain rich and stripped")
    excluded_oracle_ids: set[str] = set()
    excluded_functions = _array(
        oracle["excludedFunctions"],
        "function-boundary score report.oracle.excludedFunctions",
        MAX_ENTITIES,
    )
    for index, raw in enumerate(excluded_functions):
        item_path = f"function-boundary score report.oracle.excludedFunctions[{index}]"
        item = _object(raw, item_path, {"oracleId", "rva", "aliases", "kind", "reason"})
        oracle_id = _identifier(item["oracleId"], f"{item_path}.oracleId")
        if oracle_id in excluded_oracle_ids:
            raise StructuralScoringError("function-boundary exclusions contain a duplicate oracle ID")
        excluded_oracle_ids.add(oracle_id)
        if item["rva"] is not None:
            _address(item["rva"], f"{item_path}.rva", maximum=target.maximum_address)
        _array(item["aliases"], f"{item_path}.aliases", 256, minimum=1)
        if item["kind"] not in {"compiler-generated", "inlined"}:
            raise StructuralScoringError(f"{item_path}.kind is invalid")
        _string(item["reason"], f"{item_path}.reason", maximum=MAX_TEXT_CHARACTERS)
    function_record_count = _integer(
        oracle["functionRecordCount"],
        "function-boundary score report.oracle.functionRecordCount",
        minimum=1,
    )
    scored_function_count = _integer(
        oracle["scoredFunctionCount"],
        "function-boundary score report.oracle.scoredFunctionCount",
        minimum=1,
    )
    if function_record_count != scored_function_count + len(excluded_oracle_ids):
        raise StructuralScoringError("function-boundary oracle record and exclusion counts disagree")

    selected = _object(
        twins[twin],
        f"function-boundary score report.twins.{twin}",
        {
            "artifact",
            "boundaries",
            "nameRecovery",
            "nearMatchAssignment",
            "exactMatches",
            "nearMisses",
            "falsePositives",
            "falseNegatives",
            "ignoredExcludedRecoveries",
        },
    )
    artifact_path = f"function-boundary score report.twins.{twin}.artifact"
    object_format, input_sha256, model_image_base, executable_ranges = (
        _project_function_boundary_artifact(selected["artifact"], artifact_path, target)
    )

    near_assignment = _object(
        selected["nearMatchAssignment"],
        f"function-boundary score report.twins.{twin}.nearMatchAssignment",
        {
            "objective",
            "stableTieBreak",
            "nameIndependent",
            "hasAlternativeOptimalMatching",
            "optimalCandidateEdgeCount",
            "alternativeOptimalEdges",
        },
    )
    if near_assignment["nameIndependent"] is not True:
        raise StructuralScoringError("function-boundary selected mapping is not name-independent")
    objective = _object(
        near_assignment["objective"],
        f"function-boundary score report.twins.{twin}.nearMatchAssignment.objective",
        {"maximumCardinality", "minimumTotalDistanceBytes"},
    )
    _integer(objective["maximumCardinality"], "function-boundary near objective cardinality")
    _integer(objective["minimumTotalDistanceBytes"], "function-boundary near objective distance")

    oracle_to_recovered: dict[str, str] = {}
    recovered_to_oracle: dict[str, str] = {}
    oracle_function_ids: set[str] = set()
    recovered_function_ids: set[str] = set()
    count = 0
    category_counts: dict[str, int] = {}
    near_distance = 0
    for category in ("exactMatches", "nearMisses"):
        records = _array(selected.get(category), f"function-boundary score report.twins.{twin}.{category}", MAX_ENTITIES)
        for index, raw in enumerate(records):
            item_path = f"function-boundary score report.twins.{twin}.{category}[{index}]"
            item = _object(
                raw,
                item_path,
                {
                    "oracleId",
                    "oracleRva",
                    "oracleAliases",
                    "recoveredId",
                    "recoveredRva",
                    "recoveredName",
                    "recoveredStatus",
                    "deltaBytes",
                    "matchKind",
                    "nameResult",
                    "matchedAlias",
                    "matchedAliasAvailability",
                    "nameCategoryResults",
                },
            )
            oracle_id = _identifier(item["oracleId"], f"{item_path}.oracleId")
            recovered_id = _identifier(item["recoveredId"], f"{item_path}.recoveredId")
            if oracle_id in excluded_oracle_ids:
                raise StructuralScoringError(
                    "function-boundary selected mapping overlaps the excluded oracle universe"
                )
            oracle_rva = _address(
                item["oracleRva"], f"{item_path}.oracleRva", maximum=target.maximum_address
            )
            recovered_rva = _address(
                item["recoveredRva"], f"{item_path}.recoveredRva", maximum=target.maximum_address
            )
            delta = item["deltaBytes"]
            if isinstance(delta, bool) or not isinstance(delta, int):
                raise StructuralScoringError(f"{item_path}.deltaBytes must be an integer")
            if delta != recovered_rva - oracle_rva:
                raise StructuralScoringError(f"{item_path}.deltaBytes does not match its RVAs")
            expected_kind = "exact" if category == "exactMatches" else "near"
            if item["matchKind"] != expected_kind:
                raise StructuralScoringError(f"{item_path}.matchKind is inconsistent with its category")
            if expected_kind == "exact" and delta != 0:
                raise StructuralScoringError(f"{item_path} is not an exact-address match")
            if expected_kind == "near" and (delta == 0 or abs(delta) > near_miss_bytes):
                raise StructuralScoringError(f"{item_path} is outside the near-match policy")
            if oracle_id in oracle_to_recovered or recovered_id in recovered_to_oracle:
                raise StructuralScoringError("function-boundary selected mapping is not one-to-one")
            oracle_to_recovered[oracle_id] = recovered_id
            recovered_to_oracle[recovered_id] = oracle_id
            oracle_function_ids.add(oracle_id)
            recovered_function_ids.add(recovered_id)
            count += 1
            if expected_kind == "near":
                near_distance += abs(delta)
            if count > MAX_MAPPINGS:
                raise StructuralScoringError("function-boundary mapping exceeds the mapping limit")
        category_counts[category] = len(records)

    false_negatives = _array(
        selected["falseNegatives"],
        f"function-boundary score report.twins.{twin}.falseNegatives",
        MAX_ENTITIES,
    )
    for index, raw in enumerate(false_negatives):
        item_path = f"function-boundary score report.twins.{twin}.falseNegatives[{index}]"
        item = _object(raw, item_path, {"oracleId", "oracleRva", "oracleAliases"})
        oracle_id = _identifier(item["oracleId"], f"{item_path}.oracleId")
        _address(item["oracleRva"], f"{item_path}.oracleRva", maximum=target.maximum_address)
        _array(item["oracleAliases"], f"{item_path}.oracleAliases", 256, minimum=1)
        if oracle_id in oracle_function_ids or oracle_id in excluded_oracle_ids:
            raise StructuralScoringError("function-boundary oracle universe is not partitioned")
        oracle_function_ids.add(oracle_id)

    false_positives = _array(
        selected["falsePositives"],
        f"function-boundary score report.twins.{twin}.falsePositives",
        MAX_ENTITIES,
    )
    for index, raw in enumerate(false_positives):
        item_path = f"function-boundary score report.twins.{twin}.falsePositives[{index}]"
        item = _object(
            raw,
            item_path,
            {"recoveredId", "recoveredRva", "recoveredName", "recoveredStatus"},
        )
        recovered_id = _identifier(item["recoveredId"], f"{item_path}.recoveredId")
        _address(item["recoveredRva"], f"{item_path}.recoveredRva", maximum=target.maximum_address)
        _string(item["recoveredName"], f"{item_path}.recoveredName")
        if item["recoveredStatus"] not in {"recovered", "partial", "failed", "synthetic"}:
            raise StructuralScoringError(f"{item_path}.recoveredStatus is invalid")
        if recovered_id in recovered_function_ids:
            raise StructuralScoringError("function-boundary recovered universe is not partitioned")
        recovered_function_ids.add(recovered_id)

    ignored_recovered_ids: set[str] = set()
    ignored = _array(
        selected["ignoredExcludedRecoveries"],
        f"function-boundary score report.twins.{twin}.ignoredExcludedRecoveries",
        MAX_ENTITIES,
    )
    for index, raw in enumerate(ignored):
        item_path = f"function-boundary score report.twins.{twin}.ignoredExcludedRecoveries[{index}]"
        item = _object(
            raw,
            item_path,
            {
                "recoveredId",
                "recoveredRva",
                "recoveredName",
                "recoveredStatus",
                "oracleId",
                "exclusionKind",
                "exclusionReason",
            },
        )
        recovered_id = _identifier(item["recoveredId"], f"{item_path}.recoveredId")
        oracle_id = _identifier(item["oracleId"], f"{item_path}.oracleId")
        _address(item["recoveredRva"], f"{item_path}.recoveredRva", maximum=target.maximum_address)
        if oracle_id not in excluded_oracle_ids or item["exclusionKind"] != "compiler-generated":
            raise StructuralScoringError("ignored recovery is not backed by a reviewed exclusion")
        if recovered_id in recovered_function_ids or recovered_id in ignored_recovered_ids:
            raise StructuralScoringError("ignored recovery overlaps the scored recovered universe")
        ignored_recovered_ids.add(recovered_id)

    if len(oracle_function_ids) != scored_function_count:
        raise StructuralScoringError("function-boundary scored oracle universe count disagrees")
    if objective["maximumCardinality"] != category_counts["nearMisses"]:
        raise StructuralScoringError("function-boundary near-assignment cardinality disagrees")
    if objective["minimumTotalDistanceBytes"] != near_distance:
        raise StructuralScoringError("function-boundary near-assignment distance disagrees")

    boundaries = _object(
        selected["boundaries"],
        f"function-boundary score report.twins.{twin}.boundaries",
        {
            "referenceCount",
            "rawRecoveredCount",
            "scoredRecoveredCount",
            "ignoredExcludedCount",
            "exactMatches",
            "nearMisses",
            "truePositives",
            "falsePositives",
            "falseNegatives",
            "precision",
            "recall",
            "f1",
            "exactAddressRate",
            "nearMissRate",
            "nearMissDistanceBytes",
        },
    )
    expected_counts = {
        "referenceCount": len(oracle_function_ids),
        "scoredRecoveredCount": len(recovered_function_ids),
        "ignoredExcludedCount": len(ignored_recovered_ids),
        "exactMatches": category_counts["exactMatches"],
        "nearMisses": category_counts["nearMisses"],
        "truePositives": count,
        "falsePositives": len(false_positives),
        "falseNegatives": len(false_negatives),
        "nearMissDistanceBytes": near_distance,
    }
    for key, expected in expected_counts.items():
        if _integer(boundaries[key], f"function-boundary boundaries.{key}") != expected:
            raise StructuralScoringError(f"function-boundary boundaries.{key} disagrees with records")
    raw_recovered = _integer(boundaries["rawRecoveredCount"], "function-boundary boundaries.rawRecoveredCount")
    if raw_recovered != len(recovered_function_ids) + len(ignored_recovered_ids):
        raise StructuralScoringError("function-boundary raw recovered count disagrees")

    return BoundaryMapping(
        snapshot=snapshot,
        document=root,
        twin=twin,
        projection_adapter_id=BOUNDARY_PROJECTION_ADAPTER_ID,
        projection_adapter_version=BOUNDARY_PROJECTION_ADAPTER_VERSION,
        object_format=object_format,
        input_sha256=input_sha256,
        model_image_base=model_image_base,
        executable_rva_ranges=executable_ranges,
        oracle_to_recovered=dict(oracle_to_recovered),
        recovered_to_oracle=dict(recovered_to_oracle),
        oracle_function_ids=frozenset(oracle_function_ids),
        recovered_function_ids=frozenset(recovered_function_ids),
        excluded_oracle_ids=frozenset(excluded_oracle_ids),
        ignored_recovered_ids=frozenset(ignored_recovered_ids),
    )


def load_fixture_identity_map(
    path: Path,
    *,
    oracle: StructuralOracle,
) -> IdentityMap:
    snapshot, document, _ = _load_attested_fixture(path, "structural identity map")
    root = _object(
        document,
        "structural identity map",
        {"schemaVersion", "scope", "map", "mappings", "attestation"},
    )
    _schema_version(root, "structural identity map")
    mapping_header = _object(
        root["map"],
        "structural identity map.map",
        {"id", "oracleId", "oracleSha256", "recoveredModelId"},
    )
    _identifier(mapping_header["id"], "structural identity map.map.id")
    if mapping_header["oracleId"] != oracle.document["oracle"]["id"]:
        raise StructuralScoringError("identity map oracle ID does not match the structural oracle")
    if _sha256(mapping_header["oracleSha256"], "structural identity map.map.oracleSha256") != oracle.snapshot.sha256:
        raise StructuralScoringError("identity map oracle digest does not match the structural oracle")
    _identifier(mapping_header["recoveredModelId"], "structural identity map.map.recoveredModelId")
    recovered_to_oracle: dict[tuple[str, str], str] = {}
    oracle_to_recovered: dict[tuple[str, str], str] = {}
    for index, raw in enumerate(
        _array(root["mappings"], "structural identity map.mappings", MAX_MAPPINGS)
    ):
        item_path = f"structural identity map.mappings[{index}]"
        item = _object(raw, item_path, {"kind", "oracleId", "recoveredId", "evidence"})
        kind = _string(item["kind"], f"{item_path}.kind", maximum=32)
        if kind not in {"global", "type"}:
            raise StructuralScoringError(f"{item_path}.kind must be global or type")
        oracle_id = _identifier(item["oracleId"], f"{item_path}.oracleId")
        recovered_id = _identifier(item["recoveredId"], f"{item_path}.recoveredId")
        _validate_mapping_evidence(item["evidence"], f"{item_path}.evidence")
        recovered_key = (kind, recovered_id)
        oracle_key = (kind, oracle_id)
        if recovered_key in recovered_to_oracle or oracle_key in oracle_to_recovered:
            raise StructuralScoringError("structural identity map must be one-to-one")
        recovered_to_oracle[recovered_key] = oracle_id
        oracle_to_recovered[oracle_key] = recovered_id
    return IdentityMap(
        snapshot=snapshot,
        document=root,
        recovered_to_oracle=dict(recovered_to_oracle),
        oracle_to_recovered=dict(oracle_to_recovered),
    )


def _validate_mapping_evidence(value: Any, path: str) -> None:
    for index, raw in enumerate(_array(value, path, MAX_EVIDENCE_PER_FACT, minimum=1)):
        item_path = f"{path}[{index}]"
        item = _object(
            raw,
            item_path,
            {"kind", "oracleLocator", "recoveredLocator", "verifier"},
        )
        _string(item["kind"], f"{item_path}.kind", maximum=128)
        _string(item["oracleLocator"], f"{item_path}.oracleLocator", maximum=MAX_TEXT_CHARACTERS)
        _string(item["recoveredLocator"], f"{item_path}.recoveredLocator", maximum=MAX_TEXT_CHARACTERS)
        _string(item["verifier"], f"{item_path}.verifier", maximum=MAX_TEXT_CHARACTERS)


def load_fixture_recovered_structure(
    path: Path,
    *,
    target: TargetAbiDescriptor,
    oracle: StructuralOracle,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
) -> RecoveredStructure:
    snapshot, document, payload_sha = _load_attested_fixture(path, "recovered structure")
    root = _object(
        document,
        "recovered structure",
        {"schemaVersion", "scope", "model", "provenance", "entities", "attestation"},
    )
    _schema_version(root, "recovered structure")
    model = _object(root["model"], "recovered structure.model", {"id"})
    model_id = _identifier(model["id"], "recovered structure.model.id")
    if model_id != identity_map.document["map"]["recoveredModelId"]:
        raise StructuralScoringError("recovered model ID does not match the identity map")
    provenance = _object(
        root["provenance"],
        "recovered structure.provenance",
        {
            "inputBinary",
            "exporter",
            "loader",
            "targetAbi",
            "normalizationProfile",
            "boundaryScore",
            "identityMap",
        },
    )
    input_binary = _object(
        provenance["inputBinary"],
        "recovered structure.provenance.inputBinary",
        {"sha256", "sizeBytes"},
    )
    input_sha = _sha256(input_binary["sha256"], "recovered structure.provenance.inputBinary.sha256")
    input_size = _integer(input_binary["sizeBytes"], "recovered structure.provenance.inputBinary.sizeBytes", minimum=1)
    artifact = oracle.document["artifact"]
    if input_sha != artifact["inputSha256"] or input_size != artifact["sizeBytes"]:
        raise StructuralScoringError("recovered input-binary provenance does not match the oracle artifact")
    _validate_tool_identity(provenance["exporter"], "recovered structure.provenance.exporter")
    loader = _object(
        provenance["loader"],
        "recovered structure.provenance.loader",
        {"id", "version", "executableSha256", "configurationSha256", "imageBase"},
    )
    _validate_tool_identity(
        {key: loader[key] for key in ("id", "version", "executableSha256", "configurationSha256")},
        "recovered structure.provenance.loader",
    )
    loader_base = _address(
        loader["imageBase"],
        "recovered structure.provenance.loader.imageBase",
        maximum=target.maximum_address,
    )
    if loader_base != _address(
        artifact["imageBase"],
        "structural oracle.artifact.imageBase",
        maximum=target.maximum_address,
    ):
        raise StructuralScoringError("recovered loader image base does not match the oracle artifact")
    target_binding = _object(
        provenance["targetAbi"],
        "recovered structure.provenance.targetAbi",
        {"id", "sha256"},
    )
    if target_binding["id"] != target.identifier or target_binding["sha256"] != target.snapshot.sha256:
        raise StructuralScoringError("recovered target ABI provenance does not match the descriptor")
    recovered_normalization_profile = _validate_normalization_profile(
        provenance["normalizationProfile"],
        "recovered structure.provenance.normalizationProfile",
    )
    oracle_normalization_profile = _validate_normalization_profile(
        oracle.document["normalizationProfile"],
        "structural oracle.normalizationProfile",
    )
    if recovered_normalization_profile != oracle_normalization_profile:
        raise StructuralScoringError(
            "recovered normalization profile does not match the structural oracle"
        )
    boundary_binding = _object(
        provenance["boundaryScore"],
        "recovered structure.provenance.boundaryScore",
        {"sha256", "twin", "projectionAdapter"},
    )
    if _sha256(boundary_binding["sha256"], "recovered structure.provenance.boundaryScore.sha256") != boundary.snapshot.sha256:
        raise StructuralScoringError("recovered boundary-score provenance does not match the selected report")
    if boundary_binding["twin"] != boundary.twin:
        raise StructuralScoringError("recovered boundary-score twin does not match the selected mapping")
    projection_adapter = _object(
        boundary_binding["projectionAdapter"],
        "recovered structure.provenance.boundaryScore.projectionAdapter",
        {"id", "version"},
    )
    if projection_adapter != {
        "id": boundary.projection_adapter_id,
        "version": boundary.projection_adapter_version,
    }:
        raise StructuralScoringError(
            "recovered boundary-score projection adapter does not match the selected mapping"
        )
    map_binding = _object(
        provenance["identityMap"],
        "recovered structure.provenance.identityMap",
        {"sha256"},
    )
    if _sha256(map_binding["sha256"], "recovered structure.provenance.identityMap.sha256") != identity_map.snapshot.sha256:
        raise StructuralScoringError("recovered identity-map provenance does not match the supplied mapping")

    boundary_oracle = oracle.document["oracle"]["boundaryOracle"]
    report_oracle = boundary.document["oracle"]
    if report_oracle.get("id") != boundary_oracle["id"]:
        raise StructuralScoringError("selected boundary report uses a different boundary oracle")
    if report_oracle.get("artifactManifestSha256") != boundary_oracle["artifactManifestSha256"]:
        raise StructuralScoringError("selected boundary report uses a different artifact manifest")
    if report_oracle.get("scope") != oracle.document["scope"]:
        raise StructuralScoringError("selected boundary report uses a different evidence scope")
    if boundary.input_sha256 != input_sha:
        raise StructuralScoringError("selected boundary report uses a different input binary")
    if boundary.model_image_base != loader_base:
        raise StructuralScoringError("selected boundary report uses a different loader image base")
    if boundary.object_format != target.object_format:
        raise StructuralScoringError("selected boundary report uses a different object format")

    _validate_entities(root["entities"], "recovered structure.entities", recovered=True, target=target)
    return RecoveredStructure(snapshot=snapshot, document=root, payload_sha256=payload_sha)


def _normalize_recovered_value(
    dimension: str,
    value: Mapping[str, Any],
    *,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
) -> tuple[Mapping[str, Any], bool | None]:
    source = value["source"]
    if dimension == "call.internal":
        recovered_id = str(source).removeprefix("function:")
        oracle_id = boundary.recovered_to_oracle.get(recovered_id)
        if oracle_id is None:
            return value, False
        source = f"function:{oracle_id}"
    elif dimension == "global.reference":
        recovered_id = str(source).removeprefix("global:")
        oracle_id = identity_map.recovered_to_oracle.get(("global", recovered_id))
        if oracle_id is None:
            return value, False
        source = f"global:{oracle_id}"
    elif dimension in {
        "function.parameter-abi-class",
        "function.return-abi-class",
        "global.type",
        "type.aggregate.member-type",
        "type.enum.underlying-abi-class",
        "type.typedef.target",
    }:
        if str(source).startswith("type-entity:"):
            recovered_id = str(source).removeprefix("type-entity:")
            oracle_id = identity_map.recovered_to_oracle.get(("type", recovered_id))
            if oracle_id is None:
                return value, False
            source = f"type-entity:{oracle_id}"
    return {"source": source, "abi": value["abi"]}, (
        True
        if dimension in {"call.internal", "global.reference"}
        or (
            dimension
            in {
                "function.parameter-abi-class",
                "function.return-abi-class",
                "global.type",
                "type.aggregate.member-type",
                "type.enum.underlying-abi-class",
                "type.typedef.target",
            }
            and str(value["source"]).startswith("type-entity:")
        )
        else None
    )


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": None if denominator == 0 else round(numerator / denominator, 6),
    }


def _fact_outcome(
    dimension: str,
    oracle_value: Mapping[str, Any],
    recovered_value: Mapping[str, Any],
    *,
    mapping_verified: bool | None = None,
) -> str:
    if mapping_verified is False:
        return "contradicted"
    if oracle_value == recovered_value:
        return "exact"
    oracle_abi = oracle_value["abi"]
    recovered_abi = recovered_value["abi"]
    if (
        dimension in _ABI_EQUIVALENT_DIMENSIONS
        and oracle_abi is not None
        and oracle_abi == recovered_abi
    ):
        return "abi-equivalent"
    return "contradicted"


def _evidence_copy(value: Any) -> list[dict[str, str]]:
    return [{"kind": item["kind"], "locator": item["locator"]} for item in value]


def _entity_key(kind: str, identifier: str) -> tuple[str, str]:
    return kind, identifier


def _mapped_oracle_id(
    kind: str,
    recovered_id: str,
    *,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
) -> str | None:
    if kind == "function":
        return boundary.recovered_to_oracle.get(recovered_id)
    return identity_map.recovered_to_oracle.get((kind, recovered_id))


def _mapped_recovered_id(
    kind: str,
    oracle_id: str,
    *,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
) -> str | None:
    if kind == "function":
        return boundary.oracle_to_recovered.get(oracle_id)
    return identity_map.oracle_to_recovered.get((kind, oracle_id))


def _slot_rva(dimension: str, slot: str) -> int | None:
    if dimension.startswith("call."):
        match = _CALL_SLOT.fullmatch(slot)
        assert match is not None
        return int(match.group(1), 16)
    if dimension == "global.reference":
        match = _GLOBAL_REFERENCE_SLOT.fullmatch(slot)
        assert match is not None
        return int(match.group(1), 16)
    return None


def _in_executable_ranges(rva: int, boundary: BoundaryMapping) -> bool:
    return any(start <= rva < end for start, end in boundary.executable_rva_ranges)


def _validate_structural_identity_universes(
    oracle_entities: Mapping[tuple[str, str], Mapping[str, Any]],
    recovered_entities: Mapping[tuple[str, str], Mapping[str, Any]],
    boundary: BoundaryMapping,
) -> None:
    oracle_function_ids = {
        identifier for kind, identifier in oracle_entities if kind == "function"
    }
    recovered_function_ids = {
        identifier for kind, identifier in recovered_entities if kind == "function"
    }
    extra_oracle_ids = oracle_function_ids - boundary.oracle_function_ids
    if extra_oracle_ids:
        raise StructuralScoringError(
            "structural oracle function is absent from the selected #39 oracle universe"
        )
    missing_oracle_ids = boundary.oracle_function_ids - oracle_function_ids
    if missing_oracle_ids:
        raise StructuralScoringError(
            "structural oracle omits functions from the selected #39 oracle universe"
        )
    extra_recovered_ids = recovered_function_ids - boundary.recovered_function_ids
    if extra_recovered_ids & boundary.ignored_recovered_ids:
        raise StructuralScoringError(
            "recovered structural function is excluded by the selected #39 report"
        )
    if extra_recovered_ids:
        raise StructuralScoringError(
            "recovered structural function is absent from the selected #39 recovered universe"
        )
    missing_recovered_ids = boundary.recovered_function_ids - recovered_function_ids
    if missing_recovered_ids:
        raise StructuralScoringError(
            "recovered structure omits functions from the selected #39 recovered universe"
        )

    for entities, recovered_side in (
        (oracle_entities, False),
        (recovered_entities, True),
    ):
        for (kind, _), entity in entities.items():
            for fact in entity["facts"]:
                if kind == "function":
                    site_rva = _slot_rva(fact["dimension"], fact["slot"])
                    if site_rva is not None and not _in_executable_ranges(site_rva, boundary):
                        raise StructuralScoringError(
                            "structural call/reference site is outside the selected executable ranges"
                        )
                if fact["value"] is None:
                    continue
                source = fact["value"]["source"]
                if fact["dimension"] == "call.internal":
                    endpoint = str(source).removeprefix("function:")
                    universe = (
                        boundary.recovered_function_ids
                        if recovered_side
                        else boundary.oracle_function_ids
                    )
                    if endpoint not in universe:
                        raise StructuralScoringError(
                            "internal-call endpoint is absent from the selected #39 universe"
                        )
                elif fact["dimension"] == "global.reference":
                    endpoint = str(source).removeprefix("global:")
                    if ("global", endpoint) not in entities:
                        raise StructuralScoringError(
                            "global-reference endpoint is absent from its structural entity universe"
                        )
                elif fact["dimension"] in {
                    "function.parameter-abi-class",
                    "function.return-abi-class",
                    "global.type",
                    "type.aggregate.member-type",
                    "type.enum.underlying-abi-class",
                    "type.typedef.target",
                } and str(source).startswith("type-entity:"):
                    endpoint = str(source).removeprefix("type-entity:")
                    if ("type", endpoint) not in entities:
                        raise StructuralScoringError(
                            "type endpoint is absent from its structural entity universe"
                        )


def score_fixture_structural_recovery(
    oracle: StructuralOracle,
    recovered: RecoveredStructure,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
    target: TargetAbiDescriptor,
) -> dict[str, Any]:
    """Score digest-bound fixture inputs without granting production status."""

    if oracle.document["scope"] != "fixture" or recovered.document["scope"] != "fixture":
        raise StructuralScoringError("fixture scorer refuses production-scoped evidence")
    _preflight_scoring_budget(oracle, recovered, boundary, identity_map, target)
    oracle_entities = {
        _entity_key(item["kind"], item["id"]): item
        for item in oracle.document["entities"]
    }
    recovered_entities = {
        _entity_key(item["kind"], item["id"]): item
        for item in recovered.document["entities"]
    }
    _validate_structural_identity_universes(
        oracle_entities,
        recovered_entities,
        boundary,
    )

    for (kind, mapped_recovered_id), mapped_oracle_id in identity_map.recovered_to_oracle.items():
        if (kind, mapped_oracle_id) not in oracle_entities:
            raise StructuralScoringError("identity map references an absent oracle entity")
        if (kind, mapped_recovered_id) not in recovered_entities:
            raise StructuralScoringError("identity map references an absent recovered entity")
    for selected_recovered_id, selected_oracle_id in boundary.recovered_to_oracle.items():
        if (
            ("function", selected_recovered_id) in recovered_entities
            and ("function", selected_oracle_id) not in oracle_entities
        ):
            raise StructuralScoringError("selected boundary mapping references an absent structural oracle function")

    details: list[dict[str, Any]] = []
    consumed_recovered_entities: set[tuple[str, str]] = set()

    for (kind, oracle_id), oracle_entity in sorted(oracle_entities.items()):
        recovered_id = _mapped_recovered_id(
            kind,
            oracle_id,
            boundary=boundary,
            identity_map=identity_map,
        )
        recovered_entity = None if recovered_id is None else recovered_entities.get((kind, recovered_id))
        if recovered_entity is not None:
            assert recovered_id is not None
            consumed_recovered_entities.add((kind, recovered_id))
        recovered_facts = (
            {}
            if recovered_entity is None
            else {
                (fact["dimension"], fact["slot"]): fact
                for fact in recovered_entity["facts"]
            }
        )
        consumed_fact_slots: set[tuple[str, str]] = set()
        outcomes: list[dict[str, Any]] = []
        for oracle_fact in sorted(
            oracle_entity["facts"],
            key=lambda fact: (fact["dimension"], fact["slot"], fact["id"]),
        ):
            slot_key = (oracle_fact["dimension"], oracle_fact["slot"])
            recovered_fact = recovered_facts.get(slot_key)
            normalized_recovered_value = None
            reference_mapping_verified = None
            if recovered_fact is not None:
                consumed_fact_slots.add(slot_key)
            if oracle_fact["observability"] == "oracle-unobservable":
                outcome = "oracle-unobservable"
            elif recovered_fact is None or recovered_fact["state"] == "recovered-unknown":
                outcome = "recovered-unknown"
            else:
                normalized_recovered_value, reference_mapping_verified = _normalize_recovered_value(
                    recovered_fact["dimension"],
                    recovered_fact["value"],
                    boundary=boundary,
                    identity_map=identity_map,
                )
                outcome = _fact_outcome(
                    oracle_fact["dimension"],
                    oracle_fact["value"],
                    normalized_recovered_value,
                    mapping_verified=reference_mapping_verified,
                )
            outcomes.append(
                {
                    "dimension": oracle_fact["dimension"],
                    "slot": oracle_fact["slot"],
                    "oracleFactId": oracle_fact["id"],
                    "recoveredFactId": None if recovered_fact is None else recovered_fact["id"],
                    "outcome": outcome,
                    "oracleValue": oracle_fact["value"],
                    "recoveredValue": None if recovered_fact is None else recovered_fact["value"],
                    "normalizedRecoveredValue": normalized_recovered_value,
                    "referenceMappingVerified": reference_mapping_verified,
                    "oracleEvidence": _evidence_copy(oracle_fact["evidence"]),
                    "recoveredEvidence": [] if recovered_fact is None else _evidence_copy(recovered_fact["evidence"]),
                }
            )
        if recovered_entity is not None:
            for recovered_fact in sorted(
                recovered_entity["facts"],
                key=lambda fact: (fact["dimension"], fact["slot"], fact["id"]),
            ):
                slot_key = (recovered_fact["dimension"], recovered_fact["slot"])
                if slot_key in consumed_fact_slots:
                    continue
                outcomes.append(
                    {
                        "dimension": recovered_fact["dimension"],
                        "slot": recovered_fact["slot"],
                        "oracleFactId": None,
                        "recoveredFactId": recovered_fact["id"],
                        "outcome": "fabricated",
                        "oracleValue": None,
                        "recoveredValue": recovered_fact["value"],
                        "normalizedRecoveredValue": None,
                        "referenceMappingVerified": None,
                        "oracleEvidence": [],
                        "recoveredEvidence": _evidence_copy(recovered_fact["evidence"]),
                    }
                )
        details.append(
            {
                "kind": kind,
                "oracleId": oracle_id,
                "recoveredId": recovered_id if recovered_entity is not None else None,
                "facts": sorted(outcomes, key=lambda item: (item["dimension"], item["slot"], item["outcome"])),
            }
        )

    for (kind, recovered_id), recovered_entity in sorted(recovered_entities.items()):
        if (kind, recovered_id) in consumed_recovered_entities:
            continue
        mapped_id = _mapped_oracle_id(
            kind,
            recovered_id,
            boundary=boundary,
            identity_map=identity_map,
        )
        facts = [
            {
                "dimension": fact["dimension"],
                "slot": fact["slot"],
                "oracleFactId": None,
                "recoveredFactId": fact["id"],
                "outcome": "fabricated",
                "oracleValue": None,
                "recoveredValue": fact["value"],
                "normalizedRecoveredValue": None,
                "referenceMappingVerified": None,
                "oracleEvidence": [],
                "recoveredEvidence": _evidence_copy(fact["evidence"]),
            }
            for fact in sorted(
                recovered_entity["facts"],
                key=lambda item: (item["dimension"], item["slot"], item["id"]),
            )
        ]
        details.append(
            {
                "kind": kind,
                "oracleId": mapped_id if (kind, mapped_id) in oracle_entities else None,
                "recoveredId": recovered_id,
                "facts": facts,
            }
        )

    for entity in details:
        entity["metric"] = _metric_for_facts(entity["facts"])
    dimension_metrics = [
        _metric_for_dimension(dimension, details) for dimension in DIMENSIONS
    ]
    aggregate = _metric_for_dimension(None, details)
    report = {
        "schemaVersion": 1,
        "oracle": {
            "id": oracle.document["oracle"]["id"],
            "scope": oracle.document["scope"],
            "sha256": oracle.snapshot.sha256,
            "artifactManifestSha256": oracle.document["oracle"]["artifactManifestSha256"],
            "boundaryOracleId": oracle.document["oracle"]["boundaryOracle"]["id"],
        },
        "model": {
            "id": recovered.document["model"]["id"],
            "scope": recovered.document["scope"],
            "sha256": recovered.snapshot.sha256,
            "payloadSha256": recovered.payload_sha256,
            "verification": {
                "status": "fixture-digest-only",
                "payloadDigestVerified": True,
                "identityMapPayloadDigestVerified": True,
                "adapterReplayVerified": False,
                "productionVerified": False,
            },
            "provenance": recovered.document["provenance"],
        },
        "targetAbi": {
            "id": target.identifier,
            "sha256": target.snapshot.sha256,
        },
        "normalizationProfile": dict(oracle.document["normalizationProfile"]),
        "boundaryMapping": {
            "scoreSha256": boundary.snapshot.sha256,
            "twin": boundary.twin,
            "projectionAdapter": {
                "id": boundary.projection_adapter_id,
                "version": boundary.projection_adapter_version,
                "objectFormat": boundary.object_format,
            },
            "selectedFunctionCount": len(boundary.oracle_to_recovered),
        },
        "identityMapping": {
            "id": identity_map.document["map"]["id"],
            "sha256": identity_map.snapshot.sha256,
            "mappingCount": len(identity_map.recovered_to_oracle),
            "verification": "fixture-payload-digest-only",
            "productionVerified": False,
        },
        "policy": {
            "identitySelection": IDENTITY_SELECTION_POLICY,
            "abiEquivalence": ABI_EQUIVALENCE_POLICY,
            "sourceNormalization": SOURCE_NORMALIZATION_POLICY,
            "outcomeLattice": list(OUTCOMES),
            "limits": _report_limits(),
        },
        "dimensions": dimension_metrics,
        "aggregate": aggregate,
        "entities": sorted(
            details,
            key=lambda item: (item["kind"], item["oracleId"] or "", item["recoveredId"] or ""),
        ),
    }
    validate_structural_score_report(report, target=target)
    encoded = canonical_report_bytes(report, target=target)
    if len(encoded) > MAX_REPORT_BYTES:
        raise StructuralScoringError(
            f"structural score report exceeds the {MAX_REPORT_BYTES}-byte output limit"
        )
    return report


def _preflight_scoring_budget(
    oracle: StructuralOracle,
    recovered: RecoveredStructure,
    boundary: BoundaryMapping,
    identity_map: IdentityMap,
    target: TargetAbiDescriptor,
) -> None:
    snapshots = (
        oracle.snapshot,
        recovered.snapshot,
        boundary.snapshot,
        identity_map.snapshot,
        target.snapshot,
    )
    total_input_bytes = sum(len(snapshot.data) for snapshot in snapshots)
    if total_input_bytes > MAX_TOTAL_INPUT_BYTES:
        raise StructuralScoringError(
            f"scorer inputs exceed the {MAX_TOTAL_INPUT_BYTES}-byte aggregate input budget"
        )
    oracle_entities = oracle.document["entities"]
    recovered_entities = recovered.document["entities"]
    total_entities = len(oracle_entities) + len(recovered_entities)
    if total_entities > MAX_TOTAL_ENTITIES:
        raise StructuralScoringError("scorer inputs exceed the aggregate entity budget")
    oracle_facts = [fact for entity in oracle_entities for fact in entity["facts"]]
    recovered_facts = [fact for entity in recovered_entities for fact in entity["facts"]]
    total_facts = len(oracle_facts) + len(recovered_facts)
    if total_facts > MAX_TOTAL_FACTS:
        raise StructuralScoringError("scorer inputs exceed the aggregate fact budget")
    total_evidence = sum(len(fact["evidence"]) for fact in oracle_facts)
    total_evidence += sum(len(fact["evidence"]) for fact in recovered_facts)
    total_evidence += sum(
        len(mapping["evidence"]) for mapping in identity_map.document["mappings"]
    )
    if total_evidence > MAX_TOTAL_EVIDENCE:
        raise StructuralScoringError("scorer inputs exceed the aggregate evidence budget")

    # Every oracle fact produces one row.  A recovered fact can produce at most
    # one additional fabricated row, so this is a safe cardinality bound even
    # before identities are joined.
    maximum_report_entries = len(oracle_facts) + len(recovered_facts)
    if maximum_report_entries > MAX_REPORT_ENTRIES:
        raise StructuralScoringError("projected structural report exceeds the entry budget")
    projection = 65_536 + total_entities * 512
    projection += sum(1024 + 2 * _estimate_json_node_bytes(fact) for fact in oracle_facts)
    projection += sum(1024 + 2 * _estimate_json_node_bytes(fact) for fact in recovered_facts)
    if projection > MAX_PROJECTED_REPORT_BYTES:
        raise StructuralScoringError(
            "projected structural report exceeds the preconstruction byte budget"
        )


def _estimate_json_node_bytes(value: Any) -> int:
    """Allocation-light upper estimate for one already-bounded decoded node."""

    if value is None:
        return 4
    if isinstance(value, bool):
        return 5
    if isinstance(value, int):
        return 24
    if isinstance(value, float):
        return 32
    if isinstance(value, str):
        # UTF-8 uses at most four bytes per code point; escaping and quotes can
        # at most double that byte count for this conservative projection.
        return 2 + len(value) * 8
    if isinstance(value, list):
        return 2 + len(value) + sum(_estimate_json_node_bytes(item) for item in value)
    if isinstance(value, dict):
        return 2 + len(value) + sum(
            _estimate_json_node_bytes(str(key)) + _estimate_json_node_bytes(item)
            for key, item in value.items()
        )
    raise StructuralScoringError("cannot project an unsupported decoded JSON node")


def _metric_for_dimension(
    dimension: str | None,
    details: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    facts = [
        fact
        for entity in details
        for fact in entity["facts"]
        if dimension is None or fact["dimension"] == dimension
    ]
    return {
        "dimension": dimension,
        **_metric_for_facts(facts),
    } if dimension is not None else _metric_for_facts(facts)


def _metric_for_facts(facts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    outcome_counts = {outcome: 0 for outcome in OUTCOMES}
    oracle_denominator = 0
    recovered_denominator = 0
    for fact in facts:
        outcome_counts[fact["outcome"]] += 1
        if fact["oracleFactId"] is not None:
            oracle_denominator += 1
        if fact["recoveredFactId"] is not None:
            recovered_denominator += 1
    oracle_partition = sum(
        outcome_counts[outcome]
        for outcome in OUTCOMES
        if outcome != "fabricated"
    )
    if oracle_partition != oracle_denominator:
        raise AssertionError("structural oracle denominator partition drift")
    credit = outcome_counts["exact"] + outcome_counts["abi-equivalent"]
    return {
        "oracleDenominator": oracle_denominator,
        "recoveredDenominator": recovered_denominator,
        "observableOracleCount": oracle_denominator - outcome_counts["oracle-unobservable"],
        "unobservableOracleCount": outcome_counts["oracle-unobservable"],
        "outcomes": outcome_counts,
        "credit": _ratio(credit, oracle_denominator),
        "claimPrecision": _ratio(credit, recovered_denominator),
    }


def _validate_report_metric(
    value: Any,
    path: str,
    *,
    dimension: str | None = None,
) -> Mapping[str, Any]:
    keys = {
        "oracleDenominator",
        "recoveredDenominator",
        "observableOracleCount",
        "unobservableOracleCount",
        "outcomes",
        "credit",
        "claimPrecision",
    }
    if dimension is not None:
        keys.add("dimension")
    item = _object(value, path, keys)
    if dimension is not None and item["dimension"] != dimension:
        raise StructuralScoringError(f"{path}.dimension is inconsistent")
    for key in (
        "oracleDenominator",
        "recoveredDenominator",
        "observableOracleCount",
        "unobservableOracleCount",
    ):
        _integer(item[key], f"{path}.{key}")
    outcomes = _object(item["outcomes"], f"{path}.outcomes", OUTCOMES)
    for outcome in OUTCOMES:
        _integer(outcomes[outcome], f"{path}.outcomes.{outcome}")
    for ratio_key in ("credit", "claimPrecision"):
        ratio_path = f"{path}.{ratio_key}"
        ratio = _object(
            item[ratio_key],
            ratio_path,
            {"numerator", "denominator", "value"},
        )
        _integer(ratio["numerator"], f"{ratio_path}.numerator")
        _integer(ratio["denominator"], f"{ratio_path}.denominator")
        ratio_value = ratio["value"]
        if ratio_value is not None and (
            isinstance(ratio_value, bool)
            or not isinstance(ratio_value, (int, float))
            or not math.isfinite(ratio_value)
            or not 0 <= ratio_value <= 1
        ):
            raise StructuralScoringError(f"{ratio_path}.value must be null or a finite ratio")
    return item


def _validate_report_value(
    value: Any,
    path: str,
    dimension: str,
    target: TargetAbiDescriptor,
) -> Mapping[str, Any]:
    _validate_value(value, path, dimension, target)
    assert isinstance(value, dict)
    return value


def _normalize_report_recovered_value(
    dimension: str,
    value: Mapping[str, Any],
    recovered_to_oracle: Mapping[tuple[str, str], str],
) -> tuple[Mapping[str, Any], bool | None]:
    source = value["source"]
    reference_kind: str | None = None
    prefix: str | None = None
    if dimension == "call.internal":
        reference_kind, prefix = "function", "function:"
    elif dimension == "global.reference":
        reference_kind, prefix = "global", "global:"
    elif (
        dimension
        in {
            "function.parameter-abi-class",
            "function.return-abi-class",
            "global.type",
            "type.aggregate.member-type",
            "type.enum.underlying-abi-class",
            "type.typedef.target",
        }
        and isinstance(source, str)
        and source.startswith("type-entity:")
    ):
        reference_kind, prefix = "type", "type-entity:"
    if reference_kind is None or prefix is None:
        return value, None
    recovered_id = str(source).removeprefix(prefix)
    oracle_id = recovered_to_oracle.get((reference_kind, recovered_id))
    if oracle_id is None:
        return value, False
    return {"source": f"{prefix}{oracle_id}", "abi": value["abi"]}, True


def _validate_report_reference_endpoint(
    dimension: str,
    value: Mapping[str, Any],
    entity_ids: frozenset[tuple[str, str]],
    path: str,
) -> None:
    source = value["source"]
    reference_kind: str | None = None
    prefix: str | None = None
    if dimension == "call.internal":
        reference_kind, prefix = "function", "function:"
    elif dimension == "global.reference":
        reference_kind, prefix = "global", "global:"
    elif (
        dimension
        in {
            "function.parameter-abi-class",
            "function.return-abi-class",
            "global.type",
            "type.aggregate.member-type",
            "type.enum.underlying-abi-class",
            "type.typedef.target",
        }
        and isinstance(source, str)
        and source.startswith("type-entity:")
    ):
        reference_kind, prefix = "type", "type-entity:"
    if reference_kind is None or prefix is None:
        return
    identifier = str(source).removeprefix(prefix)
    if (reference_kind, identifier) not in entity_ids:
        raise StructuralScoringError(
            f"{path}.source references an entity absent from the report universe"
        )


def _validate_report_fact_result(
    value: Any,
    path: str,
    *,
    entity_kind: str,
    recovered_to_oracle: Mapping[tuple[str, str], str],
    oracle_entity_ids: frozenset[tuple[str, str]],
    recovered_entity_ids: frozenset[tuple[str, str]],
    target: TargetAbiDescriptor,
) -> int:
    item = _object(
        value,
        path,
        {
            "dimension",
            "slot",
            "oracleFactId",
            "recoveredFactId",
            "outcome",
            "oracleValue",
            "recoveredValue",
            "normalizedRecoveredValue",
            "referenceMappingVerified",
            "oracleEvidence",
            "recoveredEvidence",
        },
    )
    if item["dimension"] not in DIMENSIONS or item["outcome"] not in OUTCOMES:
        raise StructuralScoringError(f"{path} uses an unsupported dimension or outcome")
    dimension = item["dimension"]
    if _DIMENSION_ENTITY_KIND[dimension] != entity_kind:
        raise StructuralScoringError(
            f"{path}.dimension is incompatible with its report entity kind"
        )
    _validate_slot(dimension, item["slot"], f"{path}.slot", target)
    oracle_id = item["oracleFactId"]
    recovered_id = item["recoveredFactId"]
    if oracle_id is not None:
        _identifier(oracle_id, f"{path}.oracleFactId")
    if recovered_id is not None:
        _identifier(recovered_id, f"{path}.recoveredFactId")
    oracle_value = (
        None
        if item["oracleValue"] is None
        else _validate_report_value(
            item["oracleValue"],
            f"{path}.oracleValue",
            dimension,
            target,
        )
    )
    recovered_value = (
        None
        if item["recoveredValue"] is None
        else _validate_report_value(
            item["recoveredValue"],
            f"{path}.recoveredValue",
            dimension,
            target,
        )
    )
    normalized_recovered_value = (
        None
        if item["normalizedRecoveredValue"] is None
        else _validate_report_value(
            item["normalizedRecoveredValue"],
            f"{path}.normalizedRecoveredValue",
            dimension,
            target,
        )
    )
    if oracle_value is not None:
        _validate_report_reference_endpoint(
            dimension,
            oracle_value,
            oracle_entity_ids,
            f"{path}.oracleValue",
        )
    if recovered_value is not None:
        _validate_report_reference_endpoint(
            dimension,
            recovered_value,
            recovered_entity_ids,
            f"{path}.recoveredValue",
        )
    reference_mapping_verified = item["referenceMappingVerified"]
    if reference_mapping_verified is not None:
        _boolean(reference_mapping_verified, f"{path}.referenceMappingVerified")
    outcome = item["outcome"]
    if outcome in {"exact", "abi-equivalent", "contradicted"}:
        if (
            oracle_id is None
            or recovered_id is None
            or oracle_value is None
            or recovered_value is None
            or normalized_recovered_value is None
        ):
            raise StructuralScoringError(f"{path} has impossible concrete-outcome nullability")
        expected_normalized, expected_mapping_verified = (
            _normalize_report_recovered_value(
                item["dimension"],
                recovered_value,
                recovered_to_oracle,
            )
        )
        if (
            normalized_recovered_value != expected_normalized
            or reference_mapping_verified is not expected_mapping_verified
        ):
            raise StructuralScoringError(
                f"{path} has an inconsistent normalized comparison binding"
            )
        expected_outcome = _fact_outcome(
            item["dimension"],
            oracle_value,
            expected_normalized,
            mapping_verified=expected_mapping_verified,
        )
        if outcome != expected_outcome:
            raise StructuralScoringError(
                f"{path}.outcome does not match its normalized values"
            )
    elif outcome == "recovered-unknown":
        if oracle_id is None or oracle_value is None or recovered_value is not None:
            raise StructuralScoringError(f"{path} has impossible recovered-unknown nullability")
    elif outcome == "oracle-unobservable":
        if oracle_id is None or oracle_value is not None:
            raise StructuralScoringError(f"{path} has impossible oracle-unobservable nullability")
    elif outcome == "fabricated":
        if oracle_id is not None or oracle_value is not None or recovered_id is None:
            raise StructuralScoringError(f"{path} has impossible fabricated nullability")
    if outcome not in {"exact", "abi-equivalent", "contradicted"} and (
        normalized_recovered_value is not None or reference_mapping_verified is not None
    ):
        raise StructuralScoringError(
            f"{path} carries a comparison binding for an outcome without a comparison"
        )
    evidence_count = 0
    evidence_by_side: dict[str, list[Any]] = {}
    for evidence_key in ("oracleEvidence", "recoveredEvidence"):
        evidence = _array(item[evidence_key], f"{path}.{evidence_key}", MAX_EVIDENCE_PER_FACT)
        evidence_by_side[evidence_key] = evidence
        evidence_count += len(evidence)
        seen_evidence: set[tuple[str, str]] = set()
        for index, raw in enumerate(evidence):
            evidence_path = f"{path}.{evidence_key}[{index}]"
            evidence_item = _object(raw, evidence_path, {"kind", "locator"})
            kind = _string(evidence_item["kind"], f"{evidence_path}.kind", maximum=128)
            locator = _string(
                evidence_item["locator"],
                f"{evidence_path}.locator",
                maximum=MAX_TEXT_CHARACTERS,
            )
            evidence_identity = (kind, locator)
            if evidence_identity in seen_evidence:
                raise StructuralScoringError(f"{path}.{evidence_key} contains duplicate evidence")
            seen_evidence.add(evidence_identity)
    if (oracle_id is None) != (not evidence_by_side["oracleEvidence"]):
        raise StructuralScoringError(f"{path} has inconsistent oracle identity and evidence")
    if (recovered_id is None) != (not evidence_by_side["recoveredEvidence"]):
        raise StructuralScoringError(f"{path} has inconsistent recovered identity and evidence")
    if oracle_id is None and oracle_value is not None:
        raise StructuralScoringError(f"{path} has a value without an oracle fact identity")
    if recovered_id is None and recovered_value is not None:
        raise StructuralScoringError(f"{path} has a value without a recovered fact identity")
    return evidence_count


def validate_structural_score_report(
    report: Mapping[str, Any],
    *,
    target: TargetAbiDescriptor,
) -> None:
    """Validate a fixture report without authenticating production evidence."""

    root = _object(
        report,
        "structural score report",
        {
            "schemaVersion",
            "oracle",
            "model",
            "targetAbi",
            "normalizationProfile",
            "boundaryMapping",
            "identityMapping",
            "policy",
            "dimensions",
            "aggregate",
            "entities",
        },
    )
    _schema_version(root, "structural score report")
    oracle_header = _object(
        root["oracle"],
        "structural score report.oracle",
        {"id", "scope", "sha256", "artifactManifestSha256", "boundaryOracleId"},
    )
    model_header = _object(
        root["model"],
        "structural score report.model",
        {"id", "scope", "sha256", "payloadSha256", "verification", "provenance"},
    )
    _identifier(oracle_header["id"], "structural score report.oracle.id")
    _sha256(oracle_header["sha256"], "structural score report.oracle.sha256")
    _identifier(
        oracle_header["boundaryOracleId"],
        "structural score report.oracle.boundaryOracleId",
    )
    _identifier(model_header["id"], "structural score report.model.id")
    _sha256(model_header["sha256"], "structural score report.model.sha256")
    _sha256(
        model_header["payloadSha256"],
        "structural score report.model.payloadSha256",
    )
    scope = _string(
        oracle_header.get("scope"),
        "structural score report.oracle.scope",
        maximum=32,
    )
    model_scope = _string(
        model_header.get("scope"),
        "structural score report.model.scope",
        maximum=32,
    )
    if scope not in {"fixture", "production"} or model_scope != scope:
        raise StructuralScoringError("structural score oracle and model scopes must agree")
    if scope == "production":
        raise StructuralScoringError(
            "production structural reports require a separate trusted adapter-replay verifier"
        )
    verification = _object(
        model_header["verification"],
        "structural score report.model.verification",
        {
            "status",
            "payloadDigestVerified",
            "identityMapPayloadDigestVerified",
            "adapterReplayVerified",
            "productionVerified",
        },
    )
    fixture_verification = {
        "status": "fixture-digest-only",
        "payloadDigestVerified": True,
        "identityMapPayloadDigestVerified": True,
        "adapterReplayVerified": False,
        "productionVerified": False,
    }
    _string(
        verification["status"],
        "structural score report.model.verification.status",
        maximum=64,
    )
    for key in (
        "payloadDigestVerified",
        "identityMapPayloadDigestVerified",
        "adapterReplayVerified",
        "productionVerified",
    ):
        _boolean(
            verification[key],
            f"structural score report.model.verification.{key}",
        )
    if verification != fixture_verification:
        raise StructuralScoringError("structural score verification contradicts its evidence scope")
    mapping_header = _object(
        root["identityMapping"],
        "structural score report.identityMapping",
        {"id", "sha256", "mappingCount", "verification", "productionVerified"},
    )
    _identifier(mapping_header["id"], "structural score report.identityMapping.id")
    _sha256(mapping_header["sha256"], "structural score report.identityMapping.sha256")
    mapping_count = _integer(
        mapping_header["mappingCount"],
        "structural score report.identityMapping.mappingCount",
        maximum=MAX_MAPPINGS,
    )
    if (
        mapping_header.get("verification") != "fixture-payload-digest-only"
        or mapping_header.get("productionVerified") is not False
    ):
        raise StructuralScoringError("identity-map verification contradicts the report scope")
    manifest = oracle_header.get("artifactManifestSha256")
    if manifest is not None:
        raise StructuralScoringError("oracle manifest provenance contradicts the report scope")

    target_binding = _object(
        root["targetAbi"],
        "structural score report.targetAbi",
        {"id", "sha256"},
    )
    target_identifier = _identifier(
        target_binding["id"],
        "structural score report.targetAbi.id",
    )
    if (
        target_identifier != target.identifier
        or _sha256(
            target_binding["sha256"],
            "structural score report.targetAbi.sha256",
        )
        != target.snapshot.sha256
    ):
        raise StructuralScoringError(
            "structural score target binding does not match the supplied descriptor"
        )
    normalization_profile = _validate_normalization_profile(
        root["normalizationProfile"],
        "structural score report.normalizationProfile",
    )
    provenance = _object(
        model_header["provenance"],
        "structural score report.model.provenance",
        {
            "inputBinary",
            "exporter",
            "loader",
            "targetAbi",
            "normalizationProfile",
            "boundaryScore",
            "identityMap",
        },
    )
    boundary_header = _object(
        root["boundaryMapping"],
        "structural score report.boundaryMapping",
        {"scoreSha256", "twin", "projectionAdapter", "selectedFunctionCount"},
    )
    _sha256(
        boundary_header["scoreSha256"],
        "structural score report.boundaryMapping.scoreSha256",
    )
    boundary_twin = _string(
        boundary_header["twin"],
        "structural score report.boundaryMapping.twin",
        maximum=32,
    )
    if boundary_twin not in {"rich", "stripped"}:
        raise StructuralScoringError("structural score boundary twin is invalid")
    selected_function_count = _integer(
        boundary_header["selectedFunctionCount"],
        "structural score report.boundaryMapping.selectedFunctionCount",
        maximum=MAX_MAPPINGS,
    )
    projection_header = _object(
        boundary_header["projectionAdapter"],
        "structural score report.boundaryMapping.projectionAdapter",
        {"id", "version", "objectFormat"},
    )
    expected_projection = {
        "id": BOUNDARY_PROJECTION_ADAPTER_ID,
        "version": BOUNDARY_PROJECTION_ADAPTER_VERSION,
        "objectFormat": target.object_format,
    }
    if projection_header != expected_projection or target.object_format != "ELF":
        raise StructuralScoringError(
            "structural score projection adapter does not match the supplied target"
        )
    input_binary = _object(
        provenance["inputBinary"],
        "structural score report.model.provenance.inputBinary",
        {"sha256", "sizeBytes"},
    )
    _sha256(
        input_binary["sha256"],
        "structural score report.model.provenance.inputBinary.sha256",
    )
    _integer(
        input_binary["sizeBytes"],
        "structural score report.model.provenance.inputBinary.sizeBytes",
        minimum=1,
    )
    _validate_tool_identity(
        provenance["exporter"],
        "structural score report.model.provenance.exporter",
    )
    loader = _object(
        provenance["loader"],
        "structural score report.model.provenance.loader",
        {"id", "version", "executableSha256", "configurationSha256", "imageBase"},
    )
    _validate_tool_identity(
        {key: loader[key] for key in ("id", "version", "executableSha256", "configurationSha256")},
        "structural score report.model.provenance.loader",
    )
    _address(
        loader["imageBase"],
        "structural score report.model.provenance.loader.imageBase",
        maximum=target.maximum_address,
    )
    provenance_target = _object(
        provenance["targetAbi"],
        "structural score report.model.provenance.targetAbi",
        {"id", "sha256"},
    )
    provenance_boundary = _object(
        provenance["boundaryScore"],
        "structural score report.model.provenance.boundaryScore",
        {"sha256", "twin", "projectionAdapter"},
    )
    provenance_projection = _object(
        provenance_boundary["projectionAdapter"],
        "structural score report.model.provenance.boundaryScore.projectionAdapter",
        {"id", "version"},
    )
    provenance_identity = _object(
        provenance["identityMap"],
        "structural score report.model.provenance.identityMap",
        {"sha256"},
    )
    if provenance_target != target_binding:
        raise StructuralScoringError("structural report target provenance is internally inconsistent")
    provenance_normalization_profile = _validate_normalization_profile(
        provenance["normalizationProfile"],
        "structural score report.model.provenance.normalizationProfile",
    )
    if provenance_normalization_profile != normalization_profile:
        raise StructuralScoringError(
            "structural report normalization-profile provenance is internally inconsistent"
        )
    if provenance_boundary != {
        "sha256": boundary_header.get("scoreSha256"),
        "twin": boundary_header.get("twin"),
        "projectionAdapter": {
            "id": projection_header.get("id"),
            "version": projection_header.get("version"),
        },
    }:
        raise StructuralScoringError("structural report boundary provenance is internally inconsistent")
    if provenance_projection != {
        "id": BOUNDARY_PROJECTION_ADAPTER_ID,
        "version": BOUNDARY_PROJECTION_ADAPTER_VERSION,
    }:
        raise StructuralScoringError(
            "structural report boundary adapter provenance is internally inconsistent"
        )
    if provenance_identity != {"sha256": mapping_header.get("sha256")}:
        raise StructuralScoringError("structural report identity-map provenance is internally inconsistent")

    policy = _object(
        root["policy"],
        "structural score report.policy",
        {"identitySelection", "abiEquivalence", "sourceNormalization", "outcomeLattice", "limits"},
    )
    for key in ("identitySelection", "abiEquivalence", "sourceNormalization"):
        _string(
            policy[key],
            f"structural score report.policy.{key}",
            maximum=4096,
        )
    limits = _object(
        policy["limits"],
        "structural score report.policy.limits",
        _report_limits(),
    )
    for key, value in limits.items():
        _integer(value, f"structural score report.policy.limits.{key}", minimum=1)
    expected_policy = {
        "identitySelection": IDENTITY_SELECTION_POLICY,
        "abiEquivalence": ABI_EQUIVALENCE_POLICY,
        "sourceNormalization": SOURCE_NORMALIZATION_POLICY,
        "outcomeLattice": list(OUTCOMES),
        "limits": _report_limits(),
    }
    if policy != expected_policy:
        raise StructuralScoringError(
            "structural score report policy does not match the checked scorer contract"
        )

    dimensions = _array(root["dimensions"], "structural score report.dimensions", len(DIMENSIONS), minimum=len(DIMENSIONS))
    if [item.get("dimension") if isinstance(item, dict) else None for item in dimensions] != list(DIMENSIONS):
        raise StructuralScoringError("structural score report must contain every dimension exactly once in order")
    for index, expected_dimension in enumerate(DIMENSIONS):
        _validate_report_metric(
            dimensions[index],
            f"structural score report.dimensions[{index}]",
            dimension=expected_dimension,
        )
    _validate_report_metric(root["aggregate"], "structural score report.aggregate")
    entities = _array(
        root["entities"],
        "structural score report.entities",
        MAX_TOTAL_ENTITIES,
        minimum=1,
    )
    validated_entities: list[dict[str, Any]] = []
    seen_oracle_entities: set[tuple[str, str]] = set()
    seen_recovered_entities: set[tuple[str, str]] = set()
    recovered_to_oracle: dict[tuple[str, str], str] = {}
    previous_entity_key: tuple[str, str, str] | None = None
    total_facts = 0
    total_evidence = 0
    for entity_index, raw_entity in enumerate(entities):
        entity_path = f"structural score report.entities[{entity_index}]"
        entity = _object(raw_entity, entity_path, {"kind", "oracleId", "recoveredId", "metric", "facts"})
        kind = _string(entity["kind"], f"{entity_path}.kind", maximum=32)
        if kind not in {"function", "global", "type"}:
            raise StructuralScoringError(f"{entity_path}.kind is invalid")
        if entity["oracleId"] is None and entity["recoveredId"] is None:
            raise StructuralScoringError(f"{entity_path} has no stable identity")
        oracle_id = None
        recovered_id = None
        if entity["oracleId"] is not None:
            oracle_id = _identifier(entity["oracleId"], f"{entity_path}.oracleId")
            oracle_key = (kind, oracle_id)
            if oracle_key in seen_oracle_entities:
                raise StructuralScoringError(
                    "structural score report duplicates an oracle entity identity"
                )
            seen_oracle_entities.add(oracle_key)
        if entity["recoveredId"] is not None:
            recovered_id = _identifier(entity["recoveredId"], f"{entity_path}.recoveredId")
            recovered_key = (kind, recovered_id)
            if recovered_key in seen_recovered_entities:
                raise StructuralScoringError(
                    "structural score report duplicates a recovered entity identity"
                )
            seen_recovered_entities.add(recovered_key)
        entity_key = (kind, oracle_id or "", recovered_id or "")
        if previous_entity_key is not None and entity_key <= previous_entity_key:
            raise StructuralScoringError(
                "structural score report entities are not in canonical order"
            )
        previous_entity_key = entity_key
        if oracle_id is not None and recovered_id is not None:
            recovered_to_oracle[(kind, recovered_id)] = oracle_id
        _validate_report_metric(entity["metric"], f"{entity_path}.metric")
        facts = _array(entity["facts"], f"{entity_path}.facts", MAX_FACTS_PER_ENTITY, minimum=1)
        total_facts += len(facts)
        if total_facts > MAX_REPORT_ENTRIES:
            raise StructuralScoringError(
                "structural score report exceeds the aggregate fact limit"
            )
        seen_oracle_fact_ids: set[str] = set()
        seen_recovered_fact_ids: set[str] = set()
        seen_fact_slots: set[tuple[str, str]] = set()
        previous_fact_key: tuple[str, str, str] | None = None
        for fact_index, fact in enumerate(facts):
            fact_path = f"{entity_path}.facts[{fact_index}]"
            if not isinstance(fact, dict):
                raise StructuralScoringError(f"{fact_path} must be an object")
            dimension = fact.get("dimension")
            outcome = fact.get("outcome")
            if dimension not in DIMENSIONS or outcome not in OUTCOMES:
                raise StructuralScoringError(
                    f"{fact_path} uses an unsupported dimension or outcome"
                )
            slot = _identifier(fact.get("slot"), f"{fact_path}.slot")
            fact_slot = (dimension, slot)
            if fact_slot in seen_fact_slots:
                raise StructuralScoringError(
                    f"{entity_path} duplicates a fact dimension and slot"
                )
            seen_fact_slots.add(fact_slot)
            fact_key = (dimension, slot, outcome)
            if previous_fact_key is not None and fact_key <= previous_fact_key:
                raise StructuralScoringError(
                    f"{entity_path}.facts are not in canonical order"
                )
            previous_fact_key = fact_key
            for id_key, seen_ids in (
                ("oracleFactId", seen_oracle_fact_ids),
                ("recoveredFactId", seen_recovered_fact_ids),
            ):
                fact_id = fact.get(id_key)
                if fact_id is None:
                    continue
                normalized_fact_id = _identifier(fact_id, f"{fact_path}.{id_key}")
                if normalized_fact_id in seen_ids:
                    raise StructuralScoringError(
                        f"{entity_path} duplicates {id_key}"
                    )
                seen_ids.add(normalized_fact_id)
            for evidence_key in ("oracleEvidence", "recoveredEvidence"):
                evidence = _array(
                    fact.get(evidence_key),
                    f"{fact_path}.{evidence_key}",
                    MAX_EVIDENCE_PER_FACT,
                )
                total_evidence += len(evidence)
                if total_evidence > MAX_TOTAL_EVIDENCE:
                    raise StructuralScoringError(
                        "structural score report exceeds the aggregate evidence limit"
                    )
        validated_entities.append(entity)

    oracle_entity_universe = frozenset(seen_oracle_entities)
    recovered_entity_universe = frozenset(seen_recovered_entities)
    report_selected_function_count = sum(
        entity["kind"] == "function"
        and entity["oracleId"] is not None
        and entity["recoveredId"] is not None
        for entity in validated_entities
    )
    report_identity_mapping_count = sum(
        entity["kind"] in {"global", "type"}
        and entity["oracleId"] is not None
        and entity["recoveredId"] is not None
        for entity in validated_entities
    )
    if selected_function_count != report_selected_function_count:
        raise StructuralScoringError(
            "structural score selected-function count disagrees with its entity rows"
        )
    if mapping_count != report_identity_mapping_count:
        raise StructuralScoringError(
            "structural score identity-mapping count disagrees with its entity rows"
        )
    for entity_index, entity in enumerate(validated_entities):
        entity_path = f"structural score report.entities[{entity_index}]"
        facts = entity["facts"]
        for fact_index, fact in enumerate(facts):
            _validate_report_fact_result(
                fact,
                f"{entity_path}.facts[{fact_index}]",
                entity_kind=entity["kind"],
                recovered_to_oracle=recovered_to_oracle,
                oracle_entity_ids=oracle_entity_universe,
                recovered_entity_ids=recovered_entity_universe,
                target=target,
            )
        if entity["metric"] != _metric_for_facts(facts):
            raise StructuralScoringError(f"{entity_path}.metric does not match its fact rows")
    for dimension, metric in zip(DIMENSIONS, dimensions, strict=True):
        expected = _metric_for_dimension(dimension, validated_entities)
        if metric != expected:
            raise StructuralScoringError(f"structural score metric for {dimension} is inconsistent")
    if root["aggregate"] != _metric_for_dimension(None, validated_entities):
        raise StructuralScoringError("structural score aggregate is inconsistent")


def canonical_report_bytes(
    report: Mapping[str, Any],
    *,
    target: TargetAbiDescriptor,
) -> bytes:
    validate_structural_score_report(report, target=target)
    try:
        return (
            json.dumps(
                report,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, MemoryError) as error:
        raise StructuralScoringError(f"cannot encode structural score report: {error}") from error


def write_report_atomic(
    path: Path,
    report: Mapping[str, Any],
    *,
    target: TargetAbiDescriptor,
) -> None:
    data = canonical_report_bytes(report, target=target)
    if len(data) > MAX_REPORT_BYTES:
        raise StructuralScoringError("structural score report exceeds the output limit")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def render_summary(report: Mapping[str, Any]) -> str:
    aggregate = report["aggregate"]
    lines = [
        f"[FIXTURE; NOT PRODUCTION VERIFIED] structural recovery: {report['oracle']['id']}",
        (
            f"facts: oracle {aggregate['oracleDenominator']}; recovered "
            f"{aggregate['recoveredDenominator']}; credit "
            f"{aggregate['credit']['numerator']}/{aggregate['credit']['denominator']}"
        ),
    ]
    for metric in report["dimensions"]:
        outcomes = metric["outcomes"]
        lines.append(
            f"{metric['dimension']}: exact {outcomes['exact']}; ABI-equivalent "
            f"{outcomes['abi-equivalent']}; unknown {outcomes['recovered-unknown']}; "
            f"unobservable {outcomes['oracle-unobservable']}; contradicted "
            f"{outcomes['contradicted']}; fabricated {outcomes['fabricated']}"
        )
    return "\n".join(lines)


def fixture_attestation_payload_sha256(document: Mapping[str, Any]) -> str:
    """Return the digest used by checked fixture attestations.

    This helper does not authenticate production evidence and must not be used
    by a production adapter.
    """

    return hashlib.sha256(_canonical_payload(document)).hexdigest()
