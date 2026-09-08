"""Program-agnostic function-boundary and name scoring for paired models.

The scorer deliberately consumes a reviewed, normalized DWARF/symbol oracle
instead of guessing ground truth from recovered names.  Oracle functions are
addressed by RVA; each recovered program-model address is converted to that
domain by subtracting an explicit scorer input.  Production schema-v1 models
do not carry loader metadata, so that input must equal the manifest-derived
ELF image base; fixture inputs may exercise deliberate relocation.

ELF-backed adapters can authenticate the recorded artifact metadata, but no
compiler or benchmark identity participates in matching or metric semantics.
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping, Sequence


_SHA256 = re.compile(r"[0-9a-f]{64}")
_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})")
_MAX_ADDRESS = (1 << 64) - 1
_TWIN_NAMES = ("rich", "stripped")
_EVIDENCE_KINDS = {"dwarf-subprogram", "elf-symbol"}
_AVAILABILITY = {"surviving", "removed", "not-observable"}
_EXCLUSION_KINDS = {"compiler-generated", "inlined"}
_RECOVERY_STATUSES = {"recovered", "partial", "failed", "synthetic"}

# These are availability limits, not expected corpus sizes.  They keep malformed
# inputs from turning a measurement command into unbounded memory or output work.
MAX_JSON_INPUT_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SUPPORTING_INPUT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_FUNCTION_RECORDS = 20_000
MAX_ALIASES_PER_FUNCTION = 256
MAX_EVIDENCE_PER_ALIAS = 256
MAX_MODEL_REFERENCES_PER_FUNCTION = 100_000
MAX_MODEL_GLOBALS_OR_TYPES = 1_000_000
MAX_TEXT_CHARACTERS = 16 * 1024 * 1024
MAX_MATCHING_CELLS = 20_000_000
MAX_AMBIGUITY_EDGES = 100_000
MAX_IDENTIFIER_CHARACTERS = 4096
MAX_EVIDENCE_LOCATOR_CHARACTERS = 16_384
MAX_REASON_CHARACTERS = 16_384
MAX_JSON_NUMBER_CHARACTERS = 128
MAX_JSON_NUMBER_MAGNITUDE = (1 << 64) - 1


class ScoringError(ValueError):
    """Raised when scoring inputs cannot support an unambiguous score."""


@dataclass(frozen=True)
class ExecutableRange:
    start: int
    end_exclusive: int


@dataclass(frozen=True)
class Evidence:
    kind: str
    locator: str


@dataclass(frozen=True)
class OracleAlias:
    name: str
    evidence: tuple[Evidence, ...]
    availability: Mapping[str, str]


@dataclass(frozen=True)
class Artifact:
    input_sha256: str
    elf_type: str
    elf_image_base: int
    executable_ranges: tuple[ExecutableRange, ...]


@dataclass(frozen=True)
class Exclusion:
    kind: str
    reason: str


@dataclass(frozen=True)
class OracleFunction:
    identifier: str
    rva: int | None
    aliases: tuple[OracleAlias, ...]
    exclusion: Exclusion | None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(alias.name for alias in self.aliases)


@dataclass(frozen=True)
class FunctionOracle:
    scope: str
    identifier: str
    artifact_manifest_sha256: str | None
    artifacts: Mapping[str, Artifact]
    near_miss_bytes: int
    functions: tuple[OracleFunction, ...]


@dataclass(frozen=True)
class RecoveredFunction:
    identifier: str
    name: str
    rva: int
    status: str


@dataclass(frozen=True)
class RecoveredModel:
    input_sha256: str
    image_base: int
    functions: tuple[RecoveredFunction, ...]


@dataclass(frozen=True)
class NearAssignment:
    matches: tuple[tuple[OracleFunction, RecoveredFunction], ...]
    false_negatives: tuple[OracleFunction, ...]
    false_positives: tuple[RecoveredFunction, ...]
    total_distance_bytes: int
    optimal_candidate_edges: tuple[tuple[OracleFunction, RecoveredFunction], ...]


_CONTEXT_GUARD = object()


@dataclass(frozen=True, init=False)
class _ScoringContext:
    status: str
    artifact_manifest_verified: bool
    program_model_provenance: str
    production_verified: bool

    def __init__(
        self,
        guard: object,
        *,
        status: str,
        artifact_manifest_verified: bool,
        program_model_provenance: str,
        production_verified: bool,
    ) -> None:
        if guard is not _CONTEXT_GUARD:
            raise ScoringError("scoring verification contexts are internal")
        object.__setattr__(self, "status", status)
        object.__setattr__(
            self,
            "artifact_manifest_verified",
            artifact_manifest_verified,
        )
        object.__setattr__(
            self,
            "program_model_provenance",
            program_model_provenance,
        )
        object.__setattr__(self, "production_verified", production_verified)


def _fixture_context() -> _ScoringContext:
    return _ScoringContext(
        _CONTEXT_GUARD,
        status="fixture-non-production",
        artifact_manifest_verified=False,
        program_model_provenance="fixture-inputs",
        production_verified=False,
    )


def _artifact_verified_unattested_model_context() -> _ScoringContext:
    return _ScoringContext(
        _CONTEXT_GUARD,
        status="artifact-verified-model-unattested",
        artifact_manifest_verified=True,
        program_model_provenance="unattested-schema-v1",
        production_verified=False,
    )


def _object(value: Any, path: str, fields: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScoringError(f"{path} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        details: list[str] = []
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        if missing:
            details.append(f"missing {missing}")
        if unexpected:
            details.append(f"unexpected {unexpected}")
        raise ScoringError(f"{path} has invalid fields: {', '.join(details)}")
    return value


def _array(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    maximum: int | None = None,
) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty array" if nonempty else "an array"
        raise ScoringError(f"{path} must be {qualifier}")
    if maximum is not None and len(value) > maximum:
        raise ScoringError(f"{path} exceeds the limit of {maximum} entries")
    return value


def _string(
    value: Any,
    path: str,
    *,
    allow_empty: bool = False,
    maximum: int = MAX_TEXT_CHARACTERS,
) -> str:
    if (
        not isinstance(value, str)
        or "\x00" in value
        or (not allow_empty and not value)
        or len(value) > maximum
    ):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ScoringError(
            f"{path} must be {qualifier} without NUL bytes and at most {maximum} characters"
        )
    return value


def _integer(value: Any, path: str, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise ScoringError(
            f"{path} must be an integer between {minimum} and {maximum}"
        )
    return value


def _nullable_sha256(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, path)


def _sha256(value: Any, path: str) -> str:
    text = _string(value, path)
    if _SHA256.fullmatch(text) is None:
        raise ScoringError(f"{path} must be a lowercase SHA-256")
    return text


def _address(value: Any, path: str) -> int:
    text = _string(value, path)
    if _ADDRESS.fullmatch(text) is None:
        raise ScoringError(
            f"{path} must be a canonical lowercase hexadecimal address"
        )
    parsed = int(text[2:], 16)
    if parsed > _MAX_ADDRESS:
        raise ScoringError(f"{path} exceeds an unsigned 64-bit address")
    return parsed


def _nullable_address(value: Any, path: str) -> int | None:
    if value is None:
        return None
    return _address(value, path)


def _read_regular_snapshot(
    path: Path,
    label: str,
    maximum_bytes: int,
) -> bytes | bytearray:
    """Read one bounded regular-file snapshot through a single descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        if path.is_symlink():
            raise ScoringError(f"{label} is not a non-symlink regular file: {path}")
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ScoringError(f"{label} is not a non-symlink regular file: {path}")
        if before.st_size > maximum_bytes:
            raise ScoringError(
                f"{label} exceeds the {maximum_bytes}-byte input limit"
            )
        # Read directly into one exactly sized buffer.  The former chunk-list
        # plus join briefly retained two complete copies of every large model.
        payload = bytearray(before.st_size)
        view = memoryview(payload)
        total = 0
        try:
            while total < len(payload):
                read = os.readv(descriptor, [view[total:]])
                if read == 0:
                    break
                total += read
        finally:
            view.release()
        grew = bool(os.read(descriptor, 1))
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            identity_before != identity_after
            or total != after.st_size
            or grew
        ):
            raise ScoringError(f"{label} changed while its snapshot was read")
        return payload
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            f"not enough memory to read the bounded {label} snapshot"
        ) from error
    except OSError as error:
        raise ScoringError(f"cannot read {label} {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _decode_json(payload: bytes | bytearray, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ScoringError(f"duplicate JSON object key in {label}: {key}")
            result[key] = value
        return result

    def parse_integer(token: str) -> int:
        digits = token[1:] if token.startswith("-") else token
        maximum = str(MAX_JSON_NUMBER_MAGNITUDE)
        if (
            len(token) > MAX_JSON_NUMBER_CHARACTERS
            or len(digits) > len(maximum)
            or (len(digits) == len(maximum) and digits > maximum)
        ):
            raise ScoringError(
                f"JSON integer magnitude is too large in {label}"
            )
        return int(token, 10)

    def parse_float(token: str) -> float:
        if len(token) > MAX_JSON_NUMBER_CHARACTERS:
            raise ScoringError(f"JSON float token is too long in {label}")
        try:
            decimal_value = Decimal(token)
        except InvalidOperation as error:
            raise ScoringError(f"invalid JSON float in {label}") from error
        if (
            not decimal_value.is_finite()
            or abs(decimal_value) > Decimal(MAX_JSON_NUMBER_MAGNITUDE)
        ):
            raise ScoringError(f"JSON float magnitude is too large in {label}")
        parsed = float(decimal_value)
        if not math.isfinite(parsed):
            raise ScoringError(f"non-finite JSON float in {label}")
        return parsed

    def reject_constant(token: str) -> float:
        raise ScoringError(
            f"non-finite JSON constant {token!r} is not permitted in {label}"
        )

    try:
        text = payload.decode("utf-8")
        del payload
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_int=parse_integer,
            parse_float=parse_float,
            parse_constant=reject_constant,
        )
    except ScoringError:
        raise
    except UnicodeDecodeError as error:
        raise ScoringError(f"invalid UTF-8 in {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise ScoringError(f"invalid JSON in {label}: {error}") from error
    except (OverflowError, ValueError) as error:
        raise ScoringError(f"invalid bounded JSON value in {label}: {error}") from error
    except RecursionError as error:
        raise ScoringError(f"JSON nesting is too deep in {label}") from error
    except MemoryError as error:
        raise ScoringError(
            f"not enough memory to decode bounded JSON in {label}"
        ) from error
    if not isinstance(value, dict):
        raise ScoringError(f"{label} root must be an object")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    return _decode_json(
        _read_regular_snapshot(path, label, MAX_JSON_INPUT_BYTES),
        label,
    )


def _parse_evidence(value: Any, path: str) -> tuple[Evidence, ...]:
    evidence: list[Evidence] = []
    evidence_keys: set[tuple[str, str]] = set()
    for index, raw_evidence in enumerate(
        _array(
            value,
            path,
            nonempty=True,
            maximum=MAX_EVIDENCE_PER_ALIAS,
        )
    ):
        evidence_path = f"{path}[{index}]"
        item = _object(raw_evidence, evidence_path, {"kind", "locator"})
        kind = _string(item["kind"], f"{evidence_path}.kind", maximum=64)
        if kind not in _EVIDENCE_KINDS:
            raise ScoringError(
                f"{evidence_path}.kind must identify DWARF or ELF symbol evidence"
            )
        locator = _string(
            item["locator"],
            f"{evidence_path}.locator",
            maximum=MAX_EVIDENCE_LOCATOR_CHARACTERS,
        )
        key = (kind, locator)
        if key in evidence_keys:
            raise ScoringError(f"{path} contains duplicates")
        evidence_keys.add(key)
        evidence.append(Evidence(kind=kind, locator=locator))
    return tuple(sorted(evidence, key=lambda fact: (fact.kind, fact.locator)))


def _contains_rva(artifact: Artifact, rva: int) -> bool:
    return any(
        executable.start <= rva < executable.end_exclusive
        for executable in artifact.executable_ranges
    )


def load_function_oracle(path: Path) -> FunctionOracle:
    """Load and cross-validate the closed function-oracle format."""

    root = _object(
        _load_json(path, "function oracle"),
        "function oracle",
        {"schemaVersion", "scope", "oracle", "artifacts", "scoringPolicy", "functions"},
    )
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise ScoringError("function oracle.schemaVersion must be the integer 1")

    scope = _string(root["scope"], "function oracle.scope")
    if scope not in {"fixture", "production"}:
        raise ScoringError("function oracle.scope must be fixture or production")

    oracle_record = _object(
        root["oracle"],
        "function oracle.oracle",
        {"id", "source", "artifactManifestSha256"},
    )
    identifier = _string(
        oracle_record["id"],
        "function oracle.oracle.id",
        maximum=MAX_IDENTIFIER_CHARACTERS,
    )
    if oracle_record["source"] != "dwarf-and-symbols":
        raise ScoringError(
            "function oracle.oracle.source must be dwarf-and-symbols"
        )
    manifest_sha256 = _nullable_sha256(
        oracle_record["artifactManifestSha256"],
        "function oracle.oracle.artifactManifestSha256",
    )
    if scope == "production" and manifest_sha256 is None:
        raise ScoringError(
            "production function oracle must bind artifactManifestSha256"
        )
    if scope == "fixture" and manifest_sha256 is not None:
        raise ScoringError(
            "fixture function oracle must not claim a production artifact manifest"
        )

    artifact_records = _object(
        root["artifacts"],
        "function oracle.artifacts",
        set(_TWIN_NAMES),
    )
    artifacts: dict[str, Artifact] = {}
    for twin in _TWIN_NAMES:
        item = _object(
            artifact_records[twin],
            f"function oracle.artifacts.{twin}",
            {"inputSha256", "elfType", "elfImageBase", "executableRvaRanges"},
        )
        item_path = f"function oracle.artifacts.{twin}"
        elf_type = _string(item["elfType"], f"{item_path}.elfType", maximum=16)
        if elf_type not in {"ET_EXEC", "ET_DYN"}:
            raise ScoringError(f"{item_path}.elfType must be ET_EXEC or ET_DYN")
        ranges: list[ExecutableRange] = []
        for range_index, raw_range in enumerate(
            _array(
                item["executableRvaRanges"],
                f"{item_path}.executableRvaRanges",
                nonempty=True,
                maximum=256,
            )
        ):
            range_path = f"{item_path}.executableRvaRanges[{range_index}]"
            range_record = _object(
                raw_range,
                range_path,
                {"start", "endExclusive"},
            )
            start = _address(range_record["start"], f"{range_path}.start")
            end_exclusive = _address(
                range_record["endExclusive"],
                f"{range_path}.endExclusive",
            )
            if start >= end_exclusive:
                raise ScoringError(f"{range_path} must be a non-empty increasing range")
            if ranges and start < ranges[-1].end_exclusive:
                raise ScoringError(
                    f"{item_path}.executableRvaRanges must be sorted and non-overlapping"
                )
            ranges.append(ExecutableRange(start=start, end_exclusive=end_exclusive))
        artifacts[twin] = Artifact(
            input_sha256=_sha256(
                item["inputSha256"],
                f"{item_path}.inputSha256",
            ),
            elf_type=elf_type,
            elf_image_base=_address(
                item["elfImageBase"],
                f"{item_path}.elfImageBase",
            ),
            executable_ranges=tuple(ranges),
        )
    if artifacts["rich"].input_sha256 == artifacts["stripped"].input_sha256:
        raise ScoringError("rich and stripped artifact hashes must differ")
    for field in ("elf_type", "elf_image_base", "executable_ranges"):
        if getattr(artifacts["rich"], field) != getattr(artifacts["stripped"], field):
            raise ScoringError(f"rich and stripped artifact {field} metadata must match")

    policy = _object(
        root["scoringPolicy"],
        "function oracle.scoringPolicy",
        {"nearMissBytes"},
    )
    near_miss_bytes = _integer(
        policy["nearMissBytes"],
        "function oracle.scoringPolicy.nearMissBytes",
        minimum=1,
        maximum=4096,
    )

    functions: list[OracleFunction] = []
    identifiers: set[str] = set()
    scored_rvas: set[int] = set()
    excluded_rvas: set[int] = set()
    for index, raw_function in enumerate(
        _array(
            root["functions"],
            "function oracle.functions",
            nonempty=True,
            maximum=MAX_FUNCTION_RECORDS,
        )
    ):
        item_path = f"function oracle.functions[{index}]"
        item = _object(
            raw_function,
            item_path,
            {"id", "rva", "aliases", "exclusion"},
        )
        function_id = _string(
            item["id"],
            f"{item_path}.id",
            maximum=MAX_IDENTIFIER_CHARACTERS,
        )
        if function_id in identifiers:
            raise ScoringError(f"duplicate function oracle id: {function_id}")
        identifiers.add(function_id)

        aliases: list[OracleAlias] = []
        alias_names: set[str] = set()
        for alias_index, raw_alias in enumerate(
            _array(
                item["aliases"],
                f"{item_path}.aliases",
                nonempty=True,
                maximum=MAX_ALIASES_PER_FUNCTION,
            )
        ):
            alias_path = f"{item_path}.aliases[{alias_index}]"
            alias_record = _object(
                raw_alias,
                alias_path,
                {"name", "evidence", "availability"},
            )
            alias_name = _string(alias_record["name"], f"{alias_path}.name", maximum=4096)
            if alias_name in alias_names:
                raise ScoringError(f"{item_path}.aliases contains duplicate name {alias_name!r}")
            alias_names.add(alias_name)
            availability_record = _object(
                alias_record["availability"],
                f"{alias_path}.availability",
                set(_TWIN_NAMES),
            )
            availability: dict[str, str] = {}
            for twin in _TWIN_NAMES:
                availability_value = _string(
                    availability_record[twin],
                    f"{alias_path}.availability.{twin}",
                    maximum=32,
                )
                if availability_value not in _AVAILABILITY:
                    raise ScoringError(
                        f"{alias_path}.availability.{twin} has an invalid value"
                    )
                availability[twin] = availability_value
            aliases.append(
                OracleAlias(
                    name=alias_name,
                    evidence=_parse_evidence(alias_record["evidence"], f"{alias_path}.evidence"),
                    availability=availability,
                )
            )

        rva = _nullable_address(item["rva"], f"{item_path}.rva")
        exclusion: Exclusion | None
        if item["exclusion"] is None:
            exclusion = None
            if rva is None:
                raise ScoringError(f"scoreable {item_path} must have an RVA")
            for alias in aliases:
                if alias.availability["rich"] != "surviving":
                    raise ScoringError(
                        f"scoreable alias {alias.name!r} must be surviving in the rich twin"
                    )
                if alias.availability["stripped"] == "not-observable":
                    raise ScoringError(
                        f"scoreable alias {alias.name!r} must be surviving or removed "
                        "in the stripped twin"
                    )
            if not _contains_rva(artifacts["rich"], rva):
                raise ScoringError(f"scoreable {item_path}.rva is outside executable ranges")
            if rva in scored_rvas:
                raise ScoringError(
                    f"multiple scoreable functions share RVA {hex(rva)}; "
                    "group aliases in one record"
                )
            scored_rvas.add(rva)
        else:
            exclusion_record = _object(
                item["exclusion"],
                f"{item_path}.exclusion",
                {"kind", "reason"},
            )
            exclusion_kind = _string(
                exclusion_record["kind"],
                f"{item_path}.exclusion.kind",
            )
            if exclusion_kind not in _EXCLUSION_KINDS:
                raise ScoringError(f"{item_path}.exclusion.kind has an invalid value")
            exclusion = Exclusion(
                kind=exclusion_kind,
                reason=_string(
                    exclusion_record["reason"],
                    f"{item_path}.exclusion.reason",
                    maximum=MAX_REASON_CHARACTERS,
                ),
            )
            if exclusion_kind == "inlined" and rva is not None:
                raise ScoringError(
                    f"inlined {item_path} must use null RVA; it has no emitted function start"
                )
            if exclusion_kind == "compiler-generated" and rva is None:
                raise ScoringError(
                    f"compiler-generated {item_path} must identify its emitted RVA"
                )
            if rva is not None:
                if not _contains_rva(artifacts["rich"], rva):
                    raise ScoringError(f"excluded {item_path}.rva is outside executable ranges")
                if rva in excluded_rvas:
                    raise ScoringError(f"multiple exclusions share RVA {hex(rva)}")
                excluded_rvas.add(rva)

        functions.append(
            OracleFunction(
                identifier=function_id,
                rva=rva,
                aliases=tuple(sorted(aliases, key=lambda alias: alias.name)),
                exclusion=exclusion,
            )
        )

    overlap = scored_rvas & excluded_rvas
    if overlap:
        raise ScoringError(
            "scoreable and compiler-generated functions share RVA "
            f"{hex(min(overlap))}"
        )
    if not scored_rvas:
        raise ScoringError("function oracle must contain at least one scoreable function")
    evidence_kinds = {
        fact.kind
        for function in functions
        for alias in function.aliases
        for fact in alias.evidence
    }
    if evidence_kinds != _EVIDENCE_KINDS:
        raise ScoringError(
            "function oracle must retain both DWARF subprogram and ELF symbol evidence"
        )

    return FunctionOracle(
        scope=scope,
        identifier=identifier,
        artifact_manifest_sha256=manifest_sha256,
        artifacts=artifacts,
        near_miss_bytes=near_miss_bytes,
        functions=tuple(
            sorted(
                functions,
                key=lambda function: (
                    function.rva is None,
                    function.rva if function.rva is not None else 0,
                    function.identifier,
                ),
            )
        ),
    )


def _string_array(
    value: Any,
    path: str,
    *,
    maximum_characters: int = MAX_IDENTIFIER_CHARACTERS,
) -> None:
    for index, item in enumerate(
        _array(value, path, maximum=MAX_MODEL_REFERENCES_PER_FUNCTION)
    ):
        _string(
            item,
            f"{path}[{index}]",
            allow_empty=True,
            maximum=maximum_characters,
        )


def load_program_model(
    path: Path,
    *,
    twin: str,
    artifact: Artifact,
    model_image_base: int,
) -> RecoveredModel:
    """Project schema-1/2 model functions into diagnostic boundary/name inputs."""

    if twin not in _TWIN_NAMES:
        raise ScoringError(f"unknown twin: {twin}")
    if (
        isinstance(model_image_base, bool)
        or not isinstance(model_image_base, int)
        or model_image_base < 0
        or model_image_base > _MAX_ADDRESS
    ):
        raise ScoringError(f"{twin} model image base must be an unsigned 64-bit integer")
    root = _object(
        _load_json(path, f"{twin} program model"),
        f"{twin} program model",
        {"schemaVersion", "inputSha256", "functions", "globals", "types"},
    )
    model_version = root["schemaVersion"]
    if type(model_version) is not int or model_version not in (1, 2):
        raise ScoringError(f"{twin} program model.schemaVersion must be the integer 1 or 2")
    status_field = "status" if model_version == 1 else "extractionStatus"
    input_sha256 = _sha256(
        root["inputSha256"],
        f"{twin} program model.inputSha256",
    )
    if input_sha256 != artifact.input_sha256:
        raise ScoringError(
            f"{twin} program model input SHA-256 does not match its oracle artifact"
        )
    globals_records = _array(
        root.pop("globals"),
        f"{twin} program model.globals",
        maximum=MAX_MODEL_GLOBALS_OR_TYPES,
    )
    type_records = _array(
        root.pop("types"),
        f"{twin} program model.types",
        maximum=MAX_MODEL_GLOBALS_OR_TYPES,
    )
    raw_functions = _array(
        root.pop("functions"),
        f"{twin} program model.functions",
        maximum=MAX_FUNCTION_RECORDS,
    )
    # Globals and types do not participate in this metric.  Release their
    # potentially large decoded trees before processing function records.
    del globals_records, type_records, root

    functions: list[RecoveredFunction] = []
    identifiers: set[str] = set()
    normalized_rvas: set[int] = set()
    for index, raw_function in enumerate(raw_functions):
        item_path = f"{twin} program model.functions[{index}]"
        item = _object(
            raw_function,
            item_path,
            {
                "id",
                "name",
                "address",
                "prototype",
                status_field,
                "calls",
                "referencedGlobals",
                "strings",
                "decompiledC",
            } | ({"recoveryAssessment"} if model_version == 2 else set()),
        )
        if model_version == 2 and item["recoveryAssessment"] != "unassessed":
            raise ScoringError(f"{item_path} cannot supply a scored recovery assessment")
        identifier = _string(
            item["id"],
            f"{item_path}.id",
            maximum=MAX_IDENTIFIER_CHARACTERS,
        )
        if identifier in identifiers:
            raise ScoringError(f"duplicate {twin} recovered function id: {identifier}")
        identifiers.add(identifier)
        name = _string(item["name"], f"{item_path}.name", maximum=4096)
        raw_address = _address(item["address"], f"{item_path}.address")
        if raw_address < model_image_base:
            raise ScoringError(
                f"{item_path}.address is below the explicit program-model image base"
            )
        rva = raw_address - model_image_base
        if not _contains_rva(artifact, rva):
            raise ScoringError(
                f"{item_path}.address normalizes outside the artifact executable ranges; "
                "check the explicit program-model image base"
            )
        if rva in normalized_rvas:
            raise ScoringError(
                f"multiple {twin} recovered functions normalize to RVA {hex(rva)}"
            )
        normalized_rvas.add(rva)
        _string(
            item["prototype"],
            f"{item_path}.prototype",
            allow_empty=True,
            maximum=1_048_576,
        )
        status = _string(item[status_field], f"{item_path}.{status_field}", maximum=32)
        if status not in _RECOVERY_STATUSES:
            raise ScoringError(f"{item_path}.status has an invalid value")
        _string_array(item["calls"], f"{item_path}.calls")
        _string_array(item["referencedGlobals"], f"{item_path}.referencedGlobals")
        _string_array(
            item["strings"],
            f"{item_path}.strings",
            maximum_characters=MAX_TEXT_CHARACTERS,
        )
        if item["decompiledC"] is not None:
            _string(
                item["decompiledC"],
                f"{item_path}.decompiledC",
                allow_empty=True,
                maximum=MAX_TEXT_CHARACTERS,
            )
        functions.append(
            RecoveredFunction(
                identifier=identifier,
                name=name,
                rva=rva,
                status=status,
            )
        )
        # Do not retain prototypes, references, strings, or decompiled bodies
        # after the boundary/name projection has been validated.
        raw_functions[index] = None
    return RecoveredModel(
        input_sha256=input_sha256,
        image_base=model_image_base,
        functions=tuple(
            sorted(functions, key=lambda function: (function.rva, function.identifier))
        ),
    )


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": None if denominator == 0 else round(numerator / denominator, 6),
    }


def _alias_detail(alias: OracleAlias, twin: str) -> dict[str, Any]:
    return {
        "name": alias.name,
        "availability": alias.availability[twin],
        "evidence": [
            {"kind": fact.kind, "locator": fact.locator} for fact in alias.evidence
        ],
    }


def _oracle_detail(function: OracleFunction, twin: str) -> dict[str, Any]:
    assert function.rva is not None
    return {
        "oracleId": function.identifier,
        "oracleRva": hex(function.rva),
        "oracleAliases": [
            _alias_detail(alias, twin) for alias in function.aliases
        ],
    }


def _recovered_detail(function: RecoveredFunction) -> dict[str, Any]:
    return {
        "recoveredId": function.identifier,
        "recoveredRva": hex(function.rva),
        "recoveredName": function.name,
        "recoveredStatus": function.status,
    }


def _match_detail(
    oracle_function: OracleFunction,
    recovered_function: RecoveredFunction,
    *,
    twin: str,
    match_kind: str,
) -> dict[str, Any]:
    assert oracle_function.rva is not None
    observable_aliases = [
        alias
        for alias in oracle_function.aliases
        if alias.availability[twin] != "not-observable"
    ]
    matched_alias = next(
        (
            alias
            for alias in observable_aliases
            if alias.name == recovered_function.name
        ),
        None,
    )
    if not observable_aliases:
        name_result = "not-scored"
    elif matched_alias is not None:
        name_result = "exact"
    else:
        name_result = "incorrect"
    return {
        **_oracle_detail(oracle_function, twin),
        **_recovered_detail(recovered_function),
        "deltaBytes": recovered_function.rva - oracle_function.rva,
        "matchKind": match_kind,
        "nameResult": name_result,
        "matchedAlias": None if matched_alias is None else matched_alias.name,
        "matchedAliasAvailability": (
            None if matched_alias is None else matched_alias.availability[twin]
        ),
        "nameCategoryResults": {
            availability: (
                "not-applicable"
                if not any(
                    alias.availability[twin] == availability
                    for alias in oracle_function.aliases
                )
                else (
                    "exact"
                    if any(
                        alias.availability[twin] == availability
                        and alias.name == recovered_function.name
                        for alias in oracle_function.aliases
                    )
                    else "incorrect"
                )
            )
            for availability in ("surviving", "removed")
        },
    }


def _better_objective(
    candidate_count: int,
    candidate_cost: int,
    best_count: int,
    best_cost: int,
) -> bool:
    return candidate_count > best_count or (
        candidate_count == best_count and candidate_cost < best_cost
    )


def _minimum_cost_near_assignment_impl(
    oracle_functions: Sequence[OracleFunction],
    recovered_functions: Sequence[RecoveredFunction],
    bound: int,
) -> NearAssignment:
    """Optimize remaining starts by cardinality, distance, then stable RVA order.

    Absolute-distance assignment on sorted addresses has a non-crossing optimum,
    so sequence dynamic programming covers the complete objective.  A full
    backward objective table supports canonical reconstruction and evidence for
    every edge that participates in any equally optimal order-preserving
    assignment.
    """

    oracle_count = len(oracle_functions)
    recovered_count = len(recovered_functions)
    if oracle_count == 0 or recovered_count == 0:
        return NearAssignment(
            matches=(),
            false_negatives=tuple(oracle_functions),
            false_positives=tuple(recovered_functions),
            total_distance_bytes=0,
            optimal_candidate_edges=(),
        )
    cells = (oracle_count + 1) * (recovered_count + 1)
    if cells > MAX_MATCHING_CELLS:
        raise ScoringError(
            "near-match assignment exceeds the "
            f"{MAX_MATCHING_CELLS}-cell computation limit"
        )

    width = recovered_count + 1
    # Function counts are capped at 20,000, so 16-bit count cells are safe;
    # costs remain 32-bit (20,000 * 4,096 bytes).  At the published ceiling
    # the two suffix tables therefore consume about 120 MiB rather than 160.
    suffix_counts = array("H", [0]) * cells
    suffix_costs = array("I", [0]) * cells
    for oracle_index in range(oracle_count - 1, -1, -1):
        row = oracle_index * width
        below = (oracle_index + 1) * width
        oracle_function = oracle_functions[oracle_index]
        assert oracle_function.rva is not None
        for recovered_index in range(recovered_count - 1, -1, -1):
            best_count = suffix_counts[below + recovered_index]
            best_cost = suffix_costs[below + recovered_index]
            right_count = suffix_counts[row + recovered_index + 1]
            right_cost = suffix_costs[row + recovered_index + 1]
            if _better_objective(right_count, right_cost, best_count, best_cost):
                best_count, best_cost = right_count, right_cost
            distance = abs(
                oracle_function.rva - recovered_functions[recovered_index].rva
            )
            if distance <= bound:
                match_count = suffix_counts[below + recovered_index + 1] + 1
                match_cost = suffix_costs[below + recovered_index + 1] + distance
                if _better_objective(
                    match_count,
                    match_cost,
                    best_count,
                    best_cost,
                ):
                    best_count, best_cost = match_count, match_cost
            suffix_counts[row + recovered_index] = best_count
            suffix_costs[row + recovered_index] = best_cost

    maximum_cardinality = suffix_counts[0]
    minimum_cost = suffix_costs[0]

    # Reconstruct the lexicographically lowest address-pair sequence that still
    # achieves the complete objective.  Names never participate in this choice.
    selected: list[tuple[OracleFunction, RecoveredFunction]] = []
    start_oracle = 0
    start_recovered = 0
    remaining_cardinality = maximum_cardinality
    remaining_cost = minimum_cost
    while remaining_cardinality:
        chosen: tuple[int, int, int] | None = None
        for oracle_index in range(start_oracle, oracle_count):
            oracle_function = oracle_functions[oracle_index]
            assert oracle_function.rva is not None
            below = (oracle_index + 1) * width
            for recovered_index in range(start_recovered, recovered_count):
                distance = abs(
                    oracle_function.rva - recovered_functions[recovered_index].rva
                )
                if distance > bound:
                    continue
                suffix_index = below + recovered_index + 1
                if (
                    suffix_counts[suffix_index] + 1 == remaining_cardinality
                    and suffix_costs[suffix_index] + distance == remaining_cost
                ):
                    chosen = (oracle_index, recovered_index, distance)
                    break
            if chosen is not None:
                break
        if chosen is None:
            raise AssertionError("minimum-cost near assignment reconstruction drift")
        oracle_index, recovered_index, distance = chosen
        selected.append(
            (oracle_functions[oracle_index], recovered_functions[recovered_index])
        )
        start_oracle = oracle_index + 1
        start_recovered = recovered_index + 1
        remaining_cardinality -= 1
        remaining_cost -= distance

    # Compute prefix objectives one row at a time.  Combining a prefix, one
    # edge, and its suffix identifies edges belonging to any global optimum.
    optimal_candidates: list[tuple[OracleFunction, RecoveredFunction]] = []
    previous_counts = array("H", [0]) * width
    previous_costs = array("I", [0]) * width
    for oracle_index, oracle_function in enumerate(oracle_functions):
        assert oracle_function.rva is not None
        current_counts = array("H", [0]) * width
        current_costs = array("I", [0]) * width
        below = (oracle_index + 1) * width
        for recovered_index, recovered_function in enumerate(recovered_functions):
            distance = abs(oracle_function.rva - recovered_function.rva)
            if distance <= bound:
                suffix_index = below + recovered_index + 1
                if (
                    previous_counts[recovered_index]
                    + 1
                    + suffix_counts[suffix_index]
                    == maximum_cardinality
                    and previous_costs[recovered_index]
                    + distance
                    + suffix_costs[suffix_index]
                    == minimum_cost
                ):
                    optimal_candidates.append((oracle_function, recovered_function))
                    if len(optimal_candidates) > MAX_AMBIGUITY_EDGES:
                        raise ScoringError(
                            "optimal near-match ambiguity exceeds the "
                            f"{MAX_AMBIGUITY_EDGES}-edge report limit"
                        )

            cell = recovered_index + 1
            best_count = previous_counts[cell]
            best_cost = previous_costs[cell]
            left_count = current_counts[cell - 1]
            left_cost = current_costs[cell - 1]
            if _better_objective(left_count, left_cost, best_count, best_cost):
                best_count, best_cost = left_count, left_cost
            if distance <= bound:
                match_count = previous_counts[cell - 1] + 1
                match_cost = previous_costs[cell - 1] + distance
                if _better_objective(
                    match_count,
                    match_cost,
                    best_count,
                    best_cost,
                ):
                    best_count, best_cost = match_count, match_cost
            current_counts[cell] = best_count
            current_costs[cell] = best_cost
        previous_counts, previous_costs = current_counts, current_costs

    if (
        previous_counts[-1] != maximum_cardinality
        or previous_costs[-1] != minimum_cost
    ):
        raise AssertionError("forward/backward near assignment objective drift")
    selected_oracle = {function.identifier for function, _ in selected}
    selected_recovered = {function.identifier for _, function in selected}
    return NearAssignment(
        matches=tuple(selected),
        false_negatives=tuple(
            function
            for function in oracle_functions
            if function.identifier not in selected_oracle
        ),
        false_positives=tuple(
            function
            for function in recovered_functions
            if function.identifier not in selected_recovered
        ),
        total_distance_bytes=minimum_cost,
        optimal_candidate_edges=tuple(optimal_candidates),
    )


def _minimum_cost_near_assignment(
    oracle_functions: Sequence[OracleFunction],
    recovered_functions: Sequence[RecoveredFunction],
    bound: int,
) -> NearAssignment:
    try:
        return _minimum_cost_near_assignment_impl(
            oracle_functions,
            recovered_functions,
            bound,
        )
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            "not enough memory for the bounded near-match assignment"
        ) from error


def _name_metric(
    oracle_functions: Sequence[OracleFunction],
    matches_by_oracle_id: Mapping[str, RecoveredFunction],
    *,
    twin: str,
    availability_filter: str | None,
) -> dict[str, Any]:
    eligible = [
        function
        for function in oracle_functions
        if any(
            alias.availability[twin] != "not-observable"
            and (
                availability_filter is None
                or alias.availability[twin] == availability_filter
            )
            for alias in function.aliases
        )
    ]
    exact = 0
    incorrect = 0
    missing_boundary = 0
    for oracle_function in eligible:
        recovered = matches_by_oracle_id.get(oracle_function.identifier)
        if recovered is None:
            missing_boundary += 1
        elif any(
            alias.name == recovered.name
            and alias.availability[twin] != "not-observable"
            and (
                availability_filter is None
                or alias.availability[twin] == availability_filter
            )
            for alias in oracle_function.aliases
        ):
            exact += 1
        else:
            incorrect += 1
    if exact + incorrect + missing_boundary != len(eligible):
        raise AssertionError("name denominator partition drift")
    return {
        "referenceCount": len(eligible),
        "exact": exact,
        "incorrect": incorrect,
        "missingBoundary": missing_boundary,
        "accuracy": _ratio(exact, len(eligible)),
    }


def _assignment_edge_detail(
    oracle_function: OracleFunction,
    recovered_function: RecoveredFunction,
) -> dict[str, Any]:
    assert oracle_function.rva is not None
    return {
        "oracleId": oracle_function.identifier,
        "oracleRva": hex(oracle_function.rva),
        "recoveredId": recovered_function.identifier,
        "recoveredRva": hex(recovered_function.rva),
        "deltaBytes": recovered_function.rva - oracle_function.rva,
        "distanceBytes": abs(recovered_function.rva - oracle_function.rva),
    }


def _json_string_encoded_size(value: str) -> int:
    """Count exact ``ensure_ascii=True`` JSON-string bytes without allocating."""

    size = 2  # surrounding quotes
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\"} or character in "\b\f\n\r\t":
            size += 2
        elif codepoint < 0x20 or codepoint > 0x7E:
            size += 12 if codepoint > 0xFFFF else 6
        else:
            size += 1
    return size


def _preflight_report_projection(
    oracle: FunctionOracle,
    recovered_twins: Mapping[str, RecoveredModel],
) -> list[int]:
    """Reject clearly oversized entity reports before duplicating details."""

    estimated = 64 * 1024
    for function in oracle.functions:
        estimated += 512 + _json_string_encoded_size(function.identifier)
        appearances = 2 if function.exclusion is None else 1
        if function.exclusion is not None:
            estimated += _json_string_encoded_size(function.exclusion.reason)
            if function.exclusion.kind == "compiler-generated":
                # An exact excluded recovery can repeat the id and reason once
                # in each twin's ignored-recovery detail.
                estimated += 2 * (
                    128
                    + _json_string_encoded_size(function.identifier)
                    + _json_string_encoded_size(function.exclusion.reason)
                )
        for alias in function.aliases:
            alias_bytes = 256 + _json_string_encoded_size(alias.name)
            for fact in alias.evidence:
                alias_bytes += (
                    128
                    + _json_string_encoded_size(fact.kind)
                    + _json_string_encoded_size(fact.locator)
                )
            estimated += appearances * alias_bytes
        if estimated > MAX_REPORT_BYTES:
            raise ScoringError(
                "projected entity detail exceeds the "
                f"{MAX_REPORT_BYTES}-byte output limit"
            )
    for twin in _TWIN_NAMES:
        for recovered_function in recovered_twins[twin].functions:
            estimated += (
                512
                + _json_string_encoded_size(recovered_function.identifier)
                + _json_string_encoded_size(recovered_function.name)
            )
            if estimated > MAX_REPORT_BYTES:
                raise ScoringError(
                    "projected entity detail exceeds the "
                    f"{MAX_REPORT_BYTES}-byte output limit"
                )
    # A one-element mutable budget lets each twin charge ambiguity evidence
    # before its list of report dictionaries is materialized.
    return [estimated]


def _charge_ambiguity_projection(
    report_projection: list[int],
    alternative_edges: Sequence[tuple[OracleFunction, RecoveredFunction]],
) -> None:
    for oracle_function, recovered_function in alternative_edges:
        report_projection[0] += (
            512
            + _json_string_encoded_size(oracle_function.identifier)
            + _json_string_encoded_size(recovered_function.identifier)
        )
        if report_projection[0] > MAX_REPORT_BYTES:
            raise ScoringError(
                "projected ambiguity detail exceeds the "
                f"{MAX_REPORT_BYTES}-byte output limit"
            )


def _score_twin(
    oracle: FunctionOracle,
    recovered_model: RecoveredModel,
    *,
    twin: str,
    report_projection: list[int],
) -> dict[str, Any]:
    recovered = recovered_model.functions
    scored_oracle = sorted(
        (
            function
            for function in oracle.functions
            if function.exclusion is None
        ),
        key=lambda function: (function.rva, function.identifier),
    )
    scored_by_rva = {function.rva: function for function in scored_oracle}
    excluded_by_rva = {
        function.rva: function
        for function in oracle.functions
        if function.exclusion is not None and function.rva is not None
    }

    ignored: list[dict[str, Any]] = []
    scored_recovered: list[RecoveredFunction] = []
    for recovered_function in recovered:
        exclusion = excluded_by_rva.get(recovered_function.rva)
        if exclusion is None:
            scored_recovered.append(recovered_function)
            continue
        assert exclusion.exclusion is not None
        ignored.append(
            {
                **_recovered_detail(recovered_function),
                "oracleId": exclusion.identifier,
                "exclusionKind": exclusion.exclusion.kind,
                "exclusionReason": exclusion.exclusion.reason,
            }
        )

    exact_pairs: list[tuple[OracleFunction, RecoveredFunction]] = []
    exact_oracle_ids: set[str] = set()
    exact_recovered_ids: set[str] = set()
    for recovered_function in scored_recovered:
        oracle_function = scored_by_rva.get(recovered_function.rva)
        if oracle_function is not None:
            exact_pairs.append((oracle_function, recovered_function))
            exact_oracle_ids.add(oracle_function.identifier)
            exact_recovered_ids.add(recovered_function.identifier)

    remaining_oracle = [
        function
        for function in scored_oracle
        if function.identifier not in exact_oracle_ids
    ]
    remaining_recovered = [
        function
        for function in scored_recovered
        if function.identifier not in exact_recovered_ids
    ]
    near_assignment = _minimum_cost_near_assignment(
        remaining_oracle,
        remaining_recovered,
        oracle.near_miss_bytes,
    )
    near_pairs = list(near_assignment.matches)
    false_negative_functions = list(near_assignment.false_negatives)
    false_positive_functions = list(near_assignment.false_positives)

    matches_by_oracle_id = {
        oracle_function.identifier: recovered_function
        for oracle_function, recovered_function in exact_pairs + near_pairs
    }
    exact_count = len(exact_pairs)
    near_count = len(near_pairs)
    true_positives = exact_count + near_count
    false_positives = len(false_positive_functions)
    false_negatives = len(false_negative_functions)
    reference_count = len(scored_oracle)
    recovered_count = len(scored_recovered)
    if true_positives + false_negatives != reference_count:
        raise AssertionError("boundary reference denominator partition drift")
    if true_positives + false_positives != recovered_count:
        raise AssertionError("boundary recovery denominator partition drift")
    selected_near_edges = {
        (selected_oracle.identifier, selected_recovered.identifier)
        for selected_oracle, selected_recovered in near_pairs
    }
    alternative_optimal_edges = [
        (oracle_function, recovered_function)
        for oracle_function, recovered_function in near_assignment.optimal_candidate_edges
        if (oracle_function.identifier, recovered_function.identifier)
        not in selected_near_edges
    ]
    _charge_ambiguity_projection(report_projection, alternative_optimal_edges)

    return {
        "artifact": {
            "inputSha256": oracle.artifacts[twin].input_sha256,
            "elfType": oracle.artifacts[twin].elf_type,
            "elfImageBase": hex(oracle.artifacts[twin].elf_image_base),
            "modelImageBase": hex(recovered_model.image_base),
            "modelImageBaseEvidence": "explicit-scorer-input",
            "modelImageBaseValidation": (
                "matches-manifest-elf-image-base"
                if oracle.scope == "production"
                else "fixture-explicit-input"
            ),
            "executableRvaRanges": [
                {
                    "start": hex(executable.start),
                    "endExclusive": hex(executable.end_exclusive),
                }
                for executable in oracle.artifacts[twin].executable_ranges
            ],
        },
        "boundaries": {
            "referenceCount": reference_count,
            "rawRecoveredCount": len(recovered),
            "scoredRecoveredCount": recovered_count,
            "ignoredExcludedCount": len(ignored),
            "exactMatches": exact_count,
            "nearMisses": near_count,
            "truePositives": true_positives,
            "falsePositives": false_positives,
            "falseNegatives": false_negatives,
            "precision": _ratio(true_positives, recovered_count),
            "recall": _ratio(true_positives, reference_count),
            "f1": _ratio(
                2 * true_positives,
                2 * true_positives + false_positives + false_negatives,
            ),
            "exactAddressRate": _ratio(exact_count, reference_count),
            "nearMissRate": _ratio(near_count, reference_count),
            "nearMissDistanceBytes": near_assignment.total_distance_bytes,
        },
        "nameRecovery": {
            "overall": _name_metric(
                scored_oracle,
                matches_by_oracle_id,
                twin=twin,
                availability_filter=None,
            ),
            "surviving": _name_metric(
                scored_oracle,
                matches_by_oracle_id,
                twin=twin,
                availability_filter="surviving",
            ),
            "removed": _name_metric(
                scored_oracle,
                matches_by_oracle_id,
                twin=twin,
                availability_filter="removed",
            ),
            "notObservableCount": sum(
                not any(
                    alias.availability[twin] != "not-observable"
                    for alias in function.aliases
                )
                for function in scored_oracle
            ),
        },
        "nearMatchAssignment": {
            "objective": {
                "maximumCardinality": near_count,
                "minimumTotalDistanceBytes": near_assignment.total_distance_bytes,
            },
            "stableTieBreak": (
                "lexicographically lowest (oracle RVA, recovered RVA) edge sequence"
            ),
            "nameIndependent": True,
            "hasAlternativeOptimalMatching": bool(alternative_optimal_edges),
            "optimalCandidateEdgeCount": len(
                near_assignment.optimal_candidate_edges
            ),
            "alternativeOptimalEdges": [
                _assignment_edge_detail(oracle_function, recovered_function)
                for oracle_function, recovered_function in alternative_optimal_edges
            ],
        },
        "exactMatches": [
            _match_detail(
                oracle_function,
                recovered_function,
                twin=twin,
                match_kind="exact",
            )
            for oracle_function, recovered_function in sorted(
                exact_pairs,
                key=lambda pair: (pair[0].rva, pair[0].identifier),
            )
        ],
        "nearMisses": [
            _match_detail(
                oracle_function,
                recovered_function,
                twin=twin,
                match_kind="near",
            )
            for oracle_function, recovered_function in near_pairs
        ],
        "falsePositives": [
            _recovered_detail(function) for function in false_positive_functions
        ],
        "falseNegatives": [
            {
                **_oracle_detail(function, twin),
            }
            for function in false_negative_functions
        ],
        "ignoredExcludedRecoveries": ignored,
    }


def _score_function_recovery_with_context(
    oracle: FunctionOracle,
    recovered_twins: Mapping[str, RecoveredModel],
    context: _ScoringContext,
) -> dict[str, Any]:
    """Score both twins under a context established by a trusted entry point."""

    if set(recovered_twins) != set(_TWIN_NAMES):
        raise ScoringError("recovered twins must contain exactly rich and stripped")
    expected_context = (
        _fixture_context()
        if oracle.scope == "fixture"
        else _artifact_verified_unattested_model_context()
    )
    if context != expected_context:
        raise ScoringError(
            f"{oracle.scope} scoring received an incompatible verification context"
        )
    report_projection = _preflight_report_projection(oracle, recovered_twins)
    excluded_counts = {
        kind: sum(
            function.exclusion is not None and function.exclusion.kind == kind
            for function in oracle.functions
        )
        for kind in sorted(_EXCLUSION_KINDS)
    }
    scored_count = sum(function.exclusion is None for function in oracle.functions)
    return {
        "schemaVersion": 1,
        "oracle": {
            "id": oracle.identifier,
            "scope": oracle.scope,
            "source": "dwarf-and-symbols",
            "artifactManifestSha256": oracle.artifact_manifest_sha256,
            "verification": {
                "status": context.status,
                "artifactManifestVerified": context.artifact_manifest_verified,
                "programModelProvenance": context.program_model_provenance,
                "productionVerified": context.production_verified,
            },
            "functionRecordCount": len(oracle.functions),
            "scoredFunctionCount": scored_count,
            "exclusions": excluded_counts,
            "excludedFunctions": [
                {
                    "oracleId": function.identifier,
                    "rva": None if function.rva is None else hex(function.rva),
                    "aliases": [
                        {
                            "name": alias.name,
                            "availability": dict(alias.availability),
                            "evidence": [
                                {"kind": fact.kind, "locator": fact.locator}
                                for fact in alias.evidence
                            ],
                        }
                        for alias in function.aliases
                    ],
                    "kind": function.exclusion.kind,
                    "reason": function.exclusion.reason,
                }
                for function in oracle.functions
                if function.exclusion is not None
            ],
        },
        "policy": {
            "addressNormalization": (
                "rva = model address - explicit program-model image base; "
                "oracle RVA = ELF virtual address - recorded ELF image base "
                "(manifest-validated for production)"
            ),
            "nearMissBytes": oracle.near_miss_bytes,
            "nearMissMatching": (
                "exact addresses first; then on sorted RVAs maximize order-preserving "
                "one-to-one cardinality, minimize total absolute distance, and apply "
                "the recorded stable tie break"
            ),
            "nameComparison": "exact UTF-8 match against any oracle alias",
            "exclusionHandling": (
                "inlined records are never scored; exact starts of explicitly "
                "compiler-generated records are ignored"
            ),
            "limits": {
                "maxJsonInputBytes": MAX_JSON_INPUT_BYTES,
                "maxManifestBytes": MAX_MANIFEST_BYTES,
                "maxSupportingInputBytes": MAX_SUPPORTING_INPUT_BYTES,
                "maxArtifactBytes": MAX_ARTIFACT_BYTES,
                "maxReportBytes": MAX_REPORT_BYTES,
                "maxFunctionRecords": MAX_FUNCTION_RECORDS,
                "maxAliasesPerFunction": MAX_ALIASES_PER_FUNCTION,
                "maxEvidencePerAlias": MAX_EVIDENCE_PER_ALIAS,
                "maxModelReferencesPerFunction": (
                    MAX_MODEL_REFERENCES_PER_FUNCTION
                ),
                "maxModelGlobalsOrTypes": MAX_MODEL_GLOBALS_OR_TYPES,
                "maxTextCharacters": MAX_TEXT_CHARACTERS,
                "maxMatchingCells": MAX_MATCHING_CELLS,
                "maxAmbiguityEdges": MAX_AMBIGUITY_EDGES,
            },
        },
        "twins": {
            twin: _score_twin(
                oracle,
                recovered_twins[twin],
                twin=twin,
                report_projection=report_projection,
            )
            for twin in _TWIN_NAMES
        },
    }


def score_function_recovery(
    oracle: FunctionOracle,
    recovered_twins: Mapping[str, RecoveredModel],
) -> dict[str, Any]:
    """Unchecked in-memory scoring API, deliberately limited to fixtures.

    An adapter must authenticate file-backed artifact metadata before invoking
    the internal context-aware scorer. Schema-v1 models still lack controlled
    exporter/loader identity, so adapters must report that provenance gap.
    """

    if oracle.scope != "fixture":
        raise ScoringError(
            "unchecked in-memory scoring cannot emit a production report; "
            "use an authenticated file adapter with the bound artifact manifest"
        )
    try:
        return _score_function_recovery_with_context(
            oracle,
            recovered_twins,
            _fixture_context(),
        )
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            "not enough memory to build the bounded fixture score"
        ) from error
    except ValueError as error:
        raise ScoringError(f"invalid in-memory scoring value: {error}") from error


def report_json_bytes(report: Mapping[str, Any]) -> bytes:
    """Render canonical, reproducible report bytes."""

    try:
        encoder = json.JSONEncoder(
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        rendered = bytearray()
        for text_chunk in encoder.iterencode(report):
            chunk = text_chunk.encode("utf-8")
            if len(rendered) + len(chunk) + 1 > MAX_REPORT_BYTES:
                raise ScoringError(
                    f"JSON report exceeds the {MAX_REPORT_BYTES}-byte output limit"
                )
            rendered.extend(chunk)
        rendered.extend(b"\n")
        return bytes(rendered)
    except ScoringError:
        raise
    except MemoryError as error:
        raise ScoringError(
            "not enough memory to render the bounded JSON report"
        ) from error
    except (TypeError, ValueError, OverflowError) as error:
        raise ScoringError(f"score report is not JSON-serializable: {error}") from error


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically replace a non-symlink output with canonical report bytes."""

    if path.is_symlink():
        raise ScoringError(f"JSON output may not be a symlink: {path}")
    payload = report_json_bytes(report)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
    except OSError as error:
        raise ScoringError(f"cannot write JSON report {path}: {error}") from error


def _format_ratio(metric: Mapping[str, Any]) -> str:
    value = metric["value"]
    rendered = "n/a" if value is None else f"{value:.4f}"
    return f"{metric['numerator']}/{metric['denominator']}={rendered}"


def render_human_report(report: Mapping[str, Any]) -> str:
    """Render the concise deterministic companion to the JSON report."""

    oracle = report["oracle"]
    scope = str(oracle["scope"]).upper()
    verification = str(oracle["verification"]["status"]).upper()
    lines = [
        f"[{scope}; {verification}] function recovery: {oracle['id']}",
        (
            f"policy: near miss <= {report['policy']['nearMissBytes']} bytes; "
            f"scored {oracle['scoredFunctionCount']}; "
            f"excluded compiler-generated {oracle['exclusions']['compiler-generated']}, "
            f"inlined {oracle['exclusions']['inlined']}"
        ),
    ]
    for twin in _TWIN_NAMES:
        result = report["twins"][twin]
        boundaries = result["boundaries"]
        names = result["nameRecovery"]
        lines.append(
            f"{twin}: boundary "
            f"P {_format_ratio(boundaries['precision'])}, "
            f"R {_format_ratio(boundaries['recall'])}, "
            f"F1 {_format_ratio(boundaries['f1'])}; "
            f"exact {_format_ratio(boundaries['exactAddressRate'])}, "
            f"near {_format_ratio(boundaries['nearMissRate'])}, "
            f"FP {boundaries['falsePositives']}, FN {boundaries['falseNegatives']}"
        )
        lines.append(
            f"{twin}: names overall {_format_ratio(names['overall']['accuracy'])}; "
            f"surviving {_format_ratio(names['surviving']['accuracy'])}; "
            f"removed {_format_ratio(names['removed']['accuracy'])}"
        )
    return "\n".join(lines) + "\n"
