"""Legacy non-authoritative Python compatibility for ELF function normalization.

Kotlin/JVM owns production LLVM function-oracle generation. This module remains
for differential and unit compatibility and cannot certify or enter evidence
for a new Kotlin-only release. It extracts facts; it does not decide that a
name, compiler suffix, or benchmark identity is special. Emitted DWARF
subprogram starts and defined
``STT_FUNC`` symbols are reconciled by RVA.  A caller may supply an explicit,
reviewed RVA-to-reason map for emitted entities that should be excluded from
source-function scoring.  Inline-only DWARF entities are structural exclusions
because they have no emitted start.

``pyelftools`` is intentionally a generation-only dependency.  Scoring a
checked-in oracle remains dependency-free.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, BinaryIO, Callable, Iterable, Mapping, Sequence


MAX_GENERATION_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_EXCLUSION_PROFILE_BYTES = 4 * 1024 * 1024
MAX_GENERATED_FUNCTIONS = 20_000
MAX_GENERATED_ALIASES = 256
MAX_GENERATED_EVIDENCE = 256
MAX_SCANNED_SYMBOLS = 2_000_000
MAX_SCANNED_SUBPROGRAMS = 2_000_000
MAX_SCANNED_DIES = 5_000_000
MAX_DWARF_RANGE_SECTION_BYTES = 16 * 1024 * 1024
MAX_DWARF_RANGE_ENTRIES = 250_000
MAX_GENERATED_NAME_CHARACTERS = 4096
MAX_GENERATED_LOCATOR_CHARACTERS = 16_384
_MAX_ADDRESS = (1 << 64) - 1
_TWIN_NAMES = ("rich", "stripped")
_DWARF_ADDRESS_FORMS = frozenset(
    {
        "DW_FORM_addr",
        "DW_FORM_addrx",
        "DW_FORM_addrx1",
        "DW_FORM_addrx2",
        "DW_FORM_addrx3",
        "DW_FORM_addrx4",
    }
)
_DWARF_CONSTANT_FORMS = frozenset(
    {
        "DW_FORM_data1",
        "DW_FORM_data2",
        "DW_FORM_data4",
        "DW_FORM_data8",
        "DW_FORM_data16",
        "DW_FORM_implicit_const",
        "DW_FORM_sdata",
        "DW_FORM_udata",
    }
)


class OracleGenerationError(ValueError):
    """Raised when ELF twins cannot produce an unambiguous oracle."""


@dataclass(frozen=True, order=True)
class GenerationEvidence:
    kind: str
    locator: str


@dataclass(frozen=True)
class ElfArtifactFacts:
    input_sha256: str
    elf_type: str
    image_base: int
    executable_ranges: tuple[tuple[int, int], ...]
    aliases_by_rva: Mapping[int, Mapping[str, tuple[GenerationEvidence, ...]]]
    inline_only: tuple[tuple[int, Mapping[str, tuple[GenerationEvidence, ...]]], ...]


def _require_pyelftools() -> tuple[Any, Any, Any, Any, Any]:
    try:
        import elftools  # type: ignore[import-untyped]
        from elftools.dwarf.ranges import (  # type: ignore[import-untyped]
            BaseAddressEntry,
            RangeEntry,
        )
        from elftools.dwarf.descriptions import (  # type: ignore[import-untyped]
            describe_form_class,
        )
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
        from elftools.elf.sections import (  # type: ignore[import-untyped]
            SymbolTableSection,
        )
    except ModuleNotFoundError as error:
        raise OracleGenerationError(
            "oracle generation requires pyelftools 0.33; install the pinned "
            "generation requirements"
        ) from error
    if getattr(elftools, "__version__", None) != "0.33":
        raise OracleGenerationError(
            "oracle generation requires exactly pyelftools 0.33"
        )
    return (
        ELFFile,
        SymbolTableSection,
        BaseAddressEntry,
        RangeEntry,
        describe_form_class,
    )


def _open_stable_regular(path: Path, label: str) -> tuple[BinaryIO, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if path.is_symlink():
            raise OracleGenerationError(f"{label} must be a non-symlink regular file")
        descriptor = os.open(path, flags)
    except OracleGenerationError:
        raise
    except OSError as error:
        raise OracleGenerationError(f"cannot open {label} {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OracleGenerationError(f"{label} must be a non-symlink regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_GENERATION_ARTIFACT_BYTES:
            raise OracleGenerationError(
                f"{label} must contain 1..{MAX_GENERATION_ARTIFACT_BYTES} bytes"
            )
        return os.fdopen(descriptor, "rb", closefd=True), metadata
    except BaseException:
        os.close(descriptor)
        raise


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _sha256_file(stream: BinaryIO) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def _decode_dwarf_string(
    value: Any,
    locator: str,
    maximum_characters: int = MAX_GENERATED_NAME_CHARACTERS,
) -> str:
    if isinstance(value, bytes):
        try:
            result = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise OracleGenerationError(
                f"{locator} is not valid UTF-8"
            ) from error
    elif isinstance(value, str):
        result = value
    else:
        raise OracleGenerationError(f"{locator} is not a DWARF string")
    if not result or "\x00" in result:
        raise OracleGenerationError(f"{locator} is empty or contains NUL")
    if len(result) > maximum_characters:
        raise OracleGenerationError(
            f"{locator} exceeds the {maximum_characters}-character "
            "name limit"
        )
    return result


def _attribute_chain(die: Any) -> tuple[Any, ...]:
    """Return the DIE plus its abstract-origin/specification name sources."""

    result: list[Any] = []
    pending = [die]
    seen: set[int] = set()
    while pending:
        current = pending.pop(0)
        if current.offset in seen:
            continue
        seen.add(current.offset)
        result.append(current)
        if len(result) > 32:
            raise OracleGenerationError(
                f"DWARF reference chain from DIE {hex(die.offset)} exceeds 32 entries"
            )
        for attribute_name in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if attribute_name not in current.attributes:
                continue
            try:
                target = current.get_DIE_from_attribute(attribute_name)
            except (KeyError, ValueError, IndexError) as error:
                raise OracleGenerationError(
                    f"cannot resolve {attribute_name} from DIE {hex(die.offset)}"
                ) from error
            pending.append(target)
    return tuple(result)


def _dwarf_names(
    die: Any,
    twin: str,
    maximum_name_characters: int = MAX_GENERATED_NAME_CHARACTERS,
) -> Mapping[str, tuple[GenerationEvidence, ...]]:
    facts: dict[str, set[GenerationEvidence]] = defaultdict(set)
    for source in _attribute_chain(die):
        for attribute_name in (
            "DW_AT_linkage_name",
            "DW_AT_MIPS_linkage_name",
            "DW_AT_name",
        ):
            attribute = source.attributes.get(attribute_name)
            if attribute is None:
                continue
            locator = (
                f"{twin}:.debug_info:die={hex(die.offset)}:"
                f"{attribute_name}@{hex(source.offset)}"
            )
            name = _decode_dwarf_string(
                attribute.value,
                locator,
                maximum_characters=maximum_name_characters,
            )
            facts[name].add(GenerationEvidence("dwarf-subprogram", locator))
    if not facts:
        raise OracleGenerationError(
            f"non-declaration DWARF subprogram {hex(die.offset)} has no resolvable name"
        )
    if len(facts) > MAX_GENERATED_ALIASES or any(
        len(evidence) > MAX_GENERATED_EVIDENCE for evidence in facts.values()
    ):
        raise OracleGenerationError(
            f"DWARF subprogram {hex(die.offset)} exceeds alias/evidence limits"
        )
    return {
        name: tuple(sorted(evidence))
        for name, evidence in sorted(facts.items())
    }


def _range_section_logical_size(section: Any, stream: BinaryIO, twin: str) -> int:
    """Read a range section's declared logical size without decompressing it."""

    if section.name.startswith(".zdebug_"):
        position = stream.tell()
        try:
            stream.seek(int(section["sh_offset"]))
            header = stream.read(12)
        finally:
            stream.seek(position)
        if len(header) != 12 or header[:4] != b"ZLIB":
            raise OracleGenerationError(
                f"{twin} ELF has an invalid GNU-compressed {section.name} header"
            )
        return int.from_bytes(header[4:], byteorder="big", signed=False)
    try:
        return int(section.data_size)
    except (AttributeError, TypeError, ValueError) as error:
        raise OracleGenerationError(
            f"{twin} ELF cannot determine the logical size of {section.name}"
        ) from error


def _first_dwarf_range_start(
    die: Any,
    dwarf_info: Any,
    base_address_entry: Any,
    range_entry: Any,
    describe_form_class: Any,
) -> int | None:
    ranges_attribute = die.attributes.get("DW_AT_ranges")
    if ranges_attribute is None:
        return None
    try:
        entries = dwarf_info.range_lists().get_range_list_at_offset(
            int(ranges_attribute.value),
            die.cu,
        )
    except MemoryError as error:
        raise OracleGenerationError(
            f"not enough memory to decode the bounded range list for "
            f"DWARF subprogram {hex(die.offset)}"
        ) from error
    except Exception as error:
        raise OracleGenerationError(
            f"cannot decode ranges for DWARF subprogram {hex(die.offset)}"
        ) from error
    if len(entries) > MAX_DWARF_RANGE_ENTRIES:
        raise OracleGenerationError(
            f"DWARF subprogram {hex(die.offset)} exceeds the "
            f"{MAX_DWARF_RANGE_ENTRIES}-entry range-list limit"
        )
    top_die = die.cu.get_top_DIE()
    top_low_pc = top_die.attributes.get("DW_AT_low_pc")
    base = 0
    if top_low_pc is not None:
        locator = f"DWARF compilation unit {hex(top_die.offset)} DW_AT_low_pc"
        if _attribute_form_class(
            top_low_pc,
            locator,
            describe_form_class,
        ) != "address":
            raise OracleGenerationError(f"{locator} must have address class")
        base = _checked_dwarf_address(top_low_pc.value, locator)
    for entry in entries:
        if isinstance(entry, base_address_entry):
            base = _checked_dwarf_address(
                entry.base_address,
                f"DWARF subprogram {hex(die.offset)} range-list base",
            )
        elif isinstance(entry, range_entry):
            begin = _checked_dwarf_address(
                entry.begin_offset,
                f"DWARF subprogram {hex(die.offset)} range start",
            )
            end = _checked_dwarf_address(
                entry.end_offset,
                f"DWARF subprogram {hex(die.offset)} range end",
            )
            if not entry.is_absolute:
                if begin > _MAX_ADDRESS - base or end > _MAX_ADDRESS - base:
                    raise OracleGenerationError(
                        f"DWARF subprogram {hex(die.offset)} range overflows "
                        "unsigned 64-bit address space"
                    )
                begin += base
                end += base
            if begin < end:
                # A range list describes one possibly discontiguous subprogram.
                # Producer order defines the base/entry range; later fragments
                # are not additional DWARF functions.
                return begin
    return None


def _attribute_form_class(
    attribute: Any,
    locator: str,
    describe_form_class: Any,
) -> str:
    form = getattr(attribute, "form", None)
    if not isinstance(form, str) or not form:
        raise OracleGenerationError(f"{locator} has no resolved DWARF form")
    # pyelftools 0.33's public classifier predates the indexed and implicit
    # DWARF 5 forms even though its DIE decoder resolves their values. Keep the
    # exhaustive classes accepted for an entry/base address explicit here.
    if form in _DWARF_ADDRESS_FORMS:
        return "address"
    if form in _DWARF_CONSTANT_FORMS:
        return "constant"
    try:
        form_class = describe_form_class(form)
    except Exception as error:
        raise OracleGenerationError(
            f"{locator} has unsupported DWARF form {form}"
        ) from error
    if form_class not in {"address", "constant"}:
        raise OracleGenerationError(
            f"{locator} has unsupported DWARF form class {form_class!r}"
        )
    return str(form_class)


def _checked_dwarf_address(
    value: Any,
    locator: str,
    *,
    little_endian: bool | None = None,
) -> int:
    if isinstance(value, bool):
        raise OracleGenerationError(f"{locator} is not an integer address")
    if isinstance(value, int):
        address = value
    elif isinstance(value, (bytes, bytearray, list, tuple)):
        if (
            little_endian is None
            or len(value) != 16
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or not 0 <= item <= 0xFF
                for item in value
            )
        ):
            raise OracleGenerationError(f"{locator} is not an integer address")
        try:
            address = int.from_bytes(
                bytes(value),
                byteorder="little" if little_endian else "big",
                signed=False,
            )
        except (MemoryError, ValueError) as error:
            raise OracleGenerationError(
                f"{locator} is not an integer address"
            ) from error
    else:
        raise OracleGenerationError(f"{locator} is not an integer address")
    if address < 0 or address > _MAX_ADDRESS:
        raise OracleGenerationError(f"{locator} is outside unsigned 64-bit range")
    return address


def _dwarf_starts(
    die: Any,
    dwarf_info: Any,
    base_address_entry: Any,
    range_entry: Any,
    describe_form_class: Any,
) -> tuple[int, ...]:
    attributes = die.attributes
    entry_pc = attributes.get("DW_AT_entry_pc")
    if entry_pc is not None:
        locator = f"DWARF subprogram {hex(die.offset)} DW_AT_entry_pc"
        form_class = _attribute_form_class(entry_pc, locator, describe_form_class)
        little_endian: bool | None = None
        if getattr(entry_pc, "form", None) == "DW_FORM_data16":
            candidate = getattr(getattr(die.cu, "structs", None), "little_endian", None)
            if isinstance(candidate, bool):
                little_endian = candidate
        entry_value = _checked_dwarf_address(
            entry_pc.value,
            locator,
            little_endian=little_endian,
        )
        if form_class == "address":
            return (entry_value,)

        low_pc = attributes.get("DW_AT_low_pc")
        if low_pc is not None:
            low_locator = f"DWARF subprogram {hex(die.offset)} DW_AT_low_pc"
            if _attribute_form_class(
                low_pc,
                low_locator,
                describe_form_class,
            ) != "address":
                raise OracleGenerationError(
                    f"{low_locator} must have address class"
                )
            base = _checked_dwarf_address(low_pc.value, low_locator)
        else:
            range_start = _first_dwarf_range_start(
                die,
                dwarf_info,
                base_address_entry,
                range_entry,
                describe_form_class,
            )
            if range_start is None:
                raise OracleGenerationError(
                    f"{locator} uses a constant form without a function base"
                )
            base = _checked_dwarf_address(
                range_start,
                f"DWARF subprogram {hex(die.offset)} range base",
            )
        if entry_value > _MAX_ADDRESS - base:
            raise OracleGenerationError(f"{locator} overflows unsigned 64-bit range")
        return (base + entry_value,)

    low_pc = attributes.get("DW_AT_low_pc")
    if low_pc is not None:
        locator = f"DWARF subprogram {hex(die.offset)} DW_AT_low_pc"
        if _attribute_form_class(
            low_pc,
            locator,
            describe_form_class,
        ) != "address":
            raise OracleGenerationError(f"{locator} must have address class")
        return (_checked_dwarf_address(low_pc.value, locator),)

    range_start = _first_dwarf_range_start(
        die,
        dwarf_info,
        base_address_entry,
        range_entry,
        describe_form_class,
    )
    return () if range_start is None else (range_start,)


def _in_executable_range(
    address: int,
    image_base: int,
    ranges: Sequence[tuple[int, int]],
) -> bool:
    if address < image_base:
        return False
    rva = address - image_base
    return any(start <= rva < end for start, end in ranges)


def _freeze_aliases(
    source: Mapping[int, Mapping[str, set[GenerationEvidence]]],
) -> Mapping[int, Mapping[str, tuple[GenerationEvidence, ...]]]:
    return {
        rva: {
            name: tuple(sorted(evidence))
            for name, evidence in sorted(aliases.items())
        }
        for rva, aliases in sorted(source.items())
    }


def _compilation_unit_path(compilation_unit: Any, twin: str) -> str:
    top = compilation_unit.get_top_DIE()
    parts: list[str] = []
    for attribute_name in ("DW_AT_comp_dir", "DW_AT_name"):
        attribute = top.attributes.get(attribute_name)
        if attribute is not None:
            parts.append(
                _decode_dwarf_string(
                    attribute.value,
                    f"{twin} compilation unit {hex(top.offset)} {attribute_name}",
                )
            )
    if not parts:
        raise OracleGenerationError(
            f"{twin} compilation unit {hex(top.offset)} has no path identity"
        )
    return "/".join(part.rstrip("/") for part in parts)


def inspect_elf_functions(
    path: Path,
    *,
    twin: str,
    symbol_name_selector: Callable[[str], bool] | None = None,
    compilation_unit_selector: Callable[[str], bool] | None = None,
    include_inline_only: bool = True,
) -> ElfArtifactFacts:
    """Extract deterministic function facts from one ELF artifact."""

    if twin not in _TWIN_NAMES:
        raise OracleGenerationError(f"unknown twin name: {twin}")
    (
        ELFFile,
        SymbolTableSection,
        BaseAddressEntry,
        RangeEntry,
        describe_form_class,
    ) = _require_pyelftools()
    stream, before = _open_stable_regular(path, f"{twin} ELF artifact")
    try:
        input_sha256 = _sha256_file(stream)
        try:
            elf = ELFFile(stream)
        except Exception as error:
            raise OracleGenerationError(f"{twin} input is not a supported ELF file") from error
        elf_type = str(elf.header["e_type"])
        if elf_type not in {"ET_EXEC", "ET_DYN"}:
            raise OracleGenerationError(
                f"{twin} ELF type must be ET_EXEC or ET_DYN, got {elf_type}"
            )
        loads = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0
        ]
        if not loads:
            raise OracleGenerationError(f"{twin} ELF has no nonempty PT_LOAD segment")
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        executable_ranges = tuple(
            sorted(
                (
                    int(segment["p_vaddr"]) - image_base,
                    int(segment["p_vaddr"]) + int(segment["p_memsz"]) - image_base,
                )
                for segment in loads
                if int(segment["p_flags"]) & 1
            )
        )
        if not executable_ranges:
            raise OracleGenerationError(f"{twin} ELF has no executable PT_LOAD segment")
        for previous, current in zip(executable_ranges, executable_ranges[1:]):
            if current[0] < previous[1]:
                raise OracleGenerationError(
                    f"{twin} ELF executable PT_LOAD ranges overlap"
                )

        aliases: dict[int, dict[str, set[GenerationEvidence]]] = defaultdict(
            lambda: defaultdict(set)
        )
        inline_only: list[
            tuple[int, Mapping[str, tuple[GenerationEvidence, ...]]]
        ] = []

        def add_evidence(
            rva: int,
            name: str,
            evidence: Iterable[GenerationEvidence],
        ) -> None:
            if (
                rva not in aliases
                and len(aliases) + len(inline_only) >= MAX_GENERATED_FUNCTIONS
            ):
                raise OracleGenerationError(
                    f"{twin} ELF exceeds the "
                    f"{MAX_GENERATED_FUNCTIONS}-record generation limit"
                )
            by_name = aliases[rva]
            if name not in by_name and len(by_name) >= MAX_GENERATED_ALIASES:
                raise OracleGenerationError(
                    f"{twin} emitted RVA {hex(rva)} exceeds the alias limit"
                )
            facts = by_name[name]
            for fact in evidence:
                if len(fact.locator) > MAX_GENERATED_LOCATOR_CHARACTERS:
                    raise OracleGenerationError(
                        f"{twin} alias {name!r} at {hex(rva)} has an evidence "
                        "locator exceeding the "
                        f"{MAX_GENERATED_LOCATOR_CHARACTERS}-character limit"
                    )
                facts.add(fact)
                if len(facts) > MAX_GENERATED_EVIDENCE:
                    raise OracleGenerationError(
                        f"{twin} alias {name!r} at {hex(rva)} exceeds the evidence limit"
                    )

        scanned_symbols = 0
        for section_index, section in enumerate(elf.iter_sections()):
            if section.name in {
                ".debug_ranges",
                ".debug_rnglists",
                ".zdebug_ranges",
                ".zdebug_rnglists",
            }:
                logical_size = _range_section_logical_size(section, stream, twin)
                if logical_size > MAX_DWARF_RANGE_SECTION_BYTES:
                    raise OracleGenerationError(
                        f"{twin} ELF {section.name} exceeds the "
                        f"{MAX_DWARF_RANGE_SECTION_BYTES}-byte logical-size limit"
                    )
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol_index, symbol in enumerate(section.iter_symbols()):
                scanned_symbols += 1
                if scanned_symbols > MAX_SCANNED_SYMBOLS:
                    raise OracleGenerationError(
                        f"{twin} ELF exceeds the {MAX_SCANNED_SYMBOLS}-symbol scan limit"
                    )
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF" or not symbol.name:
                    continue
                if symbol_name_selector is not None and not symbol_name_selector(
                    symbol.name
                ):
                    continue
                address = int(symbol["st_value"])
                if not _in_executable_range(address, image_base, executable_ranges):
                    continue
                try:
                    symbol.name.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise OracleGenerationError(
                        f"{twin} symbol {section.name}[{symbol_index}] is not valid UTF-8"
                    ) from error
                if len(symbol.name) > MAX_GENERATED_NAME_CHARACTERS:
                    raise OracleGenerationError(
                        f"{twin} symbol {section.name}[{symbol_index}] exceeds the "
                        f"{MAX_GENERATED_NAME_CHARACTERS}-character name limit"
                    )
                rva = address - image_base
                add_evidence(
                    rva,
                    symbol.name,
                    (
                        GenerationEvidence(
                            "elf-symbol",
                            f"{twin}:section[{section_index}]={section.name}:"
                            f"symbol[{symbol_index}]",
                        ),
                    ),
                )

        if elf.has_dwarf_info():
            try:
                # The oracle is bound to these exact artifact bytes. Do not
                # follow mutable external debug links behind their hash.
                dwarf_info = elf.get_dwarf_info(follow_links=False)
            except MemoryError as error:
                raise OracleGenerationError(
                    f"not enough memory to load bounded DWARF sections from {twin} ELF"
                ) from error
            for descriptor_name in ("debug_ranges_sec", "debug_rnglists_sec"):
                descriptor = getattr(dwarf_info, descriptor_name, None)
                if (
                    descriptor is not None
                    and int(descriptor.size) > MAX_DWARF_RANGE_SECTION_BYTES
                ):
                    raise OracleGenerationError(
                        f"{twin} ELF {descriptor.name} exceeds the "
                        f"{MAX_DWARF_RANGE_SECTION_BYTES}-byte logical-size limit"
                    )
            scanned_dies = 0
            scanned_subprograms = 0
            for compilation_unit in dwarf_info.iter_CUs():
                if compilation_unit_selector is not None and not compilation_unit_selector(
                    _compilation_unit_path(compilation_unit, twin)
                ):
                    continue
                for die in compilation_unit.iter_DIEs():
                    scanned_dies += 1
                    if scanned_dies > MAX_SCANNED_DIES:
                        raise OracleGenerationError(
                            f"{twin} ELF exceeds the {MAX_SCANNED_DIES}-DIE scan limit"
                        )
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    scanned_subprograms += 1
                    if scanned_subprograms > MAX_SCANNED_SUBPROGRAMS:
                        raise OracleGenerationError(
                            f"{twin} ELF exceeds the "
                            f"{MAX_SCANNED_SUBPROGRAMS}-subprogram scan limit"
                        )
                    declaration = die.attributes.get("DW_AT_declaration")
                    if declaration is not None and bool(declaration.value):
                        continue
                    starts = _dwarf_starts(
                        die,
                        dwarf_info,
                        BaseAddressEntry,
                        RangeEntry,
                        describe_form_class,
                    )
                    inline_attribute = die.attributes.get("DW_AT_inline")
                    inline_value = (
                        None
                        if inline_attribute is None
                        else int(inline_attribute.value)
                    )
                    if starts:
                        names = _dwarf_names(die, twin)
                        for address in starts:
                            if not _in_executable_range(
                                address,
                                image_base,
                                executable_ranges,
                            ):
                                # Linkers may leave zero or discarded-section
                                # addresses in otherwise valid debug information.
                                # They are not emitted executable starts.
                                continue
                            rva = address - image_base
                            for name, evidence in names.items():
                                add_evidence(rva, name, evidence)
                    elif include_inline_only and inline_value in {1, 3}:
                        if len(aliases) + len(inline_only) >= MAX_GENERATED_FUNCTIONS:
                            raise OracleGenerationError(
                                f"{twin} ELF exceeds the "
                                f"{MAX_GENERATED_FUNCTIONS}-record generation limit"
                            )
                        inline_only.append((die.offset, _dwarf_names(die, twin)))

        after = os.fstat(stream.fileno())
        if _stable_identity(before) != _stable_identity(after):
            raise OracleGenerationError(f"{twin} ELF changed while it was inspected")
        return ElfArtifactFacts(
            input_sha256=input_sha256,
            elf_type=elf_type,
            image_base=image_base,
            executable_ranges=executable_ranges,
            aliases_by_rva=_freeze_aliases(aliases),
            inline_only=tuple(sorted(inline_only, key=lambda item: item[0])),
        )
    except OracleGenerationError:
        raise
    except MemoryError as error:
        raise OracleGenerationError(
            f"not enough memory to inspect bounded {twin} ELF function facts"
        ) from error
    finally:
        stream.close()


def load_explicit_exclusions(path: Path) -> tuple[str, Mapping[int, str]]:
    """Load a closed, artifact-bound exact-RVA exclusion profile."""

    stream, before = _open_stable_regular(path, "exclusion profile")
    try:
        if before.st_size > MAX_EXCLUSION_PROFILE_BYTES:
            raise OracleGenerationError(
                f"exclusion profile exceeds {MAX_EXCLUSION_PROFILE_BYTES} bytes"
            )
        payload = stream.read(MAX_EXCLUSION_PROFILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        if len(payload) != before.st_size or _stable_identity(before) != _stable_identity(after):
            raise OracleGenerationError("exclusion profile changed while it was read")
    except OSError as error:
        raise OracleGenerationError(f"cannot read exclusion profile {path}: {error}") from error
    finally:
        stream.close()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OracleGenerationError(
                    f"exclusion profile contains duplicate JSON key {key!r}"
                )
            result[key] = value
        return result

    try:
        root = json.loads(payload, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise OracleGenerationError(f"exclusion profile is invalid JSON: {error}") from error
    if not isinstance(root, dict) or set(root) != {
        "schemaVersion",
        "richArtifactSha256",
        "exclusions",
    }:
        raise OracleGenerationError("exclusion profile has invalid root fields")
    if isinstance(root["schemaVersion"], bool) or root["schemaVersion"] != 1:
        raise OracleGenerationError("exclusion profile schemaVersion must be 1")
    artifact_sha256 = root["richArtifactSha256"]
    if (
        not isinstance(artifact_sha256, str)
        or len(artifact_sha256) != 64
        or any(character not in "0123456789abcdef" for character in artifact_sha256)
    ):
        raise OracleGenerationError("exclusion profile artifact hash is invalid")
    raw_exclusions = root["exclusions"]
    if not isinstance(raw_exclusions, list):
        raise OracleGenerationError("exclusion profile exclusions must be an array")
    if len(raw_exclusions) > MAX_GENERATED_FUNCTIONS:
        raise OracleGenerationError("exclusion profile exceeds the function-record limit")
    result: dict[int, str] = {}
    previous_rva = -1
    for index, raw in enumerate(raw_exclusions):
        if not isinstance(raw, dict) or set(raw) != {"rva", "reason"}:
            raise OracleGenerationError(f"exclusion {index} has invalid fields")
        rva_text = raw["rva"]
        reason = raw["reason"]
        if not isinstance(rva_text, str):
            raise OracleGenerationError(f"exclusion {index} RVA must be hexadecimal")
        try:
            rva = int(rva_text, 16)
        except ValueError as error:
            raise OracleGenerationError(f"exclusion {index} RVA is invalid") from error
        if rva < 0 or rva >= 1 << 64 or hex(rva) != rva_text:
            raise OracleGenerationError(f"exclusion {index} RVA is not canonical")
        if rva <= previous_rva:
            raise OracleGenerationError("exclusion RVAs must be unique and increasing")
        if (
            not isinstance(reason, str)
            or not reason
            or "\x00" in reason
            or len(reason) > 16_384
        ):
            raise OracleGenerationError(f"exclusion {index} reason is invalid")
        result[rva] = reason
        previous_rva = rva
    return artifact_sha256, result


def _merge_evidence(
    *sources: Iterable[GenerationEvidence],
) -> list[dict[str, str]]:
    merged = sorted({item for source in sources for item in source})
    if not merged or len(merged) > MAX_GENERATED_EVIDENCE:
        raise OracleGenerationError("generated alias evidence count is outside limits")
    return [{"kind": item.kind, "locator": item.locator} for item in merged]


def _artifact_document(facts: ElfArtifactFacts) -> dict[str, Any]:
    return {
        "inputSha256": facts.input_sha256,
        "elfType": facts.elf_type,
        "elfImageBase": hex(facts.image_base),
        "executableRvaRanges": [
            {"start": hex(start), "endExclusive": hex(end)}
            for start, end in facts.executable_ranges
        ],
    }


def generate_function_oracle(
    rich_path: Path,
    stripped_path: Path,
    *,
    oracle_id: str,
    artifact_manifest_sha256: str,
    explicit_exclusions: Mapping[int, str],
    expected_rich_sha256: str | None = None,
    expected_stripped_sha256: str | None = None,
    near_miss_bytes: int = 16,
    symbol_name_selector: Callable[[str], bool] | None = None,
    compilation_unit_selector: Callable[[str], bool] | None = None,
    include_inline_only: bool = True,
) -> dict[str, Any]:
    """Generate a closed function oracle from an arbitrary compatible ELF pair."""

    if not oracle_id or "\x00" in oracle_id:
        raise OracleGenerationError("oracle id must be a non-empty string")
    if len(oracle_id) > 4096:
        raise OracleGenerationError("oracle id exceeds 4096 characters")
    if (
        len(artifact_manifest_sha256) != 64
        or any(character not in "0123456789abcdef" for character in artifact_manifest_sha256)
    ):
        raise OracleGenerationError("artifact manifest SHA-256 is invalid")
    if isinstance(near_miss_bytes, bool) or not 1 <= near_miss_bytes <= 4096:
        raise OracleGenerationError("near-miss distance must be between 1 and 4096")
    for rva, exclusion_reason in explicit_exclusions.items():
        if (
            isinstance(rva, bool)
            or not isinstance(rva, int)
            or rva < 0
            or rva >= 1 << 64
        ):
            raise OracleGenerationError("explicit exclusion RVA is invalid")
        if (
            not isinstance(exclusion_reason, str)
            or not exclusion_reason
            or "\x00" in exclusion_reason
            or len(exclusion_reason) > 16_384
        ):
            raise OracleGenerationError(
                f"explicit exclusion reason at {hex(rva)} is invalid"
            )

    rich = inspect_elf_functions(
        rich_path,
        twin="rich",
        symbol_name_selector=symbol_name_selector,
        compilation_unit_selector=compilation_unit_selector,
        include_inline_only=include_inline_only,
    )
    stripped = inspect_elf_functions(
        stripped_path,
        twin="stripped",
        symbol_name_selector=symbol_name_selector,
        compilation_unit_selector=compilation_unit_selector,
        include_inline_only=include_inline_only,
    )
    if expected_rich_sha256 is not None and rich.input_sha256 != expected_rich_sha256:
        raise OracleGenerationError("rich artifact hash does not match its profile")
    if expected_stripped_sha256 is not None and stripped.input_sha256 != expected_stripped_sha256:
        raise OracleGenerationError("stripped artifact hash does not match its profile")
    for field in ("elf_type", "image_base", "executable_ranges"):
        if getattr(rich, field) != getattr(stripped, field):
            raise OracleGenerationError(f"ELF twins disagree on {field}")
    stripped_only_rvas = set(stripped.aliases_by_rva) - set(rich.aliases_by_rva)
    if stripped_only_rvas:
        raise OracleGenerationError(
            "stripped twin introduces an emitted RVA absent from the rich twin: "
            f"{hex(min(stripped_only_rvas))}"
        )
    missing_exclusions = set(explicit_exclusions) - set(rich.aliases_by_rva)
    if missing_exclusions:
        raise OracleGenerationError(
            "explicit exclusion does not identify an emitted rich RVA: "
            f"{hex(min(missing_exclusions))}"
        )

    functions: list[dict[str, Any]] = []
    for rva in sorted(rich.aliases_by_rva):
        rich_aliases = rich.aliases_by_rva[rva]
        stripped_aliases = stripped.aliases_by_rva.get(rva, {})
        stripped_only_names = set(stripped_aliases) - set(rich_aliases)
        if stripped_only_names:
            raise OracleGenerationError(
                f"stripped twin introduces alias {min(stripped_only_names)!r} at {hex(rva)}"
            )
        aliases: list[dict[str, Any]] = []
        for name in sorted(rich_aliases):
            rich_evidence = rich_aliases[name]
            aliases.append(
                {
                    "name": name,
                    "evidence": _merge_evidence(
                        rich_evidence,
                        stripped_aliases.get(name, ()),
                    ),
                    "availability": {
                        "rich": "surviving",
                        "stripped": (
                            "surviving" if name in stripped_aliases else "removed"
                        ),
                    },
                }
            )
        if not aliases or len(aliases) > MAX_GENERATED_ALIASES:
            raise OracleGenerationError(
                f"emitted RVA {hex(rva)} has an unsupported alias count"
            )
        reviewed_reason = explicit_exclusions.get(rva)
        functions.append(
            {
                "id": f"function-rva-{hex(rva)}",
                "rva": hex(rva),
                "aliases": aliases,
                "exclusion": (
                    None
                    if reviewed_reason is None
                    else {
                        "kind": "compiler-generated",
                        "reason": reviewed_reason,
                    }
                ),
            }
        )

    for die_offset, aliases_by_name in sorted(rich.inline_only, key=lambda item: item[0]):
        aliases = [
            {
                "name": name,
                "evidence": _merge_evidence(evidence),
                "availability": {
                    "rich": "not-observable",
                    "stripped": "not-observable",
                },
            }
            for name, evidence in sorted(aliases_by_name.items())
        ]
        if not aliases or len(aliases) > MAX_GENERATED_ALIASES:
            raise OracleGenerationError(
                f"inline-only DIE {hex(die_offset)} has an unsupported alias count"
            )
        functions.append(
            {
                "id": f"inline-die-{hex(die_offset)}",
                "rva": None,
                "aliases": aliases,
                "exclusion": {
                    "kind": "inlined",
                    "reason": (
                        "DWARF subprogram is marked inline-only and has no emitted "
                        "address range."
                    ),
                },
            }
        )
    if not functions or len(functions) > MAX_GENERATED_FUNCTIONS:
        raise OracleGenerationError("generated function count is outside schema limits")

    return {
        "schemaVersion": 1,
        "scope": "production",
        "oracle": {
            "id": oracle_id,
            "source": "dwarf-and-symbols",
            "artifactManifestSha256": artifact_manifest_sha256,
        },
        "artifacts": {
            "rich": _artifact_document(rich),
            "stripped": _artifact_document(stripped),
        },
        "scoringPolicy": {"nearMissBytes": near_miss_bytes},
        "functions": functions,
    }


def oracle_json_bytes(document: Mapping[str, Any]) -> bytes:
    """Serialize a generated oracle deterministically."""

    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def write_oracle(path: Path, document: Mapping[str, Any]) -> None:
    """Atomically publish deterministic oracle bytes."""

    payload = oracle_json_bytes(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
