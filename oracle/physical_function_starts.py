"""Bounded physical ELF/DWARF starts for diagnostic analyzer comparisons.

The caller authenticates the artifact manifest and supplies its private rich-ELF
snapshot. This helper verifies those bytes again. It includes both defined
STT_FUNC starts and emitted DW_TAG_subprogram starts, with no name heuristics or
policy exclusions. These physical observations are not a reviewed source-function
oracle, an analyzer-execution attestation, or production accuracy qualification.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from oracle.function_recovery_oracle import (
    MAX_DWARF_RANGE_SECTION_BYTES,
    MAX_SCANNED_DIES,
    MAX_SCANNED_SUBPROGRAMS,
    MAX_SCANNED_SYMBOLS,
    _dwarf_starts,
    _in_executable_range,
    _open_stable_regular,
    _range_section_logical_size,
    _require_pyelftools,
    _sha256_file,
    _stable_identity,
)


MAX_PHYSICAL_STARTS = 131_072
MAX_COMPILATION_UNITS = 100_000
MAX_EXECUTABLE_RANGES = 256
MAX_SECTIONS = 65_536
MAX_SEGMENTS = 65_536
_ADDRESS_END = 1 << 64


class PhysicalFunctionStartsError(ValueError):
    """A complete, bounded physical-start observation could not be produced."""


def collect_physical_function_starts(
    rich_artifact: Path,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Return complete physical starts from one stable, hash-bound rich ELF.

    Counts explicitly retain declarations, addressless definitions and discarded
    addresses. Missing DWARF, malformed forms and exhausted bounds fail instead
    of silently substituting a symbol-only or truncated population. No files are
    written, and external debug links are never followed.
    """
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise PhysicalFunctionStartsError("expected ELF SHA-256 is not canonical")
    stream = None
    try:
        ELFFile, SymbolTableSection, BaseAddressEntry, RangeEntry, describe_form_class = _require_pyelftools()
        stream, before = _open_stable_regular(rich_artifact, "physical-start rich ELF")
        observed_sha256 = _sha256_file(stream)
        if observed_sha256 != expected_sha256:
            raise PhysicalFunctionStartsError("rich ELF SHA-256 differs from the authenticated input")
        elf = ELFFile(stream)
        if elf.header["e_type"] not in {"ET_EXEC", "ET_DYN"}:
            raise PhysicalFunctionStartsError("physical-start ELF must be ET_EXEC or ET_DYN")
        loads = []
        for segment_index, segment in enumerate(elf.iter_segments()):
            if segment_index >= MAX_SEGMENTS:
                raise PhysicalFunctionStartsError("ELF segment count exceeds its bound")
            if segment["p_type"] == "PT_LOAD" and int(segment["p_memsz"]) > 0:
                loads.append(segment)
        if not loads:
            raise PhysicalFunctionStartsError("physical-start ELF has no nonempty load segments")
        if any(not 0 <= int(segment["p_vaddr"]) < _ADDRESS_END or
               int(segment["p_vaddr"]) + int(segment["p_memsz"]) > _ADDRESS_END for segment in loads):
            raise PhysicalFunctionStartsError("ELF load address exceeds unsigned 64-bit range")
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        executable = tuple(sorted(
            (int(segment["p_vaddr"]) - image_base,
             int(segment["p_vaddr"]) + int(segment["p_memsz"]) - image_base)
            for segment in loads if int(segment["p_flags"]) & 1
        ))
        if not 1 <= len(executable) <= MAX_EXECUTABLE_RANGES:
            raise PhysicalFunctionStartsError("ELF executable-range count is outside its bound")
        if any(current[0] < previous[1] for previous, current in zip(executable, executable[1:])):
            raise PhysicalFunctionStartsError("ELF executable load ranges overlap")

        starts: dict[int, set[str]] = {}
        counts = {
            "scannedSymbols": 0, "undefinedFunctionSymbols": 0,
            "unnamedFunctionSymbols": 0, "outsideExecutableFunctionSymbols": 0,
            "compilationUnits": 0, "scannedDies": 0, "scannedSubprograms": 0,
            "declarationSubprograms": 0, "noEmittedStartSubprograms": 0,
            "outsideExecutableSubprograms": 0,
        }

        def add(address: int, source: str) -> None:
            rva = address - image_base
            if rva not in starts:
                if len(starts) >= MAX_PHYSICAL_STARTS:
                    raise PhysicalFunctionStartsError("physical starts exceed the unique-entry bound")
                starts[rva] = set()
            starts[rva].add(source)

        for section_index, section in enumerate(elf.iter_sections()):
            if section_index >= MAX_SECTIONS:
                raise PhysicalFunctionStartsError("ELF section count exceeds its bound")
            if section.name in {".debug_ranges", ".debug_rnglists", ".zdebug_ranges", ".zdebug_rnglists"}:
                if _range_section_logical_size(section, stream, "rich") > MAX_DWARF_RANGE_SECTION_BYTES:
                    raise PhysicalFunctionStartsError("DWARF range section exceeds its logical-size bound")
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                counts["scannedSymbols"] += 1
                if counts["scannedSymbols"] > MAX_SCANNED_SYMBOLS:
                    raise PhysicalFunctionStartsError("ELF symbol scan exceeds its bound")
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF":
                    counts["undefinedFunctionSymbols"] += 1
                    continue
                if not symbol.name:
                    counts["unnamedFunctionSymbols"] += 1
                elif len(symbol.name) > 4096:
                    raise PhysicalFunctionStartsError("ELF function symbol name exceeds its bound")
                symbol.name.encode("utf-8")
                address = int(symbol["st_value"])
                if not _in_executable_range(address, image_base, executable):
                    counts["outsideExecutableFunctionSymbols"] += 1
                    continue
                add(address, "symbol")

        if not elf.has_dwarf_info():
            raise PhysicalFunctionStartsError("rich ELF has no DWARF; symbol-only comparison is unavailable")
        dwarf = elf.get_dwarf_info(follow_links=False)
        for descriptor_name in ("debug_ranges_sec", "debug_rnglists_sec"):
            descriptor = getattr(dwarf, descriptor_name, None)
            if descriptor is not None and int(descriptor.size) > MAX_DWARF_RANGE_SECTION_BYTES:
                raise PhysicalFunctionStartsError("DWARF range section exceeds its logical-size bound")
        for unit in dwarf.iter_CUs():
            counts["compilationUnits"] += 1
            if counts["compilationUnits"] > MAX_COMPILATION_UNITS:
                raise PhysicalFunctionStartsError("DWARF compilation-unit scan exceeds its bound")
            for die in unit.iter_DIEs():
                counts["scannedDies"] += 1
                if counts["scannedDies"] > MAX_SCANNED_DIES:
                    raise PhysicalFunctionStartsError("DWARF DIE scan exceeds its bound")
                if die.tag != "DW_TAG_subprogram":
                    continue
                counts["scannedSubprograms"] += 1
                if counts["scannedSubprograms"] > MAX_SCANNED_SUBPROGRAMS:
                    raise PhysicalFunctionStartsError("DWARF subprogram scan exceeds its bound")
                declaration = die.attributes.get("DW_AT_declaration")
                if declaration is not None and bool(declaration.value):
                    counts["declarationSubprograms"] += 1
                    continue
                addresses = _dwarf_starts(die, dwarf, BaseAddressEntry, RangeEntry, describe_form_class)
                if not addresses:
                    counts["noEmittedStartSubprograms"] += 1
                elif not any(_in_executable_range(address, image_base, executable) for address in addresses):
                    counts["outsideExecutableSubprograms"] += 1
                for address in addresses:
                    if _in_executable_range(address, image_base, executable):
                        add(address, "dwarf")
            # Pyelftools is version-pinned. Release its CU caches after each unit,
            # as the existing full-tree observation scanner does.
            dwarf._cu_cache.clear()
            dwarf._cu_offsets_map.clear()
        if counts["scannedSubprograms"] == 0:
            raise PhysicalFunctionStartsError("rich DWARF contains no subprograms; refusing symbol-only comparison")
        if not any("dwarf" in sources for sources in starts.values()):
            raise PhysicalFunctionStartsError("rich DWARF has no emitted executable starts; refusing symbol-only comparison")
        if _stable_identity(before) != _stable_identity(os.fstat(stream.fileno())):
            raise PhysicalFunctionStartsError("rich ELF changed while physical starts were collected")
        counts.update({
            "functions": len(starts),
            "symbolFunctions": sum("symbol" in sources for sources in starts.values()),
            "dwarfFunctions": sum("dwarf" in sources for sources in starts.values()),
            "bothSources": sum(len(sources) == 2 for sources in starts.values()),
        })
        return {
            "inputSha256": observed_sha256,
            "elfImageBase": hex(image_base),
            "executableRvaRanges": [{"start": hex(start), "endExclusive": hex(end)} for start, end in executable],
            "functions": [{"rva": hex(rva), "sources": sorted(starts[rva])} for rva in sorted(starts)],
            "counts": counts,
        }
    except PhysicalFunctionStartsError:
        raise
    except Exception as error:
        raise PhysicalFunctionStartsError(f"cannot collect complete physical function starts: {error}") from error
    finally:
        if stream is not None:
            stream.close()
