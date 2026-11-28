from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import oracle.physical_function_starts as collector


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class Symbol(dict):
    def __init__(self, address: int, name: str = "ordinary", *, defined: bool = True) -> None:
        super().__init__(st_info={"type": "STT_FUNC"}, st_shndx=1 if defined else "SHN_UNDEF", st_value=address)
        self.name = name


class Symbols:
    name = ".symtab"

    def __init__(self, values: list[Symbol]) -> None:
        self.values = values

    def iter_symbols(self):
        return iter(self.values)


def attribute(value, form="DW_FORM_addr"):
    return SimpleNamespace(value=value, form=form)


def subprogram(address=None, **attributes):
    if address is not None:
        attributes["DW_AT_low_pc"] = attribute(address)
    return SimpleNamespace(tag="DW_TAG_subprogram", offset=0x10, attributes=attributes)


class Unit:
    structs = SimpleNamespace(little_endian=True)

    def __init__(self, dies) -> None:
        self.dies = dies
        for die in dies:
            die.cu = self

    def iter_DIEs(self):
        return iter(self.dies)

    def get_top_DIE(self):
        return SimpleNamespace(offset=0, attributes={})


class Dwarf:
    def __init__(self, units, on_finish=lambda: None) -> None:
        self.units = units
        self.on_finish = on_finish
        self._cu_cache = {}
        self._cu_offsets_map = {}

    def iter_CUs(self):
        yield from self.units
        self.on_finish()


class Elf:
    header = {"e_type": "ET_EXEC"}

    def __init__(self, symbols=None, dies=None, *, dwarf=True) -> None:
        self.symbols = [Symbol(0x401010)] if symbols is None else symbols
        self.dwarf = Dwarf([Unit([subprogram(0x401010)] if dies is None else dies)])
        self.with_dwarf = dwarf
        self.loads = [
            {"p_type": "PT_LOAD", "p_vaddr": 0x400000, "p_memsz": 0x1000, "p_flags": 4},
            {"p_type": "PT_LOAD", "p_vaddr": 0x401000, "p_memsz": 0x100, "p_flags": 5},
        ]
        self.sections = [Symbols(self.symbols)]
        self.follow_links = None

    def iter_segments(self):
        return iter(self.loads)

    def iter_sections(self):
        return iter(self.sections)

    def has_dwarf_info(self):
        return self.with_dwarf

    def get_dwarf_info(self, *, follow_links):
        self.follow_links = follow_links
        return self.dwarf


def form_class(form):
    return {"DW_FORM_addr": "address", "DW_FORM_data4": "constant"}.get(form)


class PhysicalFunctionStartsTest(unittest.TestCase):
    def setUp(self) -> None:
        scratch = REPOSITORY_ROOT / "build/physical-function-start-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rich = self.root / "rich.elf"
        self.rich.write_bytes(b"authored ELF stand-in")
        self.digest = hashlib.sha256(self.rich.read_bytes()).hexdigest()

    def collect(self, elf=None, *, expected=None):
        selected = Elf() if elf is None else elf
        primitives = (lambda stream: selected, Symbols, type("BaseAddress", (), {}), type("Range", (), {}), form_class)
        with patch.object(collector, "_require_pyelftools", return_value=primitives):
            return collector.collect_physical_function_starts(self.rich, expected_sha256=self.digest if expected is None else expected)

    def test_union_keeps_all_origins_aliases_and_generated_looking_symbols(self):
        elf = Elf([Symbol(0x401030, "named.cold"), Symbol(0x401010), Symbol(0x401010, "alias")],
                  [subprogram(0x401020), subprogram(0x401010)])
        result = self.collect(elf)
        self.assertEqual([
            {"rva": "0x1010", "sources": ["dwarf", "symbol"]},
            {"rva": "0x1020", "sources": ["dwarf"]},
            {"rva": "0x1030", "sources": ["symbol"]},
        ], result["functions"])
        self.assertEqual("0x400000", result["elfImageBase"])
        self.assertEqual(self.digest, result["inputSha256"])
        self.assertEqual(3, result["counts"]["functions"])
        self.assertEqual(2, result["counts"]["symbolFunctions"])
        self.assertEqual(2, result["counts"]["dwarfFunctions"])
        self.assertEqual(1, result["counts"]["bothSources"])
        self.assertIs(elf.follow_links, False)

    def test_retains_counts_for_non_emitted_and_discarded_evidence(self):
        elf = Elf([Symbol(0x401010), Symbol(0, defined=False), Symbol(0x401020, ""), Symbol(0x400000)], [
            subprogram(0x401010), subprogram(DW_AT_inline=attribute(3, "DW_FORM_data4")),
            subprogram(DW_AT_declaration=attribute(True, "DW_FORM_data4")), subprogram(0),
        ])
        result = self.collect(elf)
        for key in ("undefinedFunctionSymbols", "unnamedFunctionSymbols", "outsideExecutableFunctionSymbols",
                    "noEmittedStartSubprograms", "declarationSubprograms", "outsideExecutableSubprograms"):
            self.assertEqual(1, result["counts"][key], key)
        self.assertEqual(2, result["counts"]["functions"])
        self.assertIn({"rva": "0x1020", "sources": ["symbol"]}, result["functions"])

    def test_uses_generic_entry_pc_constant_and_rejects_unsupported_form(self):
        die = subprogram(0x401020, DW_AT_entry_pc=attribute(4, "DW_FORM_data4"))
        result = self.collect(Elf([], [die]))
        self.assertEqual([{"rva": "0x1024", "sources": ["dwarf"]}], result["functions"])
        die.attributes["DW_AT_entry_pc"].form = "DW_FORM_string"
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "form"):
            self.collect(Elf([], [die]))

    def test_refuses_wrong_hash_symlink_and_missing_dwarf(self):
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "SHA-256 differs"):
            self.collect(expected="0" * 64)
        for digest in ("ABC", "f" * 63, None):
            with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "not canonical"):
                collector.collect_physical_function_starts(self.rich, expected_sha256=digest)
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "no DWARF"):
            self.collect(Elf(dwarf=False))
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "no subprograms"):
            self.collect(Elf(dies=[]))
        target = self.rich.with_name("actual.elf")
        self.rich.rename(target)
        self.rich.symlink_to(target.name)
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "non-symlink"):
            self.collect()

    def test_refuses_changed_file_during_scan(self):
        elf = Elf()
        elf.dwarf.on_finish = lambda: self.rich.write_bytes(b"changed after authentication")
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "changed while"):
            self.collect(elf)

    def test_refuses_symbol_only_when_dwarf_has_no_executable_definition(self):
        for die in (
            subprogram(DW_AT_declaration=attribute(True, "DW_FORM_data4")),
            subprogram(DW_AT_inline=attribute(3, "DW_FORM_data4")),
            subprogram(0),
        ):
            with self.subTest(attributes=die.attributes):
                with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "no emitted executable starts"):
                    self.collect(Elf(dies=[die]))

    def test_segment_bound_stops_enumeration_before_materializing_remaining_segments(self):
        elf = Elf()

        def segments():
            yield elf.loads[0]
            yield elf.loads[1]
            self.fail("segment iteration continued after its bound")

        elf.iter_segments = segments
        with patch.object(collector, "MAX_SEGMENTS", 1):
            with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "segment count"):
                self.collect(elf)

    def test_rejects_unsupported_or_overlapping_elf_layout(self):
        elf = Elf()
        elf.header = {"e_type": "ET_REL"}
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "ET_EXEC or ET_DYN"):
            self.collect(elf)
        elf.header = {"e_type": "ET_EXEC"}
        elf.loads.append(dict(elf.loads[1]))
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "overlap"):
            self.collect(elf)
        elf.loads[-1]["p_vaddr"] = 1 << 64
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "64-bit"):
            self.collect(elf)

    def test_rejects_population_bounds_without_truncating(self):
        cases = [
            ("MAX_PHYSICAL_STARTS", 1, Elf([Symbol(0x401010), Symbol(0x401020)]), "unique-entry"),
            ("MAX_SCANNED_SYMBOLS", 1, Elf([Symbol(0x401010), Symbol(0x401010)]), "symbol scan"),
            ("MAX_SCANNED_DIES", 1, Elf(dies=[subprogram(0x401010), subprogram(0x401010)]), "DIE scan"),
            ("MAX_SCANNED_SUBPROGRAMS", 1, Elf(dies=[subprogram(0x401010), subprogram(0x401010)]), "subprogram scan"),
            ("MAX_COMPILATION_UNITS", 0, Elf(), "compilation-unit"),
            ("MAX_SECTIONS", 0, Elf(), "section count"),
        ]
        for name, bound, elf, message in cases:
            with self.subTest(name=name), patch.object(collector, name, bound):
                with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, message):
                    self.collect(elf)

    def test_rejects_oversized_range_sections_before_dwarf_loading(self):
        elf = Elf()
        elf.sections.append(SimpleNamespace(name=".debug_rnglists", data_size=collector.MAX_DWARF_RANGE_SECTION_BYTES + 1))
        with self.assertRaisesRegex(collector.PhysicalFunctionStartsError, "logical-size"):
            self.collect(elf)
        self.assertIsNone(elf.follow_links)

    def test_compact_census_supports_engine_population_above_legacy_limit(self):
        count = 50_001
        elf = Elf([Symbol(0x401000 + index) for index in range(count)])
        elf.loads[1]["p_memsz"] = count + 1
        result = self.collect(elf)
        self.assertEqual(count, result["counts"]["functions"])
        self.assertEqual(count, result["counts"]["symbolFunctions"])
        self.assertEqual(1, result["counts"]["dwarfFunctions"])
        self.assertEqual("0x1000", result["functions"][0]["rva"])
        self.assertEqual(hex(0x1000 + count - 1), result["functions"][-1]["rva"])

    @unittest.skipUnless(shutil.which("gcc"), "authored ELF control requires gcc")
    def test_real_authored_elf_produces_deterministic_combined_starts(self):
        source = self.root / "authored.c"
        source.write_text("int answer(void) { return 42; }\n"
                          "extern int answer_alias(void) __attribute__((alias(\"answer\")));\n"
                          "int main(void) { return answer_alias(); }\n")
        subprocess.run(["gcc", "-g", "-O0", "-no-pie", str(source), "-o", str(self.rich)],
                       check=True, capture_output=True, timeout=30,
                       env={**os.environ, "TMPDIR": str(self.root)})
        digest = hashlib.sha256(self.rich.read_bytes()).hexdigest()
        first = collector.collect_physical_function_starts(self.rich, expected_sha256=digest)
        second = collector.collect_physical_function_starts(self.rich, expected_sha256=digest)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first["counts"]["bothSources"], 2)
        self.assertGreater(first["counts"]["symbolFunctions"], first["counts"]["dwarfFunctions"])
        self.assertEqual(len(first["functions"]), len({item["rva"] for item in first["functions"]}))


if __name__ == "__main__":
    unittest.main()
