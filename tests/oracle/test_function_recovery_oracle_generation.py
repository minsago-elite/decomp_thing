from __future__ import annotations

from collections import Counter
import inspect
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import fastjsonschema  # type: ignore[import-untyped]

from oracle.function_recovery import load_function_oracle
import oracle.function_recovery_oracle as generator
from oracle.function_recovery_oracle import (
    ElfArtifactFacts,
    GenerationEvidence,
    OracleGenerationError,
    generate_function_oracle,
    load_explicit_exclusions,
)
from oracle.gcc.generate_function_recovery_oracle import (
    generate_gcc_profile_oracle,
)
import oracle.gcc.generate_function_recovery_oracle as gcc_generator
import oracle.gcc.score_function_recovery as gcc_adapter


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROFILE_ROOT = REPOSITORY_ROOT / "oracle/gcc/16.2.0"
MANIFEST = PROFILE_ROOT / "oracle-manifest.json"
EXCLUSIONS = PROFILE_ROOT / "function-recovery-exclusions.json"
PRODUCTION_ORACLE = PROFILE_ROOT / "function-recovery-oracle.json"
ORACLE_SCHEMA = REPOSITORY_ROOT / "oracle/function-recovery-oracle.schema.json"


class FunctionRecoveryOracleGenerationTest(unittest.TestCase):
    @staticmethod
    def artifact(
        sha256: str,
        aliases: dict[int, dict[str, tuple[GenerationEvidence, ...]]],
        *,
        inline: tuple[
            tuple[int, dict[str, tuple[GenerationEvidence, ...]]], ...
        ] = (),
    ) -> ElfArtifactFacts:
        return ElfArtifactFacts(
            input_sha256=sha256,
            elf_type="ET_EXEC",
            image_base=0x400000,
            executable_ranges=((0x10, 0x100),),
            aliases_by_rva=aliases,
            inline_only=inline,
        )

    def test_generic_normalizer_applies_only_explicit_rva_policy(self) -> None:
        dwarf = GenerationEvidence("dwarf-subprogram", "rich:die=0x1")
        rich_symbol = GenerationEvidence("elf-symbol", "rich:.symtab[1]")
        stripped_symbol = GenerationEvidence("elf-symbol", "stripped:.dynsym[1]")
        rich = self.artifact(
            "a" * 64,
            {
                0x10: {"looks.generated.cold": (dwarf, rich_symbol)},
                0x20: {"ordinary": (rich_symbol,)},
            },
            inline=((0x33, {"inline_name": (dwarf,)}),),
        )
        stripped = self.artifact(
            "b" * 64,
            {0x10: {"looks.generated.cold": (stripped_symbol,)}},
        )
        with patch.object(
            generator,
            "inspect_elf_functions",
            side_effect=(rich, stripped),
        ):
            document = generate_function_oracle(
                Path("rich"),
                Path("stripped"),
                oracle_id="arbitrary-program",
                artifact_manifest_sha256="c" * 64,
                explicit_exclusions={0x20: "Reviewed profile decision."},
            )

        functions = {item["id"]: item for item in document["functions"]}
        inferred_looking = functions["function-rva-0x10"]
        self.assertIsNone(inferred_looking["exclusion"])
        self.assertEqual(
            "surviving",
            inferred_looking["aliases"][0]["availability"]["stripped"],
        )
        self.assertEqual(
            {
                "kind": "compiler-generated",
                "reason": "Reviewed profile decision.",
            },
            functions["function-rva-0x20"]["exclusion"],
        )
        inline = functions["inline-die-0x33"]
        self.assertIsNone(inline["rva"])
        self.assertEqual("inlined", inline["exclusion"]["kind"])
        self.assertEqual(
            {"rich": "not-observable", "stripped": "not-observable"},
            inline["aliases"][0]["availability"],
        )

        generic_source = inspect.getsource(generator).lower()
        for benchmark_rule in (".cold", "constprop", "_zgtt", "gcc-driver"):
            self.assertNotIn(benchmark_rule, generic_source)

    def test_discontiguous_dwarf_ranges_choose_one_producer_ordered_entry(self) -> None:
        from elftools.dwarf.descriptions import (  # type: ignore[import-untyped]
            describe_form_class as form_class,
        )

        class Attribute:
            def __init__(self, value: object, form: str) -> None:
                self.value = value
                self.form = form

        class BaseAddress:
            def __init__(self, value: int) -> None:
                self.base_address = value

        class Range:
            def __init__(
                self,
                begin: int,
                end: int,
                *,
                absolute: bool = True,
            ) -> None:
                self.begin_offset = begin
                self.end_offset = end
                self.is_absolute = absolute

        class CompilationUnit:
            structs = SimpleNamespace(little_endian=True)

            @staticmethod
            def get_top_DIE() -> SimpleNamespace:
                return SimpleNamespace(
                    offset=0,
                    attributes={
                        "DW_AT_low_pc": Attribute(0x1000, "DW_FORM_addr")
                    }
                )

        class RangeLists:
            def __init__(self, entries: list[object]) -> None:
                self.entries = entries

            def get_range_list_at_offset(
                self,
                offset: int,
                compilation_unit: object,
            ) -> list[object]:
                self.last_request = (offset, compilation_unit)
                return self.entries

        class DwarfInfo:
            def __init__(self, entries: list[object]) -> None:
                self.lists = RangeLists(entries)

            def range_lists(self) -> RangeLists:
                return self.lists

        compilation_unit = CompilationUnit()
        die = SimpleNamespace(
            offset=0x44,
            cu=compilation_unit,
            attributes={"DW_AT_ranges": SimpleNamespace(value=7)},
        )
        dwarf_info = DwarfInfo(
            [
                Range(0, 0),
                Range(0x9000, 0x9010),
                Range(0x2000, 0x2010),
            ]
        )
        self.assertEqual(
            (0x9000,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        die.attributes["DW_AT_low_pc"] = Attribute(0x3000, "DW_FORM_addrx")
        self.assertEqual(
            (0x3000,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )
        die.attributes["DW_AT_entry_pc"] = Attribute(0x3010, "DW_FORM_addr")
        self.assertEqual(
            (0x3010,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        die.attributes["DW_AT_entry_pc"] = Attribute(0x10, "DW_FORM_data4")
        self.assertEqual(
            (0x3010,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        die.attributes["DW_AT_entry_pc"] = Attribute(
            [0x10, *([0] * 15)],
            "DW_FORM_data16",
        )
        self.assertEqual(
            (0x3010,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        del die.attributes["DW_AT_low_pc"]
        self.assertEqual(
            (0x9010,),
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        die.attributes["DW_AT_entry_pc"] = Attribute(1, "DW_FORM_sec_offset")
        with self.assertRaisesRegex(OracleGenerationError, "unsupported DWARF form"):
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            )
        die.attributes["DW_AT_entry_pc"] = SimpleNamespace(value=1)
        with self.assertRaisesRegex(OracleGenerationError, "no resolved DWARF form"):
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            )
        die.attributes["DW_AT_entry_pc"] = Attribute(1, "DW_FORM_implicit_const")
        die.attributes.pop("DW_AT_ranges")
        with self.assertRaisesRegex(OracleGenerationError, "without a function base"):
            generator._dwarf_starts(
                die,
                dwarf_info,
                BaseAddress,
                Range,
                form_class,
            )

        relative_die = SimpleNamespace(
            offset=0x45,
            cu=compilation_unit,
            attributes={"DW_AT_ranges": SimpleNamespace(value=8)},
        )
        relative_info = DwarfInfo(
            [BaseAddress(0x5000), Range(0x20, 0x30, absolute=False)]
        )
        self.assertEqual(
            (0x5020,),
            generator._dwarf_starts(
                relative_die,
                relative_info,
                BaseAddress,
                Range,
                form_class,
            ),
        )

        with patch.object(generator, "MAX_DWARF_RANGE_ENTRIES", 1):
            with self.assertRaisesRegex(OracleGenerationError, "1-entry range-list"):
                generator._dwarf_starts(
                    relative_die,
                    DwarfInfo([Range(0, 0), Range(1, 2)]),
                    BaseAddress,
                    Range,
                    form_class,
                )

        class MemoryRangeLists(RangeLists):
            def get_range_list_at_offset(
                self,
                offset: int,
                compilation_unit: object,
            ) -> list[object]:
                raise MemoryError("synthetic range allocation failure")

        memory_info = DwarfInfo([])
        memory_info.lists = MemoryRangeLists([])
        with self.assertRaisesRegex(OracleGenerationError, "not enough memory"):
            generator._dwarf_starts(
                relative_die,
                memory_info,
                BaseAddress,
                Range,
                form_class,
            )

    def test_extraction_bounds_state_while_symbols_and_inline_dies_are_scanned(self) -> None:
        class Symbol(dict[str, object]):
            def __init__(self, address: int, name: str) -> None:
                super().__init__(
                    st_info={"type": "STT_FUNC"},
                    st_shndx=1,
                    st_value=address,
                )
                self.name = name

        class SymbolTable:
            name = ".symtab"

            def __init__(self, symbols: list[Symbol]) -> None:
                self.symbols = symbols

            def iter_symbols(self) -> object:
                return iter(self.symbols)

        class Segment(dict[str, object]):
            pass

        class Elf:
            header = {"e_type": "ET_EXEC"}

            def __init__(
                self,
                sections: list[object],
                dwarf_info: object | None = None,
            ) -> None:
                self.sections = sections
                self.dwarf_info = dwarf_info

            @staticmethod
            def iter_segments() -> object:
                return iter(
                    [
                        Segment(
                            p_type="PT_LOAD",
                            p_memsz=0x100,
                            p_vaddr=0x400000,
                            p_flags=5,
                        )
                    ]
                )

            def iter_sections(self) -> object:
                return iter(self.sections)

            def has_dwarf_info(self) -> bool:
                return self.dwarf_info is not None

            def get_dwarf_info(self, *, follow_links: bool = False) -> object:
                assert self.dwarf_info is not None
                return self.dwarf_info

        with tempfile.TemporaryDirectory(prefix="bounded-elf-facts-") as directory:
            path = Path(directory) / "input.elf"
            path.write_bytes(b"not parsed by the fake ELF reader")

            oversized_ranges = SimpleNamespace(
                name=".debug_rnglists",
                data_size=2,
            )
            fake_elf = Elf([oversized_ranges])
            with patch.object(
                generator,
                "_require_pyelftools",
                return_value=(
                    lambda stream: fake_elf,
                    SymbolTable,
                    object,
                    object,
                    lambda form: None,
                ),
            ), patch.object(generator, "MAX_DWARF_RANGE_SECTION_BYTES", 1):
                with self.assertRaisesRegex(
                    OracleGenerationError,
                    "1-byte logical-size limit",
                ):
                    generator.inspect_elf_functions(path, twin="rich")

            symbols = SymbolTable(
                [
                    Symbol(0x400010, "first"),
                    Symbol(0x400020, "second"),
                ]
            )
            fake_elf = Elf([symbols])
            with patch.object(
                generator,
                "_require_pyelftools",
                return_value=(
                    lambda stream: fake_elf,
                    SymbolTable,
                    object,
                    object,
                    lambda form: None,
                ),
            ), patch.object(generator, "MAX_GENERATED_FUNCTIONS", 1):
                with self.assertRaisesRegex(
                    OracleGenerationError,
                    "1-record generation limit",
                ):
                    generator.inspect_elf_functions(path, twin="rich")

            class InlineDie:
                tag = "DW_TAG_subprogram"

                def __init__(self, offset: int, compilation_unit: object) -> None:
                    self.offset = offset
                    self.cu = compilation_unit
                    self.attributes = {
                        "DW_AT_inline": SimpleNamespace(value=1),
                        "DW_AT_name": SimpleNamespace(value=f"inline_{offset}"),
                    }

            class CompilationUnit:
                def __init__(self) -> None:
                    self.dies = [InlineDie(1, self), InlineDie(2, self)]

                def iter_DIEs(self) -> object:
                    return iter(self.dies)

            class DwarfInfo:
                def __init__(self) -> None:
                    self.compilation_unit = CompilationUnit()

                def iter_CUs(self) -> object:
                    return iter([self.compilation_unit])

            fake_elf = Elf([], DwarfInfo())
            with patch.object(
                generator,
                "_require_pyelftools",
                return_value=(
                    lambda stream: fake_elf,
                    SymbolTable,
                    object,
                    object,
                    lambda form: None,
                ),
            ), patch.object(generator, "MAX_GENERATED_FUNCTIONS", 1):
                with self.assertRaisesRegex(
                    OracleGenerationError,
                    "1-record generation limit",
                ):
                    generator.inspect_elf_functions(path, twin="rich")

    def test_exclusion_profile_is_closed_sorted_and_artifact_bound(self) -> None:
        artifact_sha256, exclusions = load_explicit_exclusions(EXCLUSIONS)
        self.assertEqual(
            "8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b",
            artifact_sha256,
        )
        self.assertEqual(140, len(exclusions))
        self.assertEqual(sorted(exclusions), list(exclusions))
        for co_located_source_rva in (
            0x10BCE0,
            0x10BDF0,
            0x10D1E0,
            0x10D270,
            0x10D580,
        ):
            self.assertNotIn(co_located_source_rva, exclusions)

        with tempfile.TemporaryDirectory(prefix="exclusion-mutation-") as directory:
            path = Path(directory) / "exclusions.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "richArtifactSha256": "a" * 64,
                        "exclusions": [
                            {"rva": "0x20", "reason": "second"},
                            {"rva": "0x10", "reason": "first"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(OracleGenerationError, "unique and increasing"):
                load_explicit_exclusions(path)

    def test_generation_uses_one_coherent_bounded_manifest_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="function-oracle-snapshot-"
        ) as directory:
            copied_profile = Path(directory) / "profile"
            shutil.copytree(PROFILE_ROOT, copied_profile)
            manifest = copied_profile / MANIFEST.name
            source_lock = copied_profile / "source-lock.json"
            output = Path(directory) / "generated.json"
            original_reader = gcc_adapter._read_regular_snapshot
            original_stager = gcc_adapter._stage_bounded_regular_snapshot
            source_replaced = False
            rich_replaced = False

            with self.assertRaisesRegex(
                OracleGenerationError,
                "output must not replace a generation input",
            ):
                generate_gcc_profile_oracle(
                    manifest_path=manifest,
                    exclusions_path=copied_profile / EXCLUSIONS.name,
                    output_path=source_lock,
                    schema_path=ORACLE_SCHEMA,
                )

            def replace_source_after_snapshot(
                path: Path,
                label: str,
                maximum_bytes: int,
            ) -> bytes | bytearray:
                nonlocal source_replaced
                payload = original_reader(path, label, maximum_bytes)
                if label == "source lock" and not source_replaced:
                    replacement = path.with_name(f".{path.name}.replacement")
                    replacement.write_text("{}\n", encoding="utf-8")
                    replacement.replace(path)
                    source_replaced = True
                return payload

            def replace_rich_after_staging(
                source: Path,
                destination: Path,
                label: str,
                maximum_bytes: int,
                *,
                expected_bytes: int | None = None,
            ) -> None:
                nonlocal rich_replaced
                original_stager(
                    source,
                    destination,
                    label,
                    maximum_bytes,
                    expected_bytes=expected_bytes,
                )
                if label == "full artifact" and not rich_replaced:
                    replacement = source.with_name(f".{source.name}.replacement")
                    replacement.write_bytes(b"mutated after stable staging\n")
                    replacement.replace(source)
                    rich_replaced = True

            with patch.object(
                gcc_adapter,
                "_read_regular_snapshot",
                side_effect=replace_source_after_snapshot,
            ), patch.object(
                gcc_adapter,
                "_stage_bounded_regular_snapshot",
                side_effect=replace_rich_after_staging,
            ):
                generate_gcc_profile_oracle(
                    manifest_path=manifest,
                    exclusions_path=copied_profile / EXCLUSIONS.name,
                    output_path=output,
                    schema_path=ORACLE_SCHEMA,
                )

            self.assertTrue(source_replaced)
            self.assertTrue(rich_replaced)
            self.assertEqual("{}\n", source_lock.read_text(encoding="utf-8"))
            self.assertEqual(
                b"mutated after stable staging\n",
                (copied_profile / "artifacts/gcc-driver.full").read_bytes(),
            )
            self.assertEqual(PRODUCTION_ORACLE.read_bytes(), output.read_bytes())

        schema_bytes = ORACLE_SCHEMA.stat().st_size
        with patch.object(
            gcc_generator,
            "MAX_GENERATION_SCHEMA_BYTES",
            schema_bytes - 1,
        ):
            with self.assertRaisesRegex(
                OracleGenerationError,
                f"{schema_bytes - 1}-byte input limit",
            ):
                gcc_generator._schema_validate({}, ORACLE_SCHEMA)

        with tempfile.TemporaryDirectory(
            prefix="function-oracle-schema-snapshot-"
        ) as directory:
            schema_copy = Path(directory) / ORACLE_SCHEMA.name
            shutil.copyfile(ORACLE_SCHEMA, schema_copy)
            original_schema_reader = gcc_generator._read_regular_snapshot
            schema_replaced = False

            def replace_schema_after_snapshot(
                path: Path,
                label: str,
                maximum_bytes: int,
            ) -> bytes | bytearray:
                nonlocal schema_replaced
                payload = original_schema_reader(path, label, maximum_bytes)
                replacement = path.with_name(f".{path.name}.replacement")
                replacement.write_text("{}\n", encoding="utf-8")
                replacement.replace(path)
                schema_replaced = True
                return payload

            with patch.object(
                gcc_generator,
                "_read_regular_snapshot",
                side_effect=replace_schema_after_snapshot,
            ):
                gcc_generator._schema_validate(
                    json.loads(PRODUCTION_ORACLE.read_bytes()),
                    schema_copy,
                )
            self.assertTrue(schema_replaced)
            self.assertEqual("{}\n", schema_copy.read_text(encoding="utf-8"))

    def test_checked_production_oracle_regenerates_byte_identically(self) -> None:
        with tempfile.TemporaryDirectory(prefix="function-oracle-regen-") as directory:
            output = Path(directory) / "function-recovery-oracle.json"
            document = generate_gcc_profile_oracle(
                manifest_path=MANIFEST,
                exclusions_path=EXCLUSIONS,
                output_path=output,
                schema_path=ORACLE_SCHEMA,
            )
            self.assertEqual(PRODUCTION_ORACLE.read_bytes(), output.read_bytes())
            loaded = load_function_oracle(output)

        schema = json.loads(ORACLE_SCHEMA.read_text(encoding="utf-8"))
        fastjsonschema.compile(schema)(document)
        counts = Counter(
            None if item["exclusion"] is None else item["exclusion"]["kind"]
            for item in document["functions"]
        )
        self.assertEqual(
            {None: 3284, "compiler-generated": 140, "inlined": 9420},
            counts,
        )
        self.assertEqual(12844, len(loaded.functions))
        self.assertEqual(3424, sum(item.rva is not None for item in loaded.functions))
        by_rva = {item["rva"]: item for item in document["functions"]}
        for co_located_source_rva in (
            "0x10bce0",
            "0x10bdf0",
            "0x10d1e0",
            "0x10d270",
            "0x10d580",
        ):
            record = by_rva[co_located_source_rva]
            self.assertIsNone(record["exclusion"])
            self.assertTrue(
                any(
                    fact["kind"] == "dwarf-subprogram"
                    for alias in record["aliases"]
                    for fact in alias["evidence"]
                )
            )

    def test_production_dwarf_has_no_entry_pc_form_dependent_starts(self) -> None:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

        rich_artifact = PROFILE_ROOT / "artifacts/gcc-driver.full"
        entry_pc_offsets: list[int] = []
        with rich_artifact.open("rb") as stream:
            dwarf_info = ELFFile(stream).get_dwarf_info(follow_links=False)
            for compilation_unit in dwarf_info.iter_CUs():
                for die in compilation_unit.iter_DIEs():
                    if (
                        die.tag == "DW_TAG_subprogram"
                        and "DW_AT_entry_pc" in die.attributes
                    ):
                        entry_pc_offsets.append(int(die.offset))
        self.assertEqual([], entry_pc_offsets)


if __name__ == "__main__":
    unittest.main()
