from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from typing import Any, Callable, Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

from oracle.gcc.verify_oracle_artifacts import (  # noqa: E402
    create_oracle_manifest,
    inspect_elf,
    verify_build_environment,
    verify_oracle_manifest,
)
from oracle.gcc.verify_source_lock import VerificationError  # noqa: E402


SOURCE_LOCK = REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json"
BUILD_SCHEMA = REPOSITORY_ROOT / "oracle/gcc/build-record.schema.json"
MANIFEST_SCHEMA = REPOSITORY_ROOT / "oracle/gcc/oracle-manifest.schema.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GccOracleArtifactTest(unittest.TestCase):
    fixture_directory: tempfile.TemporaryDirectory[str]
    full_fixture: Path
    stripped_fixture: Path
    tools: dict[str, Path]

    @classmethod
    def setUpClass(cls) -> None:
        discovered = {
            name: (
                str(Path("/usr/bin") / name)
                if (Path("/usr/bin") / name).is_file()
                else shutil.which(name)
            )
            for name in ("cc", "ld", "strip")
        }
        missing = [name for name, path in discovered.items() if path is None]
        if missing:
            raise unittest.SkipTest(f"ELF oracle tests require local tools: {missing}")
        cls.tools = {name: Path(path).resolve() for name, path in discovered.items() if path}
        cls.fixture_directory = tempfile.TemporaryDirectory(prefix="gcc-oracle-elf-fixture-")
        directory = Path(cls.fixture_directory.name)
        source = directory / "fixture.c"
        source.write_text(
            "#include <stdio.h>\n"
            "static int twice(int value) { return value * 2; }\n"
            "int main(void) { printf(\"fixture=%d\\n\", twice(21)); return 0; }\n",
            encoding="utf-8",
        )
        cls.full_fixture = directory / "fixture.full"
        cls.stripped_fixture = directory / "fixture.stripped"
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "SOURCE_DATE_EPOCH": "1786060800", "TZ": "UTC"})
        compiled = subprocess.run(
            [
                str(cls.tools["cc"]),
                "-g3",
                "-O1",
                "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1",
                "-o",
                str(cls.full_fixture),
                str(source),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if compiled.returncode != 0:
            raise unittest.SkipTest(f"could not compile ELF fixture: {compiled.stderr}")
        stripped = subprocess.run(
            [
                str(cls.tools["strip"]),
                "--strip-all",
                "-o",
                str(cls.stripped_fixture),
                str(cls.full_fixture),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if stripped.returncode != 0:
            raise unittest.SkipTest(f"could not strip ELF fixture: {stripped.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "fixture_directory"):
            cls.fixture_directory.cleanup()

    @classmethod
    def tool_record(cls, role: str, executable: Path) -> dict[str, Any]:
        version = subprocess.run(
            [str(executable), "--version"],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        return {
            "role": role,
            "path": str(executable),
            "versionCommand": [str(executable), "--version"],
            "versionOutput": version.stdout + version.stderr,
            "executableBytes": executable.stat().st_size,
            "executableSha256": sha256(executable),
        }

    @classmethod
    def build_record(cls, source_lock: Path) -> dict[str, Any]:
        source = json.loads(source_lock.read_text(encoding="utf-8"))
        return {
            "schemaVersion": 1,
            "oracle": {
                "id": source["oracle"]["id"],
                "version": source["oracle"]["version"],
                "sourceRevision": source["revision"]["commit"],
                "sourceLockSha256": sha256(source_lock),
            },
            "environment": {
                "container": {
                    "image": "fixture.invalid/local-elf-toolchain",
                    "digest": f"sha256:{'a' * 64}",
                    "platform": "linux/amd64",
                },
                "variables": {
                    "LC_ALL": "C",
                    "SOURCE_DATE_EPOCH": "1786060800",
                    "TZ": "UTC",
                },
            },
            "directories": {
                "source": "/fixture/source/gcc-16.2.0",
                "build": "/fixture/build",
                "install": "/fixture/install",
            },
            "commands": {
                "configure": [
                    "/fixture/source/gcc-16.2.0/configure",
                    "--enable-languages=c",
                ],
                "compile": ["/usr/bin/make", "-j1", "all-gcc"],
                "install": ["/usr/bin/make", "install-gcc"],
                "stageFull": ["/usr/bin/install", "/fixture/install/bin/gcc", "{full}"],
                "strip": [
                    str(cls.tools["strip"]),
                    "--strip-all",
                    "-o",
                    "{stripped}",
                    "{full}",
                ],
            },
            "tools": [
                cls.tool_record("compiler", cls.tools["cc"]),
                cls.tool_record("linker", cls.tools["ld"]),
                cls.tool_record("stripper", cls.tools["strip"]),
            ],
            "outputs": {
                "full": "artifacts/gcc-driver.full",
                "stripped": "artifacts/gcc-driver.stripped",
            },
        }

    @contextmanager
    def staged_pair(
        self,
        build_mutation: Callable[[dict[str, Any]], None] | None = None,
    ) -> Iterator[tuple[Path, Path, Path, Path, Path]]:
        with tempfile.TemporaryDirectory(prefix="gcc-oracle-pair-test-") as temporary:
            directory = Path(temporary)
            shutil.copytree(SOURCE_LOCK.parent, directory, dirs_exist_ok=True)
            artifacts = directory / "artifacts"
            artifacts.mkdir()
            full = artifacts / "gcc-driver.full"
            stripped = artifacts / "gcc-driver.stripped"
            shutil.copyfile(self.full_fixture, full)
            shutil.copyfile(self.stripped_fixture, stripped)
            build_data = self.build_record(directory / "source-lock.json")
            if build_mutation is not None:
                build_mutation(build_data)
            build = directory / "build-record.json"
            build.write_text(
                json.dumps(build_data, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = directory / "oracle-manifest.json"
            yield manifest, directory / "source-lock.json", build, full, stripped

    def test_formal_schemas_are_closed_and_cover_generated_root_fields(self) -> None:
        build_schema = json.loads(BUILD_SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            manifest = create_oracle_manifest(manifest_path, source_lock, build_path)
            build = json.loads(build_path.read_text(encoding="utf-8"))

        self.assertFalse(build_schema["additionalProperties"])
        self.assertEqual(set(build), set(build_schema["required"]))
        self.assertEqual(set(build), set(build_schema["properties"]))
        self.assertFalse(manifest_schema["additionalProperties"])
        self.assertEqual(set(manifest), set(manifest_schema["required"]))
        self.assertEqual(set(manifest), set(manifest_schema["properties"]))

    def test_inspector_derives_elf_headers_segments_sections_dwarf_and_symbols(self) -> None:
        full = inspect_elf(self.full_fixture)
        stripped = inspect_elf(self.stripped_fixture)

        self.assertEqual("ELF64", full["header"]["class"])
        self.assertEqual("little-endian", full["header"]["dataEncoding"])
        self.assertEqual("EM_X86_64", full["header"]["machineName"])
        self.assertEqual(full["identity"], stripped["identity"])
        self.assertEqual(1, len(full["buildIds"]))
        self.assertEqual(full["buildIds"], stripped["buildIds"])
        self.assertTrue(full["executableLoad"]["segmentIndexes"])
        self.assertEqual(full["executableLoad"], stripped["executableLoad"])
        self.assertTrue(any(header["typeName"] == "PT_LOAD" for header in full["programHeaders"]))
        self.assertTrue(any(section["allocated"] for section in full["sections"]))
        self.assertTrue(
            all(
                section["contentSha256"] is not None
                for section in full["sections"]
                if section["allocated"] and section["fileBacked"]
            )
        )
        self.assertTrue(full["metadata"]["hasDwarf"])
        self.assertTrue(full["metadata"]["hasStaticSymbols"])
        self.assertFalse(stripped["metadata"]["hasDwarf"])
        self.assertFalse(stripped["metadata"]["hasStaticSymbols"])

    def test_manifest_round_trip_proves_code_identity_and_metadata_removal(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            created = create_oracle_manifest(manifest_path, source_lock, build_path)
            first_bytes = manifest_path.read_bytes()
            verified = verify_oracle_manifest(manifest_path)
            create_oracle_manifest(manifest_path, source_lock, build_path)

            self.assertEqual(first_bytes, manifest_path.read_bytes())
            self.assertEqual(created, verified)
            self.assertNotEqual(
                created["artifacts"]["full"]["sha256"],
                created["artifacts"]["stripped"]["sha256"],
            )
            self.assertEqual(
                created["artifacts"]["full"]["elf"]["executableLoad"],
                created["equivalence"]["executableLoad"],
            )
            self.assertIn(".symtab", created["equivalence"]["metadataDelta"]["fullOnlySections"])
            self.assertIn(
                ".debug_info",
                created["equivalence"]["metadataDelta"]["removedDwarfSections"],
            )

    def test_executable_load_byte_mutation_breaks_twin_creation(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, stripped):
            inspected = inspect_elf(stripped)
            executable_index = inspected["executableLoad"]["segmentIndexes"][0]
            segment = inspected["programHeaders"][executable_index]
            payload = bytearray(stripped.read_bytes())
            mutation_offset = segment["offset"] + segment["fileSize"] // 2
            payload[mutation_offset] ^= 0x01
            stripped.write_bytes(payload)

            with self.assertRaisesRegex(VerificationError, "PT_LOAD/PF_X bytes"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_allocated_section_mutation_breaks_twin_creation(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, stripped):
            inspected = inspect_elf(stripped)
            section = next(
                candidate
                for candidate in inspected["sections"]
                if candidate["name"] == ".rodata" and candidate["size"] > 0
            )
            payload = bytearray(stripped.read_bytes())
            payload[section["offset"]] ^= 0x01
            stripped.write_bytes(payload)

            with self.assertRaisesRegex(VerificationError, "allocated sections"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_build_id_mutation_is_rejected(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, stripped):
            inspected = inspect_elf(stripped)
            note = next(
                section
                for section in inspected["sections"]
                if section["name"] == ".note.gnu.build-id"
            )
            payload = bytearray(stripped.read_bytes())
            payload[note["offset"] + 16] ^= 0x01
            stripped.write_bytes(payload)

            with self.assertRaisesRegex(VerificationError, "Build ID"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_debug_only_strip_is_not_accepted_as_stripped_twin(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, full, stripped):
            subprocess.run(
                [str(self.tools["strip"]), "--strip-debug", "-o", str(stripped), str(full)],
                check=True,
                capture_output=True,
            )

            with self.assertRaisesRegex(VerificationError, "static symbol table"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_complete_artifact_hash_detects_nonallocated_debug_mutation(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, full, _):
            create_oracle_manifest(manifest_path, source_lock, build_path)
            inspected = inspect_elf(full)
            debug = next(
                section
                for section in inspected["sections"]
                if section["name"] == ".debug_info" and section["size"] > 0
            )
            payload = bytearray(full.read_bytes())
            payload[debug["offset"]] ^= 0x01
            full.write_bytes(payload)

            with self.assertRaisesRegex(VerificationError, "artifacts.full.sha256 mismatch"):
                verify_oracle_manifest(manifest_path)

    def test_manifest_field_mutation_is_rejected_even_when_artifacts_are_unchanged(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            create_oracle_manifest(manifest_path, source_lock, build_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["equivalence"]["allocatedSectionsSha256"] = "0" * 64
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(VerificationError, "allocatedSectionsSha256 mismatch"):
                verify_oracle_manifest(manifest_path)

    def test_unknown_manifest_field_is_rejected(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            create_oracle_manifest(manifest_path, source_lock, build_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["unchecked"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(VerificationError, "unexpected.*unchecked"):
                verify_oracle_manifest(manifest_path)

    def test_unknown_build_record_field_is_rejected(self) -> None:
        def mutate(build: dict[str, Any]) -> None:
            build["environment"]["unchecked"] = True

        with self.staged_pair(mutate) as (manifest_path, source_lock, build_path, _, _):
            with self.assertRaisesRegex(VerificationError, "unexpected.*unchecked"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_build_record_cannot_change_source_lock_binding(self) -> None:
        def mutate(build: dict[str, Any]) -> None:
            build["oracle"]["sourceLockSha256"] = "0" * 64

        with self.staged_pair(mutate) as (manifest_path, source_lock, build_path, _, _):
            with self.assertRaisesRegex(VerificationError, "does not match source-lock bytes"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_build_record_rejects_secret_environment_and_unlocked_strip_command(self) -> None:
        def add_secret(build: dict[str, Any]) -> None:
            build["environment"]["variables"]["API_KEY"] = "must-not-be-recorded"

        with self.staged_pair(add_secret) as (manifest_path, source_lock, build_path, _, _):
            with self.assertRaisesRegex(VerificationError, "secret variable API_KEY"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

        def replace_stripper(build: dict[str, Any]) -> None:
            build["commands"]["strip"][0] = "/usr/bin/false"

        with self.staged_pair(replace_stripper) as (manifest_path, source_lock, build_path, _, _):
            with self.assertRaisesRegex(VerificationError, "locked stripper tool path"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_artifact_symlink_is_rejected_before_inspection(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, full, stripped):
            stripped.unlink()
            stripped.symlink_to(full)

            with self.assertRaisesRegex(VerificationError, "symbolic link"):
                create_oracle_manifest(manifest_path, source_lock, build_path)

    def test_live_build_environment_verifies_tool_hashes_and_versions(self) -> None:
        with self.staged_pair() as (_, source_lock, build_path, _, _):
            record = verify_build_environment(
                build_path,
                source_lock,
                f"sha256:{'a' * 64}",
            )

            self.assertEqual(
                ["compiler", "linker", "stripper"],
                [tool["role"] for tool in record["tools"]],
            )

    def test_live_build_environment_rejects_tool_hash_mutation(self) -> None:
        def mutate(build: dict[str, Any]) -> None:
            build["tools"][0]["executableSha256"] = "0" * 64

        with self.staged_pair(mutate) as (_, source_lock, build_path, _, _):
            with self.assertRaisesRegex(VerificationError, "compiler executable SHA-256 mismatch"):
                verify_build_environment(
                    build_path,
                    source_lock,
                    f"sha256:{'a' * 64}",
                )

    def test_duplicate_manifest_field_is_rejected(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            create_oracle_manifest(manifest_path, source_lock, build_path)
            text = manifest_path.read_text(encoding="utf-8").replace(
                '  "schemaVersion": 1',
                '  "schemaVersion": 1,\n  "schemaVersion": 1',
                1,
            )
            manifest_path.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(VerificationError, "duplicate JSON object key"):
                verify_oracle_manifest(manifest_path)

    def test_non_elf_and_truncated_elf_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gcc-oracle-invalid-elf-") as temporary:
            invalid = Path(temporary) / "invalid"
            invalid.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(VerificationError, "not an ELF"):
                inspect_elf(invalid)

            invalid.write_bytes(b"\x7fELF\x02\x01\x01")
            with self.assertRaisesRegex(VerificationError, "not an ELF|ELF header"):
                inspect_elf(invalid)

    def test_cli_create_and_verify_are_deterministic(self) -> None:
        with self.staged_pair() as (manifest_path, source_lock, build_path, _, _):
            created = subprocess.run(
                [
                    "python3",
                    str(REPOSITORY_ROOT / "scripts/create-gcc-oracle-manifest.py"),
                    "--source-lock",
                    str(source_lock),
                    "--build-record",
                    str(build_path),
                    "--output",
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=REPOSITORY_ROOT,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            first = manifest_path.read_bytes()
            recreated = subprocess.run(
                [
                    "python3",
                    str(REPOSITORY_ROOT / "scripts/create-gcc-oracle-manifest.py"),
                    "--source-lock",
                    str(source_lock),
                    "--build-record",
                    str(build_path),
                    "--output",
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=REPOSITORY_ROOT,
            )
            self.assertEqual(0, recreated.returncode, recreated.stderr)
            self.assertEqual(first, manifest_path.read_bytes())
            verified = subprocess.run(
                [
                    "python3",
                    str(REPOSITORY_ROOT / "scripts/verify-gcc-oracle-artifacts.py"),
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=REPOSITORY_ROOT,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertIn("verified GCC oracle pair", verified.stdout)


if __name__ == "__main__":
    unittest.main()
