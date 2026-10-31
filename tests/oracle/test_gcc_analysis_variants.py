from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock

from oracle.function_recovery import ScoringError
from oracle.gcc.compare_analysis_variants import compare_variants, report_bytes, VARIANTS

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "oracle/gcc/16.2.0/cc1-oracle-manifest.json"


class AnalysisVariantComparisonTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/test-analysis-variants"
        scratch.mkdir(parents=True, exist_ok=True)
        self.owner = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.manifest_path = MANIFEST
        self.manifest = json.loads(MANIFEST.read_bytes())
        self.sha = self.manifest["artifacts"]["stripped"]["sha256"]
        loads = self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"]
        self.base = min(p["virtualAddress"] - p["offset"] for p in loads if p["type"] == 1)
        self.start = next(p["virtualAddress"] for p in loads if p["type"] == 1 and p["flags"] & 1)
        self.baseline = self.write_census("baseline", [self.start, self.start + 16])
        self.variant = self.write_census("no-switch", [self.start, self.start + 32])

    def write_census(self, variant, addresses):
        entries = [hex(x) for x in addresses]
        value = {
            "schemaVersion": 1, "kind": "ghidra-function-entry-census-v1", "authority": "diagnostic-only",
            "inputSha256": self.sha, "imageBase": hex(self.base), "languageId": "x86:LE:64:default",
            "compilerSpecId": "gcc", "entries": entries, "entryCount": len(entries),
            "entriesSha256": hashlib.sha256("".join(s + "\n" for s in entries).encode()).hexdigest(),
            "disabledAnalyzers": list(VARIANTS[variant]),
        }
        path = self.root / (variant + ".json")
        path.write_text(json.dumps(value))
        return path

    def compare(self, **extra):
        return compare_variants(manifest_path=self.manifest_path, baseline_path=self.baseline,
                                variant_paths={"no-switch": self.variant}, **extra)

    def write_manifest(self):
        self.manifest_path = self.root / "manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest))

    def mutate(self, field, value):
        document = json.loads(self.variant.read_bytes())
        document[field] = value
        self.variant.write_text(json.dumps(document))

    def test_actual_deltas_and_evidence_bytes_are_recomputable(self):
        result = self.compare()
        variant = result["variants"]["no-switch"]
        self.assertEqual([hex(self.start + 32)], variant["addedEntries"])
        self.assertEqual([hex(self.start + 16)], variant["removedEntries"])
        self.assertEqual(1, variant["unchangedEntries"])
        self.assertEqual(hashlib.sha256(self.variant.read_bytes()).hexdigest(), variant["census"]["sha256"])
        self.assertEqual(len(self.variant.read_bytes()), variant["census"]["bytes"])
        self.assertEqual("unavailable", result["reviewedAccuracy"]["status"])
        self.assertFalse(result["productionProfileSelected"])
        self.assertFalse(result["releaseEligible"])
        self.assertEqual("manifest-metadata-only", result["inputVerification"])
        self.assertEqual(report_bytes(result), report_bytes(self.compare()))

    def test_engine_scale_is_not_limited_by_driver_scorer(self):
        self.baseline = self.write_census("baseline", list(range(self.start, self.start + 51000)))
        self.variant = self.write_census("no-switch", list(range(self.start, self.start + 51001)))
        result = self.compare()
        self.assertEqual([hex(self.start + 51000)], result["variants"]["no-switch"]["addedEntries"])
        self.assertEqual(51000, result["baseline"]["entryCount"])

    def test_crossed_input_and_image_base_refused(self):
        for field, value in (("inputSha256", "0" * 64), ("imageBase", hex(self.base + 4096))):
            with self.subTest(field=field):
                self.variant = self.write_census("no-switch", [self.start])
                self.mutate(field, value)
                with self.assertRaisesRegex(ScoringError, "input or image base"):
                    self.compare()

    def test_wrong_or_unknown_disabled_options_refused(self):
        for value in ([], ["Decompiler Switch Analysis - One Time"], ["Decompiler Switch Analysis", "Stack"]):
            with self.subTest(value=value):
                self.mutate("disabledAnalyzers", value)
                with self.assertRaisesRegex(ScoringError, "disabled options"):
                    self.compare()

    def test_wrong_language_and_compiler_refused(self):
        for field in ("languageId", "compilerSpecId"):
            with self.subTest(field=field):
                self.variant = self.write_census("no-switch", [self.start])
                self.mutate(field, "different")
                with self.assertRaisesRegex(ScoringError, "language/compiler"):
                    self.compare()

    def test_noncanonical_duplicate_unsorted_and_overflow_entries_refused(self):
        for entries in (["0x00"], [self.start, self.start], [self.start + 1, self.start], [1 << 64]):
            with self.subTest(entries=entries):
                if isinstance(entries[0], int):
                    self.variant = self.write_census("no-switch", entries)
                else:
                    self.mutate("entries", entries)
                    self.mutate("entryCount", len(entries))
                with self.assertRaises(ScoringError):
                    self.compare()

    def test_complete_populations_partition_non_executable_and_unknown_without_losing_deltas(self):
        self.baseline = self.write_census("baseline", [self.base, self.start, self.start + 16])
        self.variant = self.write_census("no-switch", [0, self.base, self.start + 16, (1 << 64) - 1])
        result = self.compare()
        baseline, variant = result["baseline"], result["variants"]["no-switch"]
        self.assertEqual({"executableCount": 2, "nonExecutableEntries": [hex(self.base)],
                          "unknownEntries": []}, baseline["entryClassification"])
        self.assertEqual({"executableCount": 1, "nonExecutableEntries": [hex(self.base)],
                          "unknownEntries": ["0x0", "0xffffffffffffffff"]}, variant["entryClassification"])
        self.assertEqual(["0x0", "0xffffffffffffffff"], variant["addedEntries"])
        self.assertEqual(variant["addedEntries"], variant["addedEntryClassification"]["unknownEntries"])
        self.assertEqual([hex(self.start)], variant["removedEntries"])
        self.assertEqual(1, variant["removedEntryClassification"]["executableCount"])
        for record in (baseline, variant):
            groups = record["entryClassification"]
            self.assertEqual(record["entryCount"], groups["executableCount"]
                             + len(groups["nonExecutableEntries"]) + len(groups["unknownEntries"]))
        self.assertEqual("unavailable", result["reviewedAccuracy"]["status"])
        self.assertFalse(result["releaseEligible"])

    def test_retained_run_outlier_population_and_equal_count_lean_swap_regression(self):
        # Addresses observed in run 40206482749; only the executable baseline is synthetic.
        outside = [x for x in range(0x2de5000, 0x2de5941, 8) if x != 0x2de5510]
        added = [0x956fe9, 0x9570dd, 0x9571d1, 0x9572c5, 0x9598f4, 0x959928,
                 0x95994f, 0x959976, 0x9599a0, 0x9599ca, 0x9599f4, 0x959a1e,
                 0x9ded58, 0x1123354, 0x127d961, 0x127daf7, 0x127dbb4,
                 0x1f98f0e, 0x1f98fbb, 0x1f99042, 0x1f99096, 0x1f990ea, 0x1f9913a]
        baseline = [self.start, *outside]
        self.baseline = self.write_census("baseline", baseline)
        variants = {
            "no-call-convention": self.write_census("no-call-convention", baseline),
            "no-switch": self.write_census("no-switch", sorted(baseline + added)),
            "no-switch-no-call-convention": self.write_census("no-switch-no-call-convention", sorted(baseline + added)),
            "lean": self.write_census("lean", sorted((set(baseline) | set(added) | {0x127f539}) - {0x2de5208})),
        }
        result = compare_variants(manifest_path=MANIFEST, baseline_path=self.baseline, variant_paths=variants)
        self.assertEqual(296, len(result["baseline"]["entryClassification"]["unknownEntries"]))
        no_switch, lean = result["variants"]["no-switch"], result["variants"]["lean"]
        self.assertEqual([], result["variants"]["no-call-convention"]["addedEntries"])
        self.assertEqual([], result["variants"]["no-call-convention"]["removedEntries"])
        self.assertEqual(no_switch["addedEntries"], result["variants"]["no-switch-no-call-convention"]["addedEntries"])
        self.assertEqual(23, len(no_switch["addedEntries"]))
        self.assertEqual([], no_switch["removedEntries"])
        self.assertEqual(no_switch["entryCount"], lean["entryCount"])
        self.assertNotEqual(no_switch["entriesSha256"], lean["entriesSha256"])
        self.assertEqual(24, len(lean["addedEntries"]))
        self.assertEqual(["0x2de5208"], lean["removedEntries"])
        self.assertEqual(lean["removedEntries"], lean["removedEntryClassification"]["unknownEntries"])
        self.assertEqual(295, len(lean["entryClassification"]["unknownEntries"]))
        self.assertEqual(report_bytes(result), report_bytes(compare_variants(
            manifest_path=MANIFEST, baseline_path=self.baseline, variant_paths=variants)))

    def test_overlapping_load_ranges_are_unknown_even_when_both_executable(self):
        for flags in (4, 5):
            with self.subTest(flags=flags):
                self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"].append({
                    "typeName": "PT_LOAD", "virtualAddress": self.start, "memorySize": 1, "flags": flags,
                })
                self.write_manifest()
                result = self.compare()
                self.assertEqual([hex(self.start)], result["baseline"]["entryClassification"]["unknownEntries"])
                self.assertEqual(1, result["baseline"]["entryClassification"]["executableCount"])
                self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"].pop()

    def test_invalid_or_excessive_load_ranges_refused_before_classification(self):
        for field, value in (("virtualAddress", -1), ("virtualAddress", True), ("virtualAddress", 1 << 64),
                             ("memorySize", -1), ("memorySize", 1 << 64), ("memorySize", (1 << 64) - 1),
                             ("flags", True), ("flags", 8)):
            with self.subTest(field=field, value=value):
                segment = {"typeName": "PT_LOAD", "virtualAddress": self.start, "memorySize": 1, "flags": 5}
                segment[field] = value
                self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"].append(segment)
                self.write_manifest()
                with self.assertRaisesRegex(ScoringError, "classification range|JSON integer magnitude"):
                    self.compare()
                self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"].pop()
        self.manifest_path = MANIFEST
        with patch("oracle.gcc.compare_analysis_variants.MAX_LOAD_RANGES", 1):
            with self.assertRaisesRegex(ScoringError, "ranges exceed"):
                self.compare()

    def test_digest_count_boolean_and_unknown_schema_fields_refused(self):
        for field, value in (("entryCount", 1), ("entryCount", True), ("entriesSha256", "0" * 64),
                             ("schemaVersion", True), ("authority", "production"), ("extra", "ignored?")):
            with self.subTest(field=field, value=value):
                self.variant = self.write_census("no-switch", [self.start, self.start + 32])
                self.mutate(field, value)
                with self.assertRaises(ScoringError):
                    self.compare()

    def test_duplicate_json_keys_and_symlinks_refused(self):
        original = self.variant.read_text()
        self.variant.write_text(original[:-1] + ', "entryCount":2}')
        with self.assertRaises(ScoringError):
            self.compare()
        target = self.root / "target.json"
        target.write_text(original)
        self.variant.unlink()
        self.variant.symlink_to(target)
        with self.assertRaises(ScoringError):
            self.compare()

    def test_hash_count_only_historical_log_cannot_enter(self):
        self.variant.write_text('ANALYZER-EXPERIMENT functions=50879 entrySha256=' + "0" * 64)
        with self.assertRaises(ScoringError):
            self.compare()

    def test_byte_and_population_bounds_refuse_before_comparison(self):
        with patch("oracle.gcc.compare_analysis_variants.MAX_CENSUS_BYTES", 4):
            with self.assertRaises(ScoringError):
                self.compare()
        with patch("oracle.gcc.compare_analysis_variants.MAX_ENTRIES", 1):
            with self.assertRaises(ScoringError):
                self.compare()

    def test_empty_or_duplicate_baseline_variant_refused(self):
        for variants in ({}, {"baseline": self.baseline}, {"unknown": self.variant}):
            with self.subTest(variants=variants):
                with self.assertRaises(ScoringError):
                    compare_variants(manifest_path=MANIFEST, baseline_path=self.baseline, variant_paths=variants)

    def test_physical_reference_uses_verified_snapshot_and_keeps_reviewed_accuracy_unavailable(self):
        manager = MagicMock()
        snapshot = manager.__enter__.return_value
        snapshot.manifest_payload = MANIFEST.read_bytes()
        snapshot.manifest = self.manifest
        snapshot.artifact_paths = {"rich": self.root / "verified-full"}
        reference = {"inputSha256": self.manifest["artifacts"]["full"]["sha256"],
                     "elfImageBase": hex(self.base), "executableRvaRanges": [],
                     "functions": [{"rva": hex(self.start + 32 - self.base), "sources": ["dwarf"]}],
                     "counts": {"functions": 1}}
        with patch("oracle.gcc.compare_analysis_variants._verified_artifact_manifest_snapshot", return_value=manager) as verify, \
             patch("oracle.physical_function_starts.collect_physical_function_starts", return_value=reference) as collect:
            result = self.compare(rich_artifact_path=self.root / "full", stripped_artifact_path=self.root / "stripped")
        verify.assert_called_once_with(MANIFEST, artifact_overrides={"full": self.root / "full", "stripped": self.root / "stripped"})
        collect.assert_called_once_with(self.root / "verified-full", expected_sha256=self.manifest["artifacts"]["full"]["sha256"])
        variant = result["variants"]["no-switch"]
        self.assertEqual(variant["addedEntries"], variant["addedEntriesInPhysicalReference"])
        self.assertEqual([], variant["removedEntriesInPhysicalReference"])
        self.assertEqual("unavailable", result["reviewedAccuracy"]["status"])
        self.assertEqual("manifest-and-elf-twins-verified", result["inputVerification"])
        self.assertFalse(result["releaseEligible"])

    def test_changed_or_failed_manifest_verification_cannot_supply_reference(self):
        manager = MagicMock()
        manager.__enter__.return_value.manifest_payload = b"changed manifest"
        with patch("oracle.gcc.compare_analysis_variants._verified_artifact_manifest_snapshot", return_value=manager):
            with self.assertRaisesRegex(ScoringError, "manifest changed"):
                self.compare(rich_artifact_path=self.root / "full", stripped_artifact_path=self.root / "stripped")
        with patch("oracle.gcc.compare_analysis_variants._verified_artifact_manifest_snapshot", side_effect=ScoringError("authentication failed")):
            with self.assertRaisesRegex(ScoringError, "authentication failed"):
                self.compare(rich_artifact_path=self.root / "full", stripped_artifact_path=self.root / "stripped")

    def test_non_executable_unknown_and_ambiguous_entries_cannot_gain_physical_membership(self):
        unknown = 0x2de5208
        self.baseline = self.write_census("baseline", [self.start])
        self.variant = self.write_census("no-switch", [self.base, self.start, unknown])
        self.manifest["artifacts"]["stripped"]["elf"]["programHeaders"].append({
            "typeName": "PT_LOAD", "virtualAddress": self.start, "memorySize": 1, "flags": 5,
        })
        self.write_manifest()
        manager = MagicMock()
        snapshot = manager.__enter__.return_value
        snapshot.manifest_payload = self.manifest_path.read_bytes()
        snapshot.manifest = self.manifest
        snapshot.artifact_paths = {"rich": self.root / "verified-full"}
        reference = {"elfImageBase": hex(self.base), "functions": [
            {"rva": hex(x - self.base), "sources": ["symbol"]} for x in (self.base, self.start, unknown)]}
        with patch("oracle.gcc.compare_analysis_variants._verified_artifact_manifest_snapshot", return_value=manager), \
             patch("oracle.physical_function_starts.collect_physical_function_starts", return_value=reference):
            result = self.compare(rich_artifact_path=self.root / "full", stripped_artifact_path=self.root / "stripped")
        variant = result["variants"]["no-switch"]
        self.assertEqual([hex(self.base), hex(unknown)], variant["addedEntries"])
        self.assertEqual([], variant["addedEntriesInPhysicalReference"])
        self.assertEqual(0, result["baseline"]["entriesInPhysicalReference"])
        self.assertEqual(3, len(result["physicalReference"]["functions"]))

    def test_cli_publishes_complete_report_without_overwriting_prior_evidence(self):
        output = self.root / "comparison.json"
        command = [sys.executable, "-B", str(ROOT / "scripts/compare-gcc-analysis-variants.py"),
                   "--baseline", str(self.baseline), "--variant", "no-switch=" + str(self.variant),
                   "--output", str(output)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(report_bytes(self.compare()), output.read_bytes())
        output.write_bytes(b"previous independently retained report")
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(1, result.returncode)
        self.assertEqual(b"previous independently retained report", output.read_bytes())
        self.assertEqual([], list(self.root.glob(".analysis-comparison-*")))

    def test_cli_rejects_outside_output_before_creating_anything(self):
        output = ROOT.parent / "forbidden-analysis-comparison.json"
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/compare-gcc-analysis-variants.py"),
             "--baseline", str(self.baseline), "--variant", "no-switch=" + str(self.variant),
             "--output", str(output)], cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(1, result.returncode)
        self.assertIn("inside this repository", result.stderr)
        self.assertFalse(output.exists())

    def test_one_artifact_cannot_imply_authenticated_reference(self):
        with self.assertRaisesRegex(ScoringError, "both ELF twins"):
            self.compare(rich_artifact_path=self.root / "full")


if __name__ == "__main__":
    unittest.main()
