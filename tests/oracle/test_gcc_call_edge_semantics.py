"""Small DWARF call populations distinguish observations from negative authority.

The ELF container is synthetic, but the production caller traversal, target
resolution, coverage classification and score partitioning all run unchanged.
Artifact/binding authentication is covered by the retained-profile tests.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from oracle.gcc import report_call_edges as calls


BASE = 0x400000


def attribute(value, form="DW_FORM_flag"):
    return SimpleNamespace(value=value, form=form)


class Die:
    _next_offset = 1

    def __init__(self, tag, *, rva=None, name=None, parent=None, flags=None, references=None):
        self.offset = Die._next_offset
        Die._next_offset += 1
        self.tag = tag
        self.rva = rva
        self.parent = parent
        self.references = references or {}
        self.attributes = {key: attribute(value) for key, value in (flags or {}).items()}
        if rva is not None:
            self.attributes["DW_AT_low_pc"] = attribute(BASE + rva, "DW_FORM_addr")
        if name is not None:
            self.attributes["DW_AT_name"] = attribute(name.encode(), "DW_FORM_string")
        for key, target in self.references.items():
            self.attributes[key] = attribute(target.offset, "DW_FORM_ref4")
        self.cu = SimpleNamespace(structs=SimpleNamespace(little_endian=True))

    def get_parent(self):
        return self.parent

    def get_DIE_from_attribute(self, name):
        return self.references[name]


def function(rva, name, *, flags=None, references=None):
    return Die("DW_TAG_subprogram", rva=rva, name=name, flags=flags, references=references)


def call_site(caller, target=None, *, pc=None):
    result = Die(
        "DW_TAG_call_site", parent=caller,
        references={"DW_AT_call_origin": target} if target is not None else {},
    )
    if pc is not None:
        result.attributes["DW_AT_call_return_pc"] = attribute(BASE + pc, "DW_FORM_addr")
    return result


class CallFixture:
    def __init__(self, dies, *, excluded=()):
        self.dies = dies
        self.excluded = set(excluded)
        named = {
            die.rva: die for die in dies
            if die.tag == "DW_TAG_subprogram" and die.rva is not None
        }
        self.oracle = SimpleNamespace(functions=tuple(
            SimpleNamespace(
                rva=rva,
                identifier=f"function-{rva:x}",
                aliases=(SimpleNamespace(name=die.attributes["DW_AT_name"].value.decode()),),
                exclusion=SimpleNamespace(kind="fixture-excluded") if rva in self.excluded else None,
            )
            for rva, die in sorted(named.items())
        ))
        self.scoreable = set(named) - self.excluded
        self.dwarf = SimpleNamespace(
            iter_CUs=lambda: [SimpleNamespace(iter_DIEs=lambda: iter(self.dies))],
            _cu_cache={}, _cu_offsets_map={}, _linetable_cache={},
        )
        self.elf = SimpleNamespace(
            get_dwarf_info=lambda **kwargs: self.dwarf,
            iter_segments=lambda: iter([
                {"p_type": "PT_LOAD", "p_vaddr": BASE, "p_memsz": 0x2000, "p_flags": 1}
            ]),
        )

    def population(self):
        with mock.patch.object(calls, "ELFFile", return_value=self.elf):
            return calls._oracle_edges(b"fixture-container", self.oracle, self.scoreable, self.excluded)

    def report(self, recovered):
        bound = SimpleNamespace(
            oracle=self.oracle,
            provenance={
                "artifactManifestSha256": "a" * 64,
                "qualification": {"releaseEligible": False},
            },
            model_record={"path": "model.json", "bytes": 0, "sha256": "b" * 64},
            binding_record={"path": "binding.json", "bytes": 0, "sha256": "c" * 64},
            qualification_record={"path": "qualification.json", "bytes": 0, "sha256": "d" * 64},
        )
        with mock.patch.object(calls, "ELFFile", return_value=self.elf), \
             mock.patch.object(calls, "load_bound_stripped_model", return_value=bound), \
             mock.patch.object(calls, "_full_artifact", return_value=(b"fixture-container", "e" * 64)), \
             mock.patch.object(calls, "_recovered_edges", return_value=set(recovered)):
            return calls.score_report(Path("unused-profile"), Path("model.json"),
                                      Path("binding.json"), Path("qualification.json")).report


def pairs(records):
    return {(int(record["callerRva"], 16), int(record["calleeRva"], 16)) for record in records}


class CallEdgeNegativeAuthorityTest(unittest.TestCase):
    def fixture(self, flags=None, *, reference=None):
        caller = function(0x100, "caller", flags=flags, references=reference)
        callee = function(0x200, "known_target")
        other = function(0x300, "other_target")
        site = call_site(caller, callee, pc=0x110)
        return caller, callee, other, site

    def test_complete_emitted_calls_and_resolved_targets_authorize_false_positive(self):
        for name in ("DW_AT_call_all_calls", "DW_AT_call_all_source_calls",
                     "DW_AT_GNU_all_call_sites", "DW_AT_GNU_all_source_call_sites"):
            with self.subTest(attribute=name):
                fixture = CallFixture(self.fixture({name: True}))
                report = fixture.report({(0x100, 0x200), (0x100, 0x300)})
                self.assertEqual(pairs(report["fabricatedEdges"]), {(0x100, 0x300)})
                self.assertEqual(report["unknownRecoveredEdges"], [])
                self.assertEqual(report["summary"]["precision"],
                                 {"numerator": 1, "denominator": 2, "value": 0.5})
                self.assertEqual(report["summary"]["precisionStatus"], "exact")
                self.assertEqual(report["summary"]["thresholdAssessment"]["precision"], "fail")

    def test_one_located_site_does_not_prove_complete_negative_coverage(self):
        fixture = CallFixture(self.fixture())
        population = fixture.population()
        self.assertEqual(population.callers_with_sites, {0x100})
        self.assertFalse(population.caller_coverage[0x100]["negativeEvidenceComplete"])
        report = fixture.report({(0x100, 0x200), (0x100, 0x300)})
        self.assertEqual(report["fabricatedEdges"], [])
        self.assertEqual(pairs(report["unknownRecoveredEdges"]), {(0x100, 0x300)})
        self.assertIn("complete-emitted-call-coverage-unproven",
                      report["unknownRecoveredEdges"][0]["reasonCodes"])

    def test_tail_only_or_false_completeness_is_insufficient(self):
        for flags in ({"DW_AT_call_all_tail_calls": True},
                      {"DW_AT_GNU_all_tail_call_sites": True},
                      {"DW_AT_call_all_calls": False}):
            with self.subTest(flags=flags):
                fixture = CallFixture(self.fixture(flags))
                self.assertFalse(fixture.population().caller_coverage[0x100]["negativeEvidenceComplete"])
                report = fixture.report({(0x100, 0x300)})
                self.assertEqual(len(report["unknownRecoveredEdges"]), 1)
                self.assertEqual(report["fabricatedEdges"], [])

    def test_abstract_or_specification_completeness_does_not_certify_emitted_caller(self):
        for reference in ("DW_AT_abstract_origin", "DW_AT_specification"):
            with self.subTest(reference=reference):
                origin = function(None, "abstract_caller", flags={"DW_AT_call_all_calls": True})
                fixture = CallFixture([origin, *self.fixture(reference={reference: origin})])
                self.assertFalse(fixture.population().caller_coverage[0x100]["negativeEvidenceComplete"])
                report = fixture.report({(0x100, 0x300)})
                self.assertEqual(report["fabricatedEdges"], [])
                self.assertEqual(pairs(report["unknownRecoveredEdges"]), {(0x100, 0x300)})

    def test_incomplete_duplicate_emitted_description_cannot_be_overridden_by_complete_one(self):
        caller, callee, other, site = self.fixture({"DW_AT_call_all_calls": True})
        duplicate = function(0x100, "caller", flags={"DW_AT_call_all_tail_calls": True})
        fixture = CallFixture([caller, site, callee, other, duplicate])
        self.assertFalse(fixture.population().caller_coverage[0x100]["negativeEvidenceComplete"])

    def test_unresolved_indirect_virtual_and_external_targets_block_negative_authority(self):
        for kind in ("indirect-unresolved", "virtual-unresolved", "external-unresolved"):
            with self.subTest(kind=kind):
                caller, callee, other, known = self.fixture({"DW_AT_call_all_calls": True})
                extra = []
                if kind == "indirect-unresolved":
                    target = None
                elif kind == "virtual-unresolved":
                    target = function(0x400, "virtual_target", flags={"DW_AT_virtuality": 1})
                    extra.append(target)
                else:
                    target = function(None, "external_not_in_oracle")
                    extra.append(target)
                unresolved = call_site(caller, target, pc=0x120)
                fixture = CallFixture([caller, known, unresolved, callee, other, *extra])
                coverage = fixture.population().caller_coverage[0x100]
                self.assertTrue(coverage["completeEmittedCallCoverage"])
                self.assertEqual(coverage["unresolvedSiteKinds"], {kind: 1})
                self.assertFalse(coverage["negativeEvidenceComplete"])
                report = fixture.report({(0x100, 0x200), (0x100, 0x300)})
                self.assertEqual(report["fabricatedEdges"], [])
                self.assertEqual(pairs(report["matchedEdges"]), {(0x100, 0x200)})
                self.assertEqual(pairs(report["unknownRecoveredEdges"]), {(0x100, 0x300)})

    def test_unlocated_site_blocks_negative_authority_even_with_completeness(self):
        caller, callee, other, known = self.fixture({"DW_AT_call_all_calls": True})
        fixture = CallFixture([caller, known, call_site(caller, callee), callee, other])
        coverage = fixture.population().caller_coverage[0x100]
        self.assertEqual(coverage["unresolvedSiteKinds"], {"unlocated-call-site": 1})
        self.assertFalse(coverage["negativeEvidenceComplete"])
        self.assertEqual(fixture.report({(0x100, 0x300)})["fabricatedEdges"], [])

    def test_site_before_parent_start_blocks_negative_authority(self):
        caller = function(0x100, "caller", flags={"DW_AT_call_all_calls": True})
        callee = function(0x200, "callee")
        fixture = CallFixture([caller, call_site(caller, callee, pc=0x50), callee])
        population = fixture.population()
        coverage = population.caller_coverage[0x100]
        self.assertEqual(population.kinds["caller-no-emitted-range"], 1)
        self.assertTrue(coverage["completeEmittedCallCoverage"])
        self.assertEqual(coverage["unresolvedSiteKinds"], {"unassigned-call-site": 1})
        self.assertFalse(coverage["negativeEvidenceComplete"])
        report = fixture.report({(0x100, 0x200)})
        self.assertEqual(report["fabricatedEdges"], [])
        self.assertEqual(pairs(report["unknownRecoveredEdges"]), {(0x100, 0x200)})
        self.assertIn("unresolved-unlocated-or-unassigned-call-targets",
                      report["unknownRecoveredEdges"][0]["reasonCodes"])

    def test_partial_caller_positive_reference_remains_in_recall(self):
        fixture = CallFixture(self.fixture())
        report = fixture.report({(0x100, 0x300)})
        self.assertEqual(pairs(report["oracleEdges"]), {(0x100, 0x200)})
        self.assertEqual(pairs(report["missingEdges"]), {(0x100, 0x200)})
        self.assertEqual(report["summary"]["recall"],
                         {"numerator": 0, "denominator": 1, "value": 0.0})
        self.assertEqual(report["summary"]["thresholdAssessment"]["recall"], "fail")

    def test_complete_zero_call_caller_can_refute_recovered_call(self):
        caller = function(0x100, "caller", flags={"DW_AT_call_all_calls": True})
        callee = function(0x200, "callee")
        fixture = CallFixture([caller, callee])
        coverage = fixture.population().caller_coverage[0x100]
        self.assertFalse(coverage["hasLocatedCallSites"])
        self.assertTrue(coverage["negativeEvidenceComplete"])
        report = fixture.report({(0x100, 0x200)})
        self.assertEqual(pairs(report["fabricatedEdges"]), {(0x100, 0x200)})
        self.assertEqual(report["summary"]["precision"]["value"], 0.0)

    def test_full_recovered_population_partitions_and_precision_interval_reconciles(self):
        caller, callee, other, site = self.fixture()
        silent = function(0x400, "complete_silent", flags={"DW_AT_call_all_calls": True})
        excluded = function(0x500, "excluded")
        fixture = CallFixture([caller, site, callee, other, silent, excluded], excluded={0x500})
        recovered = {(0x100, 0x200), (0x100, 0x300), (0x400, 0x200),
                     (0x100, 0x500), (0x9000, 0x200)}
        report = fixture.report(recovered)
        outcomes = [pairs(report[name]) for name in
                    ("matchedEdges", "fabricatedEdges", "unknownRecoveredEdges", "excludedRecoveredEdges")]
        self.assertEqual(set.union(*outcomes), recovered)
        self.assertEqual(sum(map(len, outcomes)), len(recovered))
        self.assertEqual([len(value) for value in outcomes], [1, 1, 1, 2])
        self.assertEqual(report["summary"]["rawRecoveredCount"], 5)
        self.assertEqual(report["summary"]["scoredRecoveredCount"], 3)
        self.assertIsNone(report["summary"]["precision"])
        self.assertEqual(report["summary"]["precisionBounds"], {
            "lower": {"numerator": 1, "denominator": 3, "value": 0.333333},
            "upper": {"numerator": 2, "denominator": 3, "value": 0.666667},
        })
        self.assertEqual(report["summary"]["recall"],
                         {"numerator": 1, "denominator": 1, "value": 1.0})
        self.assertEqual(report["summary"]["thresholdAssessment"]["precision"], "unproven")
        self.assertTrue(all(row["reasonCodes"] for row in report["excludedRecoveredEdges"]))

    def test_even_high_precision_lower_bound_with_unknowns_cannot_claim_exact_threshold_pass(self):
        caller = function(0x100, "partial")
        callees = [function(0x200 + index * 0x10, f"target_{index}") for index in range(10)]
        other = function(0x400, "unobserved_target")
        sites = [call_site(caller, target, pc=0x110 + index)
                 for index, target in enumerate(callees)]
        fixture = CallFixture([caller, *sites, *callees, other])
        report = fixture.report({(0x100, target.rva) for target in callees} | {(0x100, 0x400)})
        self.assertGreaterEqual(report["summary"]["precisionBounds"]["lower"]["value"], 0.9)
        self.assertIsNone(report["summary"]["precision"])
        self.assertEqual(report["summary"]["thresholdAssessment"]["precision"], "unproven")
        self.assertFalse(report["summary"]["thresholdAssessment"]["releaseEligible"])

    def test_empty_precision_and_recall_populations_are_unproven(self):
        fixture = CallFixture([function(0x100, "silent", flags={"DW_AT_call_all_calls": True})])
        report = fixture.report(set())
        self.assertIsNone(report["summary"]["precisionBounds"]["lower"]["value"])
        self.assertIsNone(report["summary"]["recall"]["value"])
        self.assertEqual(report["summary"]["thresholdAssessment"]["precision"], "unproven")
        self.assertEqual(report["summary"]["thresholdAssessment"]["recall"], "unproven")


if __name__ == "__main__":
    unittest.main()
