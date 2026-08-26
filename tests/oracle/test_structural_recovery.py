from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from oracle.function_recovery import (  # noqa: E402
    load_function_oracle,
    load_program_model,
    report_json_bytes,
    score_function_recovery,
)
from oracle.structural_recovery import (  # noqa: E402
    DIMENSIONS,
    NORMALIZATION_PROFILE_CONFIGURATION,
    NORMALIZATION_PROFILE_CONFIGURATION_BYTES,
    NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
    OUTCOMES,
    StructuralScoringError,
    canonical_report_bytes,
    fixture_attestation_payload_sha256,
    load_boundary_mapping,
    load_fixture_identity_map,
    load_fixture_recovered_structure,
    load_structural_oracle,
    load_target_abi_descriptor,
    score_fixture_structural_recovery,
    validate_structural_score_report,
)


FIXTURES = REPOSITORY_ROOT / "tests/oracle/fixtures/structural_recovery"
FUNCTION_FIXTURES = REPOSITORY_ROOT / "tests/oracle/fixtures/function_recovery"
TARGET = REPOSITORY_ROOT / "oracle/targets/sysv-amd64-v1.json"
ORACLE = FIXTURES / "oracle.json"
IDENTITY_MAP = FIXTURES / "identity-map.json"
RECOVERED = FIXTURES / "recovered.json"


def _write_json(path: Path, document: dict) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _reattest(document: dict) -> None:
    document["attestation"]["payloadSha256"] = fixture_attestation_payload_sha256(document)


def _refresh_report_metrics(report: dict) -> None:
    def ratio(numerator: int, denominator: int) -> dict:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "value": None if denominator == 0 else round(numerator / denominator, 6),
        }

    def metric(facts: list[dict]) -> dict:
        outcomes = {name: 0 for name in OUTCOMES}
        for fact in facts:
            outcomes[fact["outcome"]] += 1
        oracle_denominator = sum(fact["oracleFactId"] is not None for fact in facts)
        recovered_denominator = sum(fact["recoveredFactId"] is not None for fact in facts)
        credit = outcomes["exact"] + outcomes["abi-equivalent"]
        return {
            "oracleDenominator": oracle_denominator,
            "recoveredDenominator": recovered_denominator,
            "observableOracleCount": oracle_denominator - outcomes["oracle-unobservable"],
            "unobservableOracleCount": outcomes["oracle-unobservable"],
            "outcomes": outcomes,
            "credit": ratio(credit, oracle_denominator),
            "claimPrecision": ratio(credit, recovered_denominator),
        }

    for entity in report["entities"]:
        entity["metric"] = metric(entity["facts"])
    all_facts = [fact for entity in report["entities"] for fact in entity["facts"]]
    report["dimensions"] = [
        {
            "dimension": dimension,
            **metric([fact for fact in all_facts if fact["dimension"] == dimension]),
        }
        for dimension in DIMENSIONS
    ]
    report["aggregate"] = metric(all_facts)


class StructuralRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="structural-recovery-test-")
        cls.temp = Path(cls.temporary.name)
        cls.target = load_target_abi_descriptor(TARGET)
        function_oracle = load_function_oracle(FUNCTION_FIXTURES / "oracle.json")
        rich = load_program_model(
            FUNCTION_FIXTURES / "rich-model.json",
            twin="rich",
            artifact=function_oracle.artifacts["rich"],
            model_image_base=0x400000,
        )
        stripped = load_program_model(
            FUNCTION_FIXTURES / "stripped-model.json",
            twin="stripped",
            artifact=function_oracle.artifacts["stripped"],
            model_image_base=0x500000,
        )
        boundary_report = score_function_recovery(
            function_oracle,
            {"rich": rich, "stripped": stripped},
        )
        cls.boundary_path = cls.temp / "boundary-score.json"
        cls.boundary_path.write_bytes(report_json_bytes(boundary_report))
        cls.boundary_sha256 = hashlib.sha256(cls.boundary_path.read_bytes()).hexdigest()
        if cls.boundary_sha256 != "b05d85d9f21e704c2581b84ded3ea5442eb4695ed75e74d25778e417a5a8d593":
            raise AssertionError("the checked structural fixture boundary binding drifted")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _inputs(
        self,
        *,
        recovered_path: Path = RECOVERED,
        identity_map_path: Path = IDENTITY_MAP,
        oracle_path: Path = ORACLE,
        target_path: Path = TARGET,
        boundary_path: Path | None = None,
    ):
        target = load_target_abi_descriptor(target_path)
        oracle = load_structural_oracle(oracle_path, target)
        boundary = load_boundary_mapping(
            self.boundary_path if boundary_path is None else boundary_path,
            twin="rich",
            target=target,
        )
        identity_map = load_fixture_identity_map(identity_map_path, oracle=oracle)
        recovered = load_fixture_recovered_structure(
            recovered_path,
            target=target,
            oracle=oracle,
            boundary=boundary,
            identity_map=identity_map,
        )
        return target, oracle, boundary, identity_map, recovered

    def _score(self, **paths):
        target, oracle, boundary, identity_map, recovered = self._inputs(**paths)
        return score_fixture_structural_recovery(
            oracle,
            recovered,
            boundary,
            identity_map,
            target,
        )

    def _validate_report(self, report: dict) -> None:
        validate_structural_score_report(report, target=self.target)

    def _canonical_report(self, report: dict) -> bytes:
        return canonical_report_bytes(report, target=self.target)

    def _mutated_recovered(self, mutator) -> Path:
        document = json.loads(RECOVERED.read_text(encoding="utf-8"))
        mutator(document)
        _reattest(document)
        path = self.temp / f"recovered-{len(list(self.temp.glob('recovered-*.json')))}.json"
        _write_json(path, document)
        return path

    def _mutated_boundary(self, mutator) -> Path:
        document = json.loads(self.boundary_path.read_text(encoding="utf-8"))
        mutator(document)
        path = self.temp / f"boundary-{len(list(self.temp.glob('boundary-*.json')))}.json"
        _write_json(path, document)
        return path

    def _mutated_bundle(self, *, oracle_mutator=None, recovered_mutator=None):
        oracle_document = json.loads(ORACLE.read_text(encoding="utf-8"))
        if oracle_mutator is not None:
            oracle_mutator(oracle_document)
        oracle_path = self.temp / f"bundle-oracle-{len(list(self.temp.glob('bundle-oracle-*.json')))}.json"
        _write_json(oracle_path, oracle_document)

        map_document = json.loads(IDENTITY_MAP.read_text(encoding="utf-8"))
        map_document["map"]["oracleSha256"] = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
        _reattest(map_document)
        map_path = self.temp / f"bundle-map-{len(list(self.temp.glob('bundle-map-*.json')))}.json"
        _write_json(map_path, map_document)

        recovered_document = json.loads(RECOVERED.read_text(encoding="utf-8"))
        if recovered_mutator is not None:
            recovered_mutator(recovered_document)
        recovered_document["provenance"]["identityMap"]["sha256"] = hashlib.sha256(
            map_path.read_bytes()
        ).hexdigest()
        _reattest(recovered_document)
        recovered_path = self.temp / f"bundle-recovered-{len(list(self.temp.glob('bundle-recovered-*.json')))}.json"
        _write_json(recovered_path, recovered_document)
        return oracle_path, map_path, recovered_path

    def test_checked_fixture_covers_every_dimension_and_outcome(self) -> None:
        report = self._score()
        self.assertEqual(list(DIMENSIONS), [item["dimension"] for item in report["dimensions"]])
        self.assertEqual(
            {
                "exact": 14,
                "abi-equivalent": 4,
                "recovered-unknown": 3,
                "oracle-unobservable": 1,
                "contradicted": 2,
                "fabricated": 3,
            },
            report["aggregate"]["outcomes"],
        )
        self.assertEqual(24, report["aggregate"]["oracleDenominator"])
        self.assertEqual(26, report["aggregate"]["recoveredDenominator"])
        self.assertEqual(18, report["aggregate"]["credit"]["numerator"])
        self.assertFalse(report["model"]["verification"]["productionVerified"])

    def test_every_entity_has_a_transparent_metric_partition(self) -> None:
        report = self._score()
        self.assertEqual(
            report["aggregate"]["oracleDenominator"],
            sum(entity["metric"]["oracleDenominator"] for entity in report["entities"]),
        )
        self.assertEqual(
            report["aggregate"]["recoveredDenominator"],
            sum(entity["metric"]["recoveredDenominator"] for entity in report["entities"]),
        )
        for entity in report["entities"]:
            metric = entity["metric"]
            self.assertEqual(
                metric["oracleDenominator"],
                sum(
                    metric["outcomes"][name]
                    for name in (
                        "exact",
                        "abi-equivalent",
                        "recovered-unknown",
                        "oracle-unobservable",
                        "contradicted",
                    )
                ),
            )

    def test_absent_dimension_still_emits_zero_null_metrics(self) -> None:
        oracle_document = json.loads(ORACLE.read_text(encoding="utf-8"))
        mode = next(item for item in oracle_document["entities"] if item["id"] == "type.mode")
        mode["facts"] = [
            fact for fact in mode["facts"] if fact["dimension"] != "type.enum.enumerator-value"
        ]
        oracle_path = self.temp / "oracle-with-absent-dimension.json"
        _write_json(oracle_path, oracle_document)

        map_document = json.loads(IDENTITY_MAP.read_text(encoding="utf-8"))
        map_document["map"]["oracleSha256"] = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
        _reattest(map_document)
        map_path = self.temp / "map-with-absent-dimension.json"
        _write_json(map_path, map_document)

        recovered_document = json.loads(RECOVERED.read_text(encoding="utf-8"))
        recovered_mode = next(
            item for item in recovered_document["entities"] if item["id"] == "recovered.type.mode"
        )
        recovered_mode["facts"] = [
            fact
            for fact in recovered_mode["facts"]
            if fact["dimension"] != "type.enum.enumerator-value"
        ]
        recovered_document["provenance"]["identityMap"]["sha256"] = hashlib.sha256(
            map_path.read_bytes()
        ).hexdigest()
        _reattest(recovered_document)
        recovered_path = self.temp / "recovered-with-absent-dimension.json"
        _write_json(recovered_path, recovered_document)

        report = self._score(
            oracle_path=oracle_path,
            identity_map_path=map_path,
            recovered_path=recovered_path,
        )
        self.assertEqual(list(DIMENSIONS), [item["dimension"] for item in report["dimensions"]])
        metric = next(
            item
            for item in report["dimensions"]
            if item["dimension"] == "type.enum.enumerator-value"
        )
        self.assertEqual(0, metric["oracleDenominator"])
        self.assertEqual(0, metric["recoveredDenominator"])
        self.assertEqual({"numerator": 0, "denominator": 0, "value": None}, metric["credit"])

    def test_unknown_and_unobservable_are_visible_zero_credit_denominators(self) -> None:
        report = self._score()
        prototype = next(
            item for item in report["dimensions"] if item["dimension"] == "function.prototype"
        )
        self.assertEqual(5, prototype["oracleDenominator"])
        self.assertEqual(5, prototype["recoveredDenominator"])
        self.assertEqual(2, prototype["outcomes"]["recovered-unknown"])
        self.assertEqual(1, prototype["outcomes"]["oracle-unobservable"])
        self.assertEqual({"numerator": 2, "denominator": 5, "value": 0.4}, prototype["credit"])

    def test_function_and_internal_endpoint_identity_come_only_from_boundary_mapping(self) -> None:
        def mutate(document: dict) -> None:
            alpha = next(item for item in document["entities"] if item["id"] == "fn_0000000000400010")
            call = next(fact for fact in alpha["facts"] if fact["dimension"] == "call.internal")
            call["value"]["source"] = "function:fn_0000000000400010"

        report = self._score(recovered_path=self._mutated_recovered(mutate))
        call = next(
            fact
            for entity in report["entities"]
            for fact in entity["facts"]
            if fact["oracleFactId"] == "truth-call-internal"
        )
        self.assertEqual("contradicted", call["outcome"])

    def test_boundary_projection_carries_complete_scored_and_excluded_universes(self) -> None:
        target = load_target_abi_descriptor(TARGET)
        boundary = load_boundary_mapping(self.boundary_path, twin="rich", target=target)
        self.assertEqual(
            {
                "die-cu0-10-alpha",
                "die-cu0-20-beta",
                "die-cu0-30-gamma",
                "die-cu0-40-delta",
                "die-cu0-50-epsilon",
            },
            set(boundary.oracle_function_ids),
        )
        self.assertEqual(
            {
                "fn_0000000000400010",
                "fn_0000000000400022",
                "fn_0000000000400040",
                "fn_0000000000400050",
                "fn_0000000000400080",
            },
            set(boundary.recovered_function_ids),
        )
        self.assertEqual(
            {"symbol-60-clone", "die-cu0-70-inline-helper"},
            set(boundary.excluded_oracle_ids),
        )
        self.assertEqual({"fn_0000000000400060"}, set(boundary.ignored_recovered_ids))

    def test_boundary_projection_rejects_name_dependent_assignment_and_count_drift(self) -> None:
        target = load_target_abi_descriptor(TARGET)
        cases = (
            (
                lambda document: document["twins"]["rich"]["nearMatchAssignment"].__setitem__(
                    "nameIndependent", False
                ),
                "not name-independent",
            ),
            (
                lambda document: document["twins"]["rich"]["boundaries"].__setitem__(
                    "falseNegatives", 99
                ),
                "falseNegatives disagrees",
            ),
            (
                lambda document: document["twins"]["rich"]["exactMatches"][0].__setitem__(
                    "oracleId", "symbol-60-clone"
                ),
                "selected mapping overlaps the excluded oracle universe",
            ),
        )
        for mutate, message in cases:
            with self.subTest(message=message):
                path = self._mutated_boundary(mutate)
                with self.assertRaisesRegex(StructuralScoringError, message):
                    load_boundary_mapping(path, twin="rich", target=target)

    def test_only_complete_boundary_universe_functions_can_enter_structural_scoring(self) -> None:
        def fact(identifier: str, state_key: str, state: str) -> dict:
            return {
                "id": f"{identifier}-prototype",
                "slot": "prototype",
                "dimension": "function.prototype",
                state_key: state,
                "value": {"source": "prototype:void-from-void", "abi": None},
                "evidence": [{"kind": "fixture", "locator": identifier}],
            }

        def add_recovered(identifier: str):
            return lambda document: document["entities"].append(
                {"kind": "function", "id": identifier, "facts": [fact(identifier, "state", "recovered")]}
            )

        arbitrary = self._mutated_recovered(add_recovered("function-not-in-boundary"))
        with self.assertRaisesRegex(StructuralScoringError, "absent from the selected #39 recovered universe"):
            self._score(recovered_path=arbitrary)

        ignored = self._mutated_recovered(add_recovered("fn_0000000000400060"))
        with self.assertRaisesRegex(StructuralScoringError, "excluded by the selected #39 report"):
            self._score(recovered_path=ignored)

        false_positive = self._score()
        fp_entity = next(
            entity for entity in false_positive["entities"]
            if entity["recoveredId"] == "fn_0000000000400080"
        )
        self.assertEqual(["fabricated"], [row["outcome"] for row in fp_entity["facts"]])

        false_negative = self._score()
        fn_entity = next(
            entity for entity in false_negative["entities"]
            if entity["oracleId"] == "die-cu0-30-gamma"
        )
        self.assertEqual(["recovered-unknown"], [row["outcome"] for row in fn_entity["facts"]])

        def omit_false_negative(document: dict) -> None:
            document["entities"] = [
                entity
                for entity in document["entities"]
                if entity["id"] != "die-cu0-30-gamma"
            ]

        oracle_path, map_path, recovered_path = self._mutated_bundle(
            oracle_mutator=omit_false_negative
        )
        with self.assertRaisesRegex(StructuralScoringError, "omits functions.*#39 oracle"):
            self._score(
                oracle_path=oracle_path,
                identity_map_path=map_path,
                recovered_path=recovered_path,
            )

        def omit_false_positive(document: dict) -> None:
            document["entities"] = [
                entity
                for entity in document["entities"]
                if entity["id"] != "fn_0000000000400080"
            ]

        with self.assertRaisesRegex(StructuralScoringError, "omits functions.*#39 recovered"):
            self._score(recovered_path=self._mutated_recovered(omit_false_positive))

        def add_arbitrary_oracle(document: dict) -> None:
            document["entities"].append(
                {
                    "kind": "function",
                    "id": "function-not-in-boundary",
                    "facts": [fact("function-not-in-boundary", "observability", "observable")],
                }
            )

        oracle_path, map_path, recovered_path = self._mutated_bundle(
            oracle_mutator=add_arbitrary_oracle
        )
        with self.assertRaisesRegex(StructuralScoringError, "absent from the selected #39 oracle universe"):
            self._score(
                oracle_path=oracle_path,
                identity_map_path=map_path,
                recovered_path=recovered_path,
            )

    def test_old_unmapped_sentinel_namespaces_are_not_valid_source_values(self) -> None:
        cases = (
            ("call.internal", "unmapped-boundary:x"),
            ("global.reference", "unmapped-global:x"),
            ("global.type", "unmapped-type:x"),
        )
        for dimension, source in cases:
            with self.subTest(dimension=dimension):
                def mutate(document: dict, dimension=dimension, source=source) -> None:
                    fact = next(
                        fact
                        for entity in document["entities"]
                        for fact in entity["facts"]
                        if fact["dimension"] == dimension
                    )
                    fact["value"]["source"] = source

                with self.assertRaisesRegex(StructuralScoringError, "closed normalization"):
                    self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_unmapped_but_well_formed_references_never_receive_credit(self) -> None:
        def internal(document: dict) -> None:
            fact = next(
                fact for fact in document["entities"][0]["facts"]
                if fact["dimension"] == "call.internal"
            )
            fact["value"]["source"] = "function:fn_0000000000400080"

        internal_report = self._score(recovered_path=self._mutated_recovered(internal))
        internal_row = next(
            row for entity in internal_report["entities"] for row in entity["facts"]
            if row["oracleFactId"] == "truth-call-internal"
        )
        self.assertEqual("contradicted", internal_row["outcome"])

        def global_reference(document: dict) -> None:
            document["entities"].append(
                {
                    "kind": "global",
                    "id": "recovered.global.unmapped",
                    "facts": [{
                        "id": "unmapped-global-storage",
                        "slot": "storage",
                        "dimension": "global.storage",
                        "state": "recovered",
                        "value": {"source": "static-rva:0x990", "abi": None},
                        "evidence": [{"kind": "fixture", "locator": "global-unmapped"}],
                    }],
                }
            )
            fact = next(
                fact for fact in document["entities"][0]["facts"]
                if fact["dimension"] == "global.reference"
            )
            fact["value"]["source"] = "global:recovered.global.unmapped"

        global_report = self._score(recovered_path=self._mutated_recovered(global_reference))
        global_row = next(
            row for entity in global_report["entities"] for row in entity["facts"]
            if row["oracleFactId"] == "truth-global-reference"
        )
        self.assertEqual("contradicted", global_row["outcome"])

        def type_reference(document: dict) -> None:
            document["entities"].append(
                {
                    "kind": "type",
                    "id": "recovered.type.unmapped",
                    "facts": [{
                        "id": "unmapped-type-target",
                        "slot": "typedef-target",
                        "dimension": "type.typedef.target",
                        "state": "recovered",
                        "value": {
                            "source": "type-token:signed-i32",
                            "abi": {
                                "callingConvention": None,
                                "classes": ["INTEGER"],
                                "sizeBits": 32,
                                "alignmentBits": 32,
                                "variadic": None,
                            },
                        },
                        "evidence": [{"kind": "fixture", "locator": "type-unmapped"}],
                    }],
                }
            )
            global_entity = next(
                entity for entity in document["entities"]
                if entity["id"] == "recovered.global.900"
            )
            fact = next(fact for fact in global_entity["facts"] if fact["dimension"] == "global.type")
            fact["value"]["source"] = "type-entity:recovered.type.unmapped"

        type_report = self._score(recovered_path=self._mutated_recovered(type_reference))
        type_row = next(
            row for entity in type_report["entities"] for row in entity["facts"]
            if row["oracleFactId"] == "truth-global-type"
        )
        self.assertEqual("contradicted", type_row["outcome"])

    def test_recovered_claim_cannot_select_an_oracle_fact_id(self) -> None:
        def mutate(document: dict) -> None:
            document["entities"][0]["facts"][0]["oracleFactId"] = "truth-interface-prototype"

        with self.assertRaisesRegex(StructuralScoringError, "closed shape"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_unmapped_entity_claims_are_fabricated_without_consuming_truth(self) -> None:
        report = self._score()
        extra = next(item for item in report["entities"] if item["recoveredId"] == "recovered.global.extra")
        self.assertIsNone(extra["oracleId"])
        self.assertEqual(["fabricated"], [fact["outcome"] for fact in extra["facts"]])

    def test_irrelevant_abi_projection_cannot_launder_a_wrong_call(self) -> None:
        def mutate(document: dict) -> None:
            alpha = document["entities"][0]
            call = next(fact for fact in alpha["facts"] if fact["dimension"] == "call.indirect")
            call["value"]["abi"] = {
                "callingConvention": "sysv-amd64",
                "classes": [],
                "sizeBits": None,
                "alignmentBits": None,
                "variadic": None,
            }

        with self.assertRaisesRegex(StructuralScoringError, "forbidden"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_source_and_mechanical_projection_must_agree(self) -> None:
        def mutate(document: dict) -> None:
            alpha = document["entities"][0]
            variadic = next(fact for fact in alpha["facts"] if fact["dimension"] == "function.variadic")
            variadic["value"]["abi"]["variadic"] = True

        with self.assertRaisesRegex(StructuralScoringError, "inconsistent"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_aggregate_offsets_are_nonnegative_and_bounded(self) -> None:
        def mutate(document: dict) -> None:
            packet = next(item for item in document["entities"] if item["id"] == "recovered.type.packet")
            offset = next(fact for fact in packet["facts"] if fact["slot"] == "member:0:offset")
            offset["value"]["source"] = -1

        with self.assertRaisesRegex(StructuralScoringError, "nonnegative"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_descriptor_controls_conventions_and_abi_classes(self) -> None:
        def mutate(document: dict) -> None:
            alpha = document["entities"][0]
            parameter = next(
                fact for fact in alpha["facts"] if fact["dimension"] == "function.parameter-abi-class"
            )
            parameter["value"]["abi"]["classes"] = ["NOT_IN_DESCRIPTOR"]

        with self.assertRaisesRegex(StructuralScoringError, "absent from the target descriptor"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_target_address_width_and_boundary_object_format_are_enforced(self) -> None:
        target_document = json.loads(TARGET.read_text(encoding="utf-8"))
        target_document["target"]["addressBits"] = 32
        target_path = self.temp / "target-32.json"
        _write_json(target_path, target_document)
        target = load_target_abi_descriptor(target_path)

        oracle_document = json.loads(ORACLE.read_text(encoding="utf-8"))
        oracle_document["targetAbi"]["sha256"] = hashlib.sha256(target_path.read_bytes()).hexdigest()
        oracle_document["artifact"]["imageBase"] = "0x100000000"
        oracle_path = self.temp / "oracle-out-of-width.json"
        _write_json(oracle_path, oracle_document)
        with self.assertRaisesRegex(StructuralScoringError, "selected target address width"):
            load_structural_oracle(oracle_path, target)

        target_document["target"]["objectFormat"] = "MACHO"
        mismatch_path = self.temp / "target-macho.json"
        _write_json(mismatch_path, target_document)
        mismatch_target = load_target_abi_descriptor(mismatch_path)
        with self.assertRaisesRegex(StructuralScoringError, "object format"):
            load_boundary_mapping(self.boundary_path, twin="rich", target=mismatch_target)

    def test_closed_normalizations_reject_adapter_local_spellings(self) -> None:
        cases = (
            ("function.prototype", "signed int task(signed int)"),
            ("global.linkage", "file-local-ish"),
            ("type.aggregate.kind", "structure"),
        )
        for dimension, source in cases:
            with self.subTest(dimension=dimension):
                def mutate(document: dict, dimension=dimension, source=source) -> None:
                    fact = next(
                        fact
                        for entity in document["entities"]
                        for fact in entity["facts"]
                        if fact["dimension"] == dimension
                    )
                    fact["value"]["source"] = source

                with self.assertRaisesRegex(StructuralScoringError, "closed normalization"):
                    self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_normalization_profile_is_closed_and_must_match_exactly(self) -> None:
        expected = {
            "id": "structural-source-normalization",
            "version": "1",
            "configurationSha256": NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
        }
        self.assertEqual(
            NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
            hashlib.sha256(NORMALIZATION_PROFILE_CONFIGURATION_BYTES).hexdigest(),
        )
        self.assertEqual(
            set(DIMENSIONS),
            set(NORMALIZATION_PROFILE_CONFIGURATION["dimensionSourceForms"]),
        )
        for schema_name in (
            "structural-oracle.schema.json",
            "recovered-structure.schema.json",
            "structural-score.schema.json",
        ):
            schema = json.loads(
                (REPOSITORY_ROOT / "oracle" / schema_name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                NORMALIZATION_PROFILE_CONFIGURATION_SHA256,
                schema["$defs"]["normalizationProfile"]["properties"]
                ["configurationSha256"]["const"],
            )
        report = self._score()
        self.assertEqual(expected, report["normalizationProfile"])
        self.assertEqual(
            expected,
            report["model"]["provenance"]["normalizationProfile"],
        )

        replacements = (
            ("id", "different-normalization-profile"),
            ("version", "2"),
            ("configurationSha256", "8" * 64),
        )
        for key, replacement in replacements:
            with self.subTest(key=key):
                def mutate(document: dict, key=key, replacement=replacement) -> None:
                    document["provenance"]["normalizationProfile"][key] = replacement

                with self.assertRaisesRegex(StructuralScoringError, "normalization profile"):
                    self._inputs(recovered_path=self._mutated_recovered(mutate))

        def alternate_oracle(document: dict) -> None:
            document["normalizationProfile"]["configurationSha256"] = "8" * 64

        def alternate_recovered(document: dict) -> None:
            document["provenance"]["normalizationProfile"]["configurationSha256"] = "8" * 64

        oracle_path, map_path, recovered_path = self._mutated_bundle(
            oracle_mutator=alternate_oracle,
            recovered_mutator=alternate_recovered,
        )
        with self.assertRaisesRegex(StructuralScoringError, "checked scorer-v1"):
            self._inputs(
                oracle_path=oracle_path,
                identity_map_path=map_path,
                recovered_path=recovered_path,
            )

        forged_report = deepcopy(report)
        forged_report["normalizationProfile"]["configurationSha256"] = "8" * 64
        with self.assertRaisesRegex(
            StructuralScoringError,
            "normalization profile",
        ):
            self._validate_report(forged_report)

    def test_fixture_digest_binds_exporter_loader_target_base_and_input(self) -> None:
        original = json.loads(RECOVERED.read_text(encoding="utf-8"))
        fields = (
            ("exporter", "executableSha256", "1" * 64),
            ("loader", "configurationSha256", "2" * 64),
            ("loader", "imageBase", "0x500000"),
        )
        for index, (section, key, replacement) in enumerate(fields):
            document = deepcopy(original)
            document["provenance"][section][key] = replacement
            path = self.temp / f"unattested-provenance-{index}.json"
            _write_json(path, document)
            with self.assertRaisesRegex(StructuralScoringError, "payload digest"):
                self._inputs(recovered_path=path)

    def test_binary_hash_alone_cannot_promote_fixture_to_production(self) -> None:
        document = json.loads(RECOVERED.read_text(encoding="utf-8"))
        document["scope"] = "production"
        document["attestation"]["kind"] = "adapter-replay"
        _reattest(document)
        path = self.temp / "false-production.json"
        _write_json(path, document)
        with self.assertRaisesRegex(StructuralScoringError, "concrete adapter replay verifier"):
            self._inputs(recovered_path=path)

    def test_identity_map_digest_and_independent_evidence_are_required(self) -> None:
        document = json.loads(IDENTITY_MAP.read_text(encoding="utf-8"))
        document["mappings"][0]["evidence"] = []
        _reattest(document)
        path = self.temp / "empty-map-evidence.json"
        _write_json(path, document)
        with self.assertRaisesRegex(StructuralScoringError, "between 1 and"):
            self._inputs(identity_map_path=path)

    def test_boundary_report_and_image_base_are_cross_checked(self) -> None:
        def mutate(document: dict) -> None:
            document["provenance"]["loader"]["imageBase"] = "0x500000"

        path = self._mutated_recovered(mutate)
        with self.assertRaisesRegex(StructuralScoringError, "image base"):
            self._inputs(recovered_path=path)

    def test_boundary_projection_adapter_is_attested_and_visible(self) -> None:
        report = self._score()
        self.assertEqual(
            {
                "id": "function-recovery-score-elf",
                "version": "1",
                "objectFormat": "ELF",
            },
            report["boundaryMapping"]["projectionAdapter"],
        )
        self.assertEqual(
            {"id": "function-recovery-score-elf", "version": "1"},
            report["model"]["provenance"]["boundaryScore"]["projectionAdapter"],
        )

        def mutate(document: dict) -> None:
            document["provenance"]["boundaryScore"]["projectionAdapter"]["version"] = "2"

        with self.assertRaisesRegex(StructuralScoringError, "projection adapter"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_call_site_slot_requires_caller_local_rva_and_endpoint_kind(self) -> None:
        def mutate(document: dict) -> None:
            alpha = document["entities"][0]
            call = next(fact for fact in alpha["facts"] if fact["dimension"] == "call.external")
            call["slot"] = "call:runtime.write"

        with self.assertRaisesRegex(StructuralScoringError, "canonical call site"):
            self._inputs(recovered_path=self._mutated_recovered(mutate))

    def test_inputs_reject_symlinks(self) -> None:
        link = self.temp / "target-link.json"
        link.symlink_to(TARGET)
        with self.assertRaisesRegex(StructuralScoringError, "regular file"):
            load_target_abi_descriptor(link)

    def test_global_fact_limit_fails_before_scoring(self) -> None:
        with patch("oracle.structural_recovery.MAX_FACTS", 1):
            with self.assertRaisesRegex(StructuralScoringError, "global fact limit"):
                self._inputs()

    def test_scorer_wide_and_report_preconstruction_budgets_fail_closed(self) -> None:
        cases = (
            ("MAX_TOTAL_INPUT_BYTES", "aggregate input budget"),
            ("MAX_TOTAL_ENTITIES", "aggregate entity budget"),
            ("MAX_TOTAL_FACTS", "aggregate fact budget"),
            ("MAX_TOTAL_EVIDENCE", "aggregate evidence budget"),
            ("MAX_REPORT_ENTRIES", "entry budget"),
            ("MAX_PROJECTED_REPORT_BYTES", "preconstruction byte budget"),
        )
        for constant, message in cases:
            with self.subTest(constant=constant):
                target, oracle, boundary, identity_map, recovered = self._inputs()
                with patch(f"oracle.structural_recovery.{constant}", 1):
                    with self.assertRaisesRegex(StructuralScoringError, message):
                        score_fixture_structural_recovery(
                            oracle,
                            recovered,
                            boundary,
                            identity_map,
                            target,
                        )

    def test_oversized_numeric_tokens_take_the_controlled_cli_failure_path(self) -> None:
        target_path = self.temp / "huge-integer-target.json"
        target_path.write_text('{"schemaVersion":' + ("9" * 5000) + "}", encoding="utf-8")
        with self.assertRaisesRegex(StructuralScoringError, "lexical bound"):
            load_target_abi_descriptor(target_path)
        output = self.temp / "huge-integer-score.json"
        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts/score-structural-recovery.py"),
                "--target-abi", str(target_path),
                "--oracle", str(ORACLE),
                "--boundary-score", str(self.boundary_path),
                "--boundary-twin", "rich",
                "--identity-map", str(IDENTITY_MAP),
                "--recovered-model", str(RECOVERED),
                "--json-output", str(output),
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("lexical bound", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_report_is_byte_deterministic_and_has_no_host_path_or_timestamp(self) -> None:
        first = self._canonical_report(self._score())
        second = self._canonical_report(self._score())
        self.assertEqual(first, second)
        rendered = first.decode("utf-8")
        self.assertNotIn(str(self.temp), rendered)
        self.assertNotIn("timestamp", rendered.lower())

    def test_cli_emits_identical_machine_and_human_reports(self) -> None:
        outputs = []
        summaries = []
        for index in range(2):
            output = self.temp / f"cli-score-{index}.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts/score-structural-recovery.py"),
                    "--target-abi",
                    str(TARGET),
                    "--oracle",
                    str(ORACLE),
                    "--boundary-score",
                    str(self.boundary_path),
                    "--boundary-twin",
                    "rich",
                    "--identity-map",
                    str(IDENTITY_MAP),
                    "--recovered-model",
                    str(RECOVERED),
                    "--json-output",
                    str(output),
                ],
                cwd=REPOSITORY_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            outputs.append(output.read_bytes())
            summaries.append(result.stdout.replace(str(output), "<output>"))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(summaries[0], summaries[1])
        self.assertIn("NOT PRODUCTION VERIFIED", summaries[0])

    def test_checked_schemas_validate_descriptor_inputs_and_report(self) -> None:
        try:
            import fastjsonschema
        except ImportError as error:
            self.skipTest(f"fastjsonschema unavailable: {error}")
        pairs = (
            ("target-abi.schema.json", TARGET),
            ("structural-oracle.schema.json", ORACLE),
            ("structural-identity-map.schema.json", IDENTITY_MAP),
            ("recovered-structure.schema.json", RECOVERED),
        )
        for schema_name, document_path in pairs:
            schema = json.loads((REPOSITORY_ROOT / "oracle" / schema_name).read_text(encoding="utf-8"))
            document = json.loads(document_path.read_text(encoding="utf-8"))
            fastjsonschema.compile(schema)(document)
        report_schema = json.loads(
            (REPOSITORY_ROOT / "oracle/structural-score.schema.json").read_text(encoding="utf-8")
        )
        fastjsonschema.compile(report_schema)(self._score())

    def test_scope_and_attestation_discriminators_reject_false_production(self) -> None:
        try:
            import fastjsonschema
        except ImportError as error:
            self.skipTest(f"fastjsonschema unavailable: {error}")
        cases = (
            ("structural-identity-map.schema.json", IDENTITY_MAP),
            ("recovered-structure.schema.json", RECOVERED),
        )
        for schema_name, document_path in cases:
            schema = json.loads((REPOSITORY_ROOT / "oracle" / schema_name).read_text(encoding="utf-8"))
            validate = fastjsonschema.compile(schema)
            fixture = json.loads(document_path.read_text(encoding="utf-8"))
            false_production = deepcopy(fixture)
            false_production["scope"] = "production"
            with self.assertRaises(fastjsonschema.JsonSchemaException, msg=schema_name):
                validate(false_production)
            false_fixture = deepcopy(fixture)
            false_fixture["attestation"]["kind"] = "adapter-replay"
            false_fixture["attestation"]["evidenceSha256"] = "0" * 64
            with self.assertRaises(fastjsonschema.JsonSchemaException, msg=schema_name):
                validate(false_fixture)
            production = deepcopy(fixture)
            production["scope"] = "production"
            production["attestation"]["kind"] = "adapter-replay"
            production["attestation"]["evidenceSha256"] = "0" * 64
            validate(production)

    def test_score_contract_has_distinct_honest_fixture_and_production_verification(self) -> None:
        try:
            import fastjsonschema
        except ImportError as error:
            self.skipTest(f"fastjsonschema unavailable: {error}")
        schema = json.loads(
            (REPOSITORY_ROOT / "oracle/structural-score.schema.json").read_text(encoding="utf-8")
        )
        validate_schema = fastjsonschema.compile(schema)
        fixture = self._score()
        self.assertNotIn("identityMapVerified", fixture["model"]["verification"])
        self.assertEqual(
            "fixture-payload-digest-only",
            fixture["identityMapping"]["verification"],
        )
        production = deepcopy(fixture)
        production["oracle"]["scope"] = "production"
        production["oracle"]["artifactManifestSha256"] = "0" * 64
        production["model"]["scope"] = "production"
        production["model"]["verification"] = {
            "status": "adapter-replay-verified",
            "payloadDigestVerified": True,
            "identityMapPayloadDigestVerified": True,
            "adapterReplayVerified": True,
            "productionVerified": True,
        }
        production["identityMapping"]["verification"] = "adapter-replay-verified"
        production["identityMapping"]["productionVerified"] = True
        validate_schema(production)
        with self.assertRaisesRegex(StructuralScoringError, "trusted adapter-replay verifier"):
            self._validate_report(production)

        false_production = deepcopy(production)
        false_production["model"]["verification"] = fixture["model"]["verification"]
        with self.assertRaises(fastjsonschema.JsonSchemaException):
            validate_schema(false_production)
        with self.assertRaisesRegex(StructuralScoringError, "trusted adapter-replay verifier"):
            self._validate_report(false_production)

    def test_score_schema_and_semantic_validator_reject_omission_and_metric_forgery(self) -> None:
        try:
            import fastjsonschema
        except ImportError as error:
            self.skipTest(f"fastjsonschema unavailable: {error}")
        schema = json.loads(
            (REPOSITORY_ROOT / "oracle/structural-score.schema.json").read_text(encoding="utf-8")
        )
        validate_schema = fastjsonschema.compile(schema)
        report = self._score()

        schema_invalid_reports = []
        invalid_policy = deepcopy(report)
        invalid_policy["policy"]["identitySelection"] = "attacker-selected"
        schema_invalid_reports.append(invalid_policy)
        invalid_limit = deepcopy(report)
        invalid_limit["policy"]["limits"]["maxFacts"] += 1
        schema_invalid_reports.append(invalid_limit)
        invalid_adapter = deepcopy(report)
        invalid_adapter["boundaryMapping"]["projectionAdapter"]["version"] = "2"
        schema_invalid_reports.append(invalid_adapter)
        for invalid_report in schema_invalid_reports:
            with self.assertRaises(fastjsonschema.JsonSchemaException):
                validate_schema(invalid_report)

        omitted = deepcopy(report)
        omitted["dimensions"] = omitted["dimensions"][:-1]
        with self.assertRaises(fastjsonschema.JsonSchemaException):
            validate_schema(omitted)
        with self.assertRaisesRegex(StructuralScoringError, "between 20 and 20"):
            self._validate_report(omitted)

        reordered = deepcopy(report)
        reordered["dimensions"][0], reordered["dimensions"][1] = (
            reordered["dimensions"][1],
            reordered["dimensions"][0],
        )
        validate_schema(reordered)
        with self.assertRaisesRegex(StructuralScoringError, "every dimension exactly once in order"):
            self._validate_report(reordered)

        forged = deepcopy(report)
        forged["aggregate"]["oracleDenominator"] += 1
        validate_schema(forged)
        with self.assertRaisesRegex(StructuralScoringError, "aggregate is inconsistent"):
            self._validate_report(forged)

        impossible = deepcopy(report)
        exact = next(
            row for entity in impossible["entities"] for row in entity["facts"]
            if row["outcome"] == "exact"
        )
        exact["oracleFactId"] = None
        with self.assertRaises(fastjsonschema.JsonSchemaException):
            validate_schema(impossible)
        with self.assertRaisesRegex(StructuralScoringError, "impossible concrete-outcome"):
            self._validate_report(impossible)

    def test_semantic_validator_recomputes_outcomes_and_mapping_normalization(self) -> None:
        report = self._score()

        flipped = deepcopy(report)
        contradicted = next(
            row
            for entity in flipped["entities"]
            for row in entity["facts"]
            if row["outcome"] == "contradicted"
        )
        contradicted["outcome"] = "exact"
        _refresh_report_metrics(flipped)
        with self.assertRaisesRegex(StructuralScoringError, "outcome does not match"):
            self._validate_report(flipped)

        normalized_forgery = deepcopy(report)
        internal_call = next(
            row
            for entity in normalized_forgery["entities"]
            for row in entity["facts"]
            if row["oracleFactId"] == "truth-call-internal"
        )
        internal_call["normalizedRecoveredValue"]["source"] = (
            "function:die-cu0-10-alpha"
        )
        with self.assertRaisesRegex(StructuralScoringError, "normalized comparison binding"):
            self._validate_report(normalized_forgery)

        mapping_forgery = deepcopy(report)
        internal_call = next(
            row
            for entity in mapping_forgery["entities"]
            for row in entity["facts"]
            if row["oracleFactId"] == "truth-call-internal"
        )
        internal_call["referenceMappingVerified"] = False
        with self.assertRaisesRegex(StructuralScoringError, "normalized comparison binding"):
            self._validate_report(mapping_forgery)

    def test_semantic_validator_enforces_the_closed_report_contract(self) -> None:
        report = self._score()

        invalid_policy_shape = deepcopy(report)
        invalid_policy_shape["policy"] = "not-an-object"
        with self.assertRaisesRegex(StructuralScoringError, "policy must be an object"):
            self._validate_report(invalid_policy_shape)

        changed_policy = deepcopy(report)
        changed_policy["policy"]["identitySelection"] = "attacker-selected"
        with self.assertRaisesRegex(StructuralScoringError, "checked scorer contract"):
            self._validate_report(changed_policy)

        changed_limit = deepcopy(report)
        changed_limit["policy"]["limits"]["maxFacts"] += 1
        with self.assertRaisesRegex(StructuralScoringError, "checked scorer contract"):
            self._validate_report(changed_limit)

        non_boolean_verification = deepcopy(report)
        non_boolean_verification["model"]["verification"]["payloadDigestVerified"] = 1
        with self.assertRaisesRegex(StructuralScoringError, "must be a boolean"):
            self._validate_report(non_boolean_verification)

        non_integer_metric = deepcopy(report)
        metric = next(
            item["metric"]
            for item in non_integer_metric["entities"]
            if item["metric"]["oracleDenominator"] == 1
        )
        metric["oracleDenominator"] = True
        with self.assertRaisesRegex(StructuralScoringError, "must be an integer"):
            self._validate_report(non_integer_metric)

        invalid_source = deepcopy(report)
        prototype = next(
            row
            for entity in invalid_source["entities"]
            for row in entity["facts"]
            if row["dimension"] == "function.prototype" and row["outcome"] == "exact"
        )
        for key in ("oracleValue", "recoveredValue", "normalizedRecoveredValue"):
            prototype[key] = {"source": "global:not-a-prototype", "abi": None}
        with self.assertRaisesRegex(StructuralScoringError, "closed normalization"):
            self._validate_report(invalid_source)

        invalid_slot = deepcopy(report)
        prototype = next(
            row
            for entity in invalid_slot["entities"]
            for row in entity["facts"]
            if row["dimension"] == "function.prototype" and row["outcome"] == "exact"
        )
        prototype["slot"] = "not-a-prototype-slot"
        with self.assertRaisesRegex(StructuralScoringError, "must be 'prototype'"):
            self._validate_report(invalid_slot)

        invalid_entity_dimension = deepcopy(report)
        prototype_only = next(
            entity
            for entity in invalid_entity_dimension["entities"]
            if entity["kind"] == "function"
            and len(entity["facts"]) == 1
            and entity["facts"][0]["outcome"] == "exact"
        )
        prototype_only["facts"][0]["dimension"] = "global.linkage"
        with self.assertRaisesRegex(StructuralScoringError, "incompatible with its report entity kind"):
            self._validate_report(invalid_entity_dimension)

        invalid_target_class = deepcopy(report)
        typedef = next(
            row
            for entity in invalid_target_class["entities"]
            for row in entity["facts"]
            if row["dimension"] == "type.typedef.target"
        )
        for key in ("oracleValue", "recoveredValue", "normalizedRecoveredValue"):
            typedef[key]["abi"]["classes"] = ["NOT_IN_DESCRIPTOR"]
        with self.assertRaisesRegex(StructuralScoringError, "absent from the target descriptor"):
            self._validate_report(invalid_target_class)

        invalid_projection = deepcopy(report)
        invalid_projection["boundaryMapping"]["projectionAdapter"]["version"] = "2"
        with self.assertRaisesRegex(StructuralScoringError, "projection adapter"):
            self._validate_report(invalid_projection)

        open_nested_header = deepcopy(report)
        open_nested_header["model"]["provenance"]["inputBinary"]["extra"] = True
        with self.assertRaisesRegex(StructuralScoringError, "closed shape"):
            self._validate_report(open_nested_header)

    def test_semantic_validator_rejects_duplicate_reordered_and_unbounded_rows(self) -> None:
        report = self._score()

        duplicate_entity = deepcopy(report)
        duplicate_entity["entities"].append(deepcopy(duplicate_entity["entities"][-1]))
        with self.assertRaisesRegex(StructuralScoringError, "duplicates an oracle entity"):
            self._validate_report(duplicate_entity)

        duplicate_fact_id = deepcopy(report)
        entity = next(item for item in duplicate_fact_id["entities"] if len(item["facts"]) > 1)
        entity["facts"][1]["oracleFactId"] = entity["facts"][0]["oracleFactId"]
        with self.assertRaisesRegex(StructuralScoringError, "duplicates oracleFactId"):
            self._validate_report(duplicate_fact_id)

        duplicate_slot = deepcopy(report)
        entity = next(item for item in duplicate_slot["entities"] if len(item["facts"]) > 1)
        duplicate = deepcopy(entity["facts"][0])
        duplicate["oracleFactId"] = "duplicate-oracle-fact"
        duplicate["recoveredFactId"] = "duplicate-recovered-fact"
        entity["facts"].insert(1, duplicate)
        with self.assertRaisesRegex(StructuralScoringError, "duplicates a fact dimension and slot"):
            self._validate_report(duplicate_slot)

        reordered_entities = deepcopy(report)
        reordered_entities["entities"][0], reordered_entities["entities"][1] = (
            reordered_entities["entities"][1],
            reordered_entities["entities"][0],
        )
        with self.assertRaisesRegex(StructuralScoringError, "entities are not in canonical order"):
            self._validate_report(reordered_entities)

        reordered_facts = deepcopy(report)
        entity = next(item for item in reordered_facts["entities"] if len(item["facts"]) > 1)
        entity["facts"][0], entity["facts"][1] = entity["facts"][1], entity["facts"][0]
        with self.assertRaisesRegex(StructuralScoringError, "facts are not in canonical order"):
            self._validate_report(reordered_facts)

        fact_limited = deepcopy(report)
        fact_limited["policy"]["limits"]["maxReportEntries"] = 1
        with patch("oracle.structural_recovery.MAX_REPORT_ENTRIES", 1):
            with self.assertRaisesRegex(StructuralScoringError, "aggregate fact limit"):
                self._validate_report(fact_limited)
        evidence_limited = deepcopy(report)
        evidence_limited["policy"]["limits"]["maxTotalEvidence"] = 1
        with patch("oracle.structural_recovery.MAX_TOTAL_EVIDENCE", 1):
            with self.assertRaisesRegex(StructuralScoringError, "aggregate evidence limit"):
                self._validate_report(evidence_limited)

    def test_formal_schemas_are_closed_at_every_object_boundary(self) -> None:
        for name in (
            "target-abi.schema.json",
            "structural-oracle.schema.json",
            "structural-identity-map.schema.json",
            "recovered-structure.schema.json",
            "structural-score.schema.json",
        ):
            schema = json.loads((REPOSITORY_ROOT / "oracle" / name).read_text(encoding="utf-8"))
            objects = []

            def visit(value):
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        objects.append(value)
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)

            visit(schema)
            self.assertTrue(objects, name)
            for item in objects:
                self.assertFalse(item.get("additionalProperties", False), name)

    def test_generic_scoring_surface_contains_no_benchmark_cases(self) -> None:
        generic_files = (
            REPOSITORY_ROOT / "oracle/structural_recovery.py",
            REPOSITORY_ROOT / "oracle/target-abi.schema.json",
            REPOSITORY_ROOT / "oracle/structural-oracle.schema.json",
            REPOSITORY_ROOT / "oracle/structural-identity-map.schema.json",
            REPOSITORY_ROOT / "oracle/recovered-structure.schema.json",
            REPOSITORY_ROOT / "oracle/structural-score.schema.json",
            REPOSITORY_ROOT / "oracle/targets/sysv-amd64-v1.json",
            REPOSITORY_ROOT / "scripts/score-structural-recovery.py",
            REPOSITORY_ROOT / "docs/structural-recovery-scoring.md",
        )
        for path in generic_files:
            self.assertNotIn("gcc", path.read_text(encoding="utf-8").lower(), str(path))


if __name__ == "__main__":
    unittest.main()
