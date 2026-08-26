from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from typing import Any, Callable, Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

import oracle.function_recovery as function_scorer  # noqa: E402
import oracle.gcc.score_function_recovery as gcc_adapter  # noqa: E402
from oracle.function_recovery import (  # noqa: E402
    Evidence,
    OracleAlias,
    OracleFunction,
    RecoveredFunction,
    ScoringError,
    _minimum_cost_near_assignment,
    load_function_oracle,
    load_program_model,
    report_json_bytes,
    score_function_recovery,
)
from oracle.gcc.score_function_recovery import (  # noqa: E402
    _artifact_metadata_from_manifest,
    score_files,
)


FIXTURES = REPOSITORY_ROOT / "tests/oracle/fixtures/function_recovery"
ORACLE = FIXTURES / "oracle.json"
RICH_MODEL = FIXTURES / "rich-model.json"
STRIPPED_MODEL = FIXTURES / "stripped-model.json"
ORACLE_SCHEMA = REPOSITORY_ROOT / "oracle/function-recovery-oracle.schema.json"
SCORE_SCHEMA = REPOSITORY_ROOT / "oracle/function-recovery-score.schema.json"
SCORER = REPOSITORY_ROOT / "scripts/score-gcc-function-recovery.py"
RICH_MODEL_IMAGE_BASE = 0x400000
STRIPPED_MODEL_IMAGE_BASE = 0x500000


def validate_json_schema(schema: dict[str, Any], instance: Any) -> None:
    """Use a standards validator when installed, with a strict local fallback."""

    try:
        import fastjsonschema  # type: ignore[import-untyped]
    except ModuleNotFoundError:
        fastjsonschema = None  # type: ignore[assignment]
    if fastjsonschema is not None:
        try:
            fastjsonschema.compile(schema)(instance)
        except fastjsonschema.JsonSchemaException as error:
            raise AssertionError(str(error)) from error
        return

    def json_equal(left: Any, right: Any) -> bool:
        if isinstance(left, bool) or isinstance(right, bool):
            return type(left) is type(right) and left == right
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left == right
        if type(left) is not type(right):
            return False
        if isinstance(left, list):
            return len(left) == len(right) and all(  # type: ignore[arg-type]
                json_equal(a, b) for a, b in zip(left, right)
            )
        if isinstance(left, dict):
            return set(left) == set(right) and all(  # type: ignore[arg-type]
                json_equal(left[key], right[key]) for key in left
            )
        return left == right

    def resolve(reference: str) -> dict[str, Any]:
        if not reference.startswith("#/"):
            raise AssertionError(f"unsupported non-local schema reference: {reference}")
        value: Any = schema
        for part in reference[2:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
        return value

    def check(specification: dict[str, Any], value: Any, path: str) -> None:
        if "$ref" in specification:
            check(resolve(specification["$ref"]), value, path)
            return
        if "oneOf" in specification:
            matches = 0
            for choice in specification["oneOf"]:
                try:
                    check(choice, value, path)
                except AssertionError:
                    continue
                matches += 1
            if matches != 1:
                raise AssertionError(f"{path} matches {matches} oneOf branches")
        if "const" in specification and not json_equal(
            value,
            specification["const"],
        ):
            raise AssertionError(f"{path} does not match const")
        if "enum" in specification and not any(
            json_equal(value, choice) for choice in specification["enum"]
        ):
            raise AssertionError(f"{path} is outside enum")

        expected_type = specification.get("type")
        if expected_type == "object":
            if not isinstance(value, dict):
                raise AssertionError(f"{path} is not an object")
            required = set(specification.get("required", []))
            if not required <= set(value):
                raise AssertionError(f"{path} misses required fields")
            properties = specification.get("properties", {})
            if specification.get("additionalProperties") is False:
                unexpected = set(value) - set(properties)
                if unexpected:
                    raise AssertionError(f"{path} has unexpected fields {unexpected}")
            for key, child in properties.items():
                if key in value:
                    check(child, value[key], f"{path}.{key}")
        elif expected_type == "array":
            if not isinstance(value, list):
                raise AssertionError(f"{path} is not an array")
            if len(value) < specification.get("minItems", 0):
                raise AssertionError(f"{path} has too few items")
            if len(value) > specification.get("maxItems", len(value)):
                raise AssertionError(f"{path} has too many items")
            if specification.get("uniqueItems"):
                canonical = [json.dumps(item, sort_keys=True) for item in value]
                if len(canonical) != len(set(canonical)):
                    raise AssertionError(f"{path} has duplicate items")
            if "items" in specification:
                for index, item in enumerate(value):
                    check(specification["items"], item, f"{path}[{index}]")
        elif expected_type == "string":
            if not isinstance(value, str):
                raise AssertionError(f"{path} is not a string")
            if len(value) < specification.get("minLength", 0):
                raise AssertionError(f"{path} is too short")
            if len(value) > specification.get("maxLength", len(value)):
                raise AssertionError(f"{path} is too long")
            if "pattern" in specification and re.search(specification["pattern"], value) is None:
                raise AssertionError(f"{path} does not match pattern")
        elif expected_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise AssertionError(f"{path} is not an integer")
        elif expected_type == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise AssertionError(f"{path} is not a number")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                raise AssertionError(f"{path} is not a boolean")
        elif expected_type == "null":
            if value is not None:
                raise AssertionError(f"{path} is not null")
        elif expected_type is not None:
            raise AssertionError(f"unsupported schema type {expected_type}")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value < specification.get("minimum", value):
                raise AssertionError(f"{path} is below minimum")
            if value > specification.get("maximum", value):
                raise AssertionError(f"{path} is above maximum")

    check(schema, instance, "$")


def score_fixture(
    oracle: Path = ORACLE,
    rich_model: Path = RICH_MODEL,
    stripped_model: Path = STRIPPED_MODEL,
    *,
    rich_model_image_base: int = RICH_MODEL_IMAGE_BASE,
    stripped_model_image_base: int = STRIPPED_MODEL_IMAGE_BASE,
    artifact_manifest: Path | None = None,
) -> dict[str, Any]:
    return score_files(
        oracle,
        rich_model,
        stripped_model,
        rich_model_image_base=rich_model_image_base,
        stripped_model_image_base=stripped_model_image_base,
        artifact_manifest_path=artifact_manifest,
    )


class GccFunctionRecoveryTest(unittest.TestCase):
    @contextmanager
    def staged_text(self, name: str, payload: str) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="function-score-raw-") as temporary:
            path = Path(temporary) / name
            path.write_text(payload, encoding="utf-8")
            yield path

    @contextmanager
    def staged_json(
        self,
        source: Path,
        mutation: Callable[[dict[str, Any]], None],
    ) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="function-score-mutation-") as temporary:
            value = copy.deepcopy(json.loads(source.read_text(encoding="utf-8")))
            mutation(value)
            path = Path(temporary) / source.name
            path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            yield path

    @staticmethod
    def oracle_function(identifier: str, rva: int, name: str) -> OracleFunction:
        return OracleFunction(
            identifier=identifier,
            rva=rva,
            aliases=(
                OracleAlias(
                    name=name,
                    evidence=(Evidence("dwarf-subprogram", f"fixture:{identifier}"),),
                    availability={"rich": "surviving", "stripped": "removed"},
                ),
            ),
            exclusion=None,
        )

    @staticmethod
    def recovered_function(identifier: str, rva: int, name: str) -> RecoveredFunction:
        return RecoveredFunction(identifier, name, rva, "recovered")

    def test_fixture_covers_both_twins_and_every_required_result_class(self) -> None:
        report = score_fixture()

        self.assertEqual("fixture", report["oracle"]["scope"])
        self.assertEqual(
            {
                "status": "fixture-non-production",
                "artifactManifestVerified": False,
                "programModelProvenance": "fixture-inputs",
                "productionVerified": False,
            },
            report["oracle"]["verification"],
        )
        self.assertIsNone(report["oracle"]["artifactManifestSha256"])
        self.assertEqual(5, report["oracle"]["scoredFunctionCount"])
        self.assertEqual(
            {"compiler-generated": 1, "inlined": 1},
            report["oracle"]["exclusions"],
        )
        self.assertEqual(
            ["compiler-generated", "inlined"],
            [item["kind"] for item in report["oracle"]["excludedFunctions"]],
        )
        self.assertIsNone(report["oracle"]["excludedFunctions"][1]["rva"])

        for twin in ("rich", "stripped"):
            boundaries = report["twins"][twin]["boundaries"]
            self.assertEqual(5, boundaries["referenceCount"])
            self.assertEqual(6, boundaries["rawRecoveredCount"])
            self.assertEqual(5, boundaries["scoredRecoveredCount"])
            self.assertEqual(1, boundaries["ignoredExcludedCount"])
            self.assertEqual(3, boundaries["exactMatches"])
            self.assertEqual(1, boundaries["nearMisses"])
            self.assertEqual(1, boundaries["falsePositives"])
            self.assertEqual(1, boundaries["falseNegatives"])
            self.assertEqual(
                {"numerator": 4, "denominator": 5, "value": 0.8},
                boundaries["precision"],
            )
            self.assertEqual(boundaries["precision"], boundaries["recall"])
            self.assertEqual(
                {"numerator": 8, "denominator": 10, "value": 0.8},
                boundaries["f1"],
            )
            self.assertEqual(
                {"numerator": 3, "denominator": 5, "value": 0.6},
                boundaries["exactAddressRate"],
            )
            self.assertEqual(
                {"numerator": 1, "denominator": 5, "value": 0.2},
                boundaries["nearMissRate"],
            )

        rich_names = report["twins"]["rich"]["nameRecovery"]
        self.assertEqual(
            {
                "referenceCount": 5,
                "exact": 2,
                "incorrect": 2,
                "missingBoundary": 1,
                "accuracy": {"numerator": 2, "denominator": 5, "value": 0.4},
            },
            rich_names["overall"],
        )
        self.assertEqual(rich_names["overall"], rich_names["surviving"])
        self.assertEqual(0, rich_names["removed"]["referenceCount"])
        self.assertIsNone(rich_names["removed"]["accuracy"]["value"])
        self.assertEqual(0, rich_names["notObservableCount"])

        stripped_names = report["twins"]["stripped"]["nameRecovery"]
        self.assertEqual(2, stripped_names["overall"]["exact"])
        self.assertEqual(0, stripped_names["surviving"]["exact"])
        self.assertEqual(1, stripped_names["surviving"]["incorrect"])
        self.assertEqual(
            {"numerator": 2, "denominator": 5, "value": 0.4},
            stripped_names["removed"]["accuracy"],
        )
        stripped_near = report["twins"]["stripped"]["nearMisses"][0]
        self.assertEqual(-3, stripped_near["deltaBytes"])
        stripped_beta = next(
            match
            for match in report["twins"]["stripped"]["exactMatches"]
            if match["oracleId"] == "die-cu0-20-beta"
        )
        self.assertEqual(
            [
                ("beta", "surviving"),
                ("beta_alias", "removed"),
            ],
            [
                (alias["name"], alias["availability"])
                for alias in stripped_beta["oracleAliases"]
            ],
        )
        self.assertFalse(
            report["twins"]["rich"]["nearMatchAssignment"][
                "hasAlternativeOptimalMatching"
            ]
        )
        self.assertEqual(
            "explicit-scorer-input",
            report["twins"]["rich"]["artifact"]["modelImageBaseEvidence"],
        )
        self.assertEqual(
            "fixture-explicit-input",
            report["twins"]["rich"]["artifact"]["modelImageBaseValidation"],
        )
        self.assertEqual(
            "compiler-generated",
            report["twins"]["rich"]["ignoredExcludedRecoveries"][0]["exclusionKind"],
        )

    def test_reordering_all_function_arrays_does_not_change_report_bytes(self) -> None:
        expected = report_json_bytes(score_fixture())
        with self.staged_json(ORACLE, lambda data: data["functions"].reverse()) as oracle:
            with self.staged_json(
                RICH_MODEL,
                lambda data: data["functions"].reverse(),
            ) as rich:
                with self.staged_json(
                    STRIPPED_MODEL,
                    lambda data: data["functions"].reverse(),
                ) as stripped:
                    actual = report_json_bytes(score_fixture(oracle, rich, stripped))

        self.assertEqual(expected, actual)

    def test_mixed_alias_availability_scores_the_selected_alias_category(self) -> None:
        def recover_name(name: str) -> Callable[[dict[str, Any]], None]:
            def mutate(data: dict[str, Any]) -> None:
                function = next(
                    item for item in data["functions"] if item["address"] == "0x500020"
                )
                function["name"] = name

            return mutate

        with self.staged_json(STRIPPED_MODEL, recover_name("beta")) as stripped:
            surviving_report = score_fixture(stripped_model=stripped)
        surviving_names = surviving_report["twins"]["stripped"]["nameRecovery"]
        self.assertEqual(1, surviving_names["surviving"]["exact"])
        self.assertEqual(2, surviving_names["removed"]["exact"])
        surviving_match = next(
            match
            for match in surviving_report["twins"]["stripped"]["exactMatches"]
            if match["oracleId"] == "die-cu0-20-beta"
        )
        self.assertEqual("surviving", surviving_match["matchedAliasAvailability"])
        self.assertEqual(
            {"surviving": "exact", "removed": "incorrect"},
            surviving_match["nameCategoryResults"],
        )

        with self.staged_json(STRIPPED_MODEL, recover_name("beta_alias")) as stripped:
            removed_report = score_fixture(stripped_model=stripped)
        removed_names = removed_report["twins"]["stripped"]["nameRecovery"]
        self.assertEqual(0, removed_names["surviving"]["exact"])
        self.assertEqual(3, removed_names["removed"]["exact"])
        removed_match = next(
            match
            for match in removed_report["twins"]["stripped"]["exactMatches"]
            if match["oracleId"] == "die-cu0-20-beta"
        )
        self.assertEqual("removed", removed_match["matchedAliasAvailability"])
        self.assertEqual(
            {"surviving": "incorrect", "removed": "exact"},
            removed_match["nameCategoryResults"],
        )

    def test_near_assignment_prefers_nearest_candidate_over_earliest_candidate(self) -> None:
        oracle = [self.oracle_function("oracle", 2, "target")]
        recovered = [
            self.recovered_function("earliest", 0, "target"),
            self.recovered_function("nearest", 1, "wrong-name"),
        ]

        assignment = _minimum_cost_near_assignment(oracle, recovered, 2)

        self.assertEqual(
            [("oracle", "nearest")],
            [(left.identifier, right.identifier) for left, right in assignment.matches],
        )
        self.assertEqual(1, assignment.total_distance_bytes)
        self.assertEqual(["earliest"], [item.identifier for item in assignment.false_positives])

    def test_near_assignment_maximizes_cardinality_before_distance(self) -> None:
        oracle = [
            self.oracle_function("first", 2, "first"),
            self.oracle_function("second", 5, "second"),
        ]
        recovered = [
            self.recovered_function("zero", 0, "zero"),
            self.recovered_function("three", 3, "three"),
        ]

        assignment = _minimum_cost_near_assignment(oracle, recovered, 2)

        self.assertEqual(2, len(assignment.matches))
        self.assertEqual(4, assignment.total_distance_bytes)

    def test_equal_cost_near_assignment_has_stable_tie_and_ambiguity_evidence(self) -> None:
        oracle = [self.oracle_function("oracle", 2, "target")]
        recovered = [
            self.recovered_function("lower", 1, "wrong-lower"),
            self.recovered_function("upper", 3, "target"),
        ]

        assignment = _minimum_cost_near_assignment(oracle, recovered, 1)

        self.assertEqual("lower", assignment.matches[0][1].identifier)
        self.assertEqual(
            ["lower", "upper"],
            [right.identifier for _, right in assignment.optimal_candidate_edges],
        )

        renamed = [
            self.recovered_function("lower", 1, "target"),
            self.recovered_function("upper", 3, "wrong-upper"),
        ]
        renamed_assignment = _minimum_cost_near_assignment(oracle, renamed, 1)
        self.assertEqual("lower", renamed_assignment.matches[0][1].identifier)

    def test_report_exposes_alternative_optimal_near_edges(self) -> None:
        def one_oracle(data: dict[str, Any]) -> None:
            data["functions"] = [data["functions"][0]]
            data["functions"][0]["rva"] = "0x12"

        def tied_recoveries(data: dict[str, Any]) -> None:
            data["functions"] = data["functions"][:2]
            data["functions"][0]["address"] = "0x400011"
            data["functions"][0]["id"] = "lower"
            data["functions"][1]["address"] = "0x400013"
            data["functions"][1]["id"] = "upper"

        with self.staged_json(ORACLE, one_oracle) as oracle:
            with self.staged_json(RICH_MODEL, tied_recoveries) as rich:
                report = score_fixture(oracle, rich)

        assignment = report["twins"]["rich"]["nearMatchAssignment"]
        self.assertTrue(assignment["hasAlternativeOptimalMatching"])
        self.assertEqual(2, assignment["optimalCandidateEdgeCount"])
        self.assertEqual("upper", assignment["alternativeOptimalEdges"][0]["recoveredId"])
        self.assertEqual("lower", report["twins"]["rich"]["nearMisses"][0]["recoveredId"])

    def test_exact_matches_are_fixed_before_higher_cardinality_near_assignment(self) -> None:
        def two_adjacent_oracle_functions(data: dict[str, Any]) -> None:
            data["functions"] = data["functions"][:2]
            data["functions"][0]["rva"] = "0x10"
            data["functions"][1]["rva"] = "0x11"
            data["scoringPolicy"]["nearMissBytes"] = 1

        def two_shifted_recoveries(data: dict[str, Any]) -> None:
            data["functions"] = data["functions"][:2]
            data["functions"][0]["address"] = "0x400011"
            data["functions"][1]["address"] = "0x400012"

        with self.staged_json(ORACLE, two_adjacent_oracle_functions) as oracle:
            with self.staged_json(RICH_MODEL, two_shifted_recoveries) as rich:
                report = score_fixture(oracle, rich)

        boundaries = report["twins"]["rich"]["boundaries"]
        self.assertEqual(1, boundaries["exactMatches"])
        self.assertEqual(0, boundaries["nearMisses"])
        self.assertEqual(1, boundaries["falsePositives"])
        self.assertEqual(1, boundaries["falseNegatives"])

    def test_exclusion_mutation_changes_denominators_instead_of_hiding_it(self) -> None:
        def include_compiler_generated(data: dict[str, Any]) -> None:
            clone = next(function for function in data["functions"] if function["rva"] == "0x60")
            clone["exclusion"] = None
            for alias in clone["aliases"]:
                alias["availability"] = {
                    "rich": "surviving",
                    "stripped": "removed",
                }

        with self.staged_json(ORACLE, include_compiler_generated) as oracle:
            report = score_fixture(oracle)

        rich = report["twins"]["rich"]["boundaries"]
        self.assertEqual(6, report["oracle"]["scoredFunctionCount"])
        self.assertEqual(6, rich["referenceCount"])
        self.assertEqual(6, rich["scoredRecoveredCount"])
        self.assertEqual(0, rich["ignoredExcludedCount"])
        self.assertEqual(5, rich["truePositives"])

    def test_inline_record_cannot_mutate_into_a_scoreable_denominator_without_rva(self) -> None:
        def include_inline(data: dict[str, Any]) -> None:
            inline = next(function for function in data["functions"] if function["rva"] is None)
            inline["exclusion"] = None

        with self.staged_json(ORACLE, include_inline) as oracle:
            with self.assertRaisesRegex(ScoringError, "scoreable.*must have an RVA"):
                load_function_oracle(oracle)

    def test_aliases_must_share_one_record_and_cannot_inflate_boundary_denominator(self) -> None:
        def duplicate_start(data: dict[str, Any]) -> None:
            duplicate = copy.deepcopy(data["functions"][0])
            duplicate["id"] = "duplicate-alpha-alias"
            duplicate["aliases"][0]["name"] = "another_alpha_alias"
            data["functions"].append(duplicate)

        with self.staged_json(ORACLE, duplicate_start) as oracle:
            with self.assertRaisesRegex(ScoringError, "share RVA.*group aliases"):
                load_function_oracle(oracle)

    def test_missing_boundary_remains_in_name_denominator(self) -> None:
        def drop_alpha(data: dict[str, Any]) -> None:
            data["functions"] = [
                function
                for function in data["functions"]
                if function["address"] != "0x400010"
            ]

        with self.staged_json(RICH_MODEL, drop_alpha) as rich:
            report = score_fixture(rich_model=rich)

        names = report["twins"]["rich"]["nameRecovery"]["overall"]
        self.assertEqual(5, names["referenceCount"])
        self.assertEqual(1, names["exact"])
        self.assertEqual(2, names["missingBoundary"])
        self.assertEqual(2, names["incorrect"])

    def test_scoreable_name_cannot_mutate_out_of_the_denominator(self) -> None:
        def hide_alpha(data: dict[str, Any]) -> None:
            data["functions"][0]["aliases"][0]["availability"]["rich"] = "not-observable"

        with self.staged_json(ORACLE, hide_alpha) as oracle:
            with self.assertRaisesRegex(
                ScoringError,
                "must be surviving in the rich twin",
            ):
                load_function_oracle(oracle)

    def test_equal_base_and_address_shift_preserves_normalized_scoring(self) -> None:
        baseline = score_fixture()["twins"]["rich"]

        def shift_addresses(data: dict[str, Any]) -> None:
            for function in data["functions"]:
                function["address"] = hex(int(function["address"], 16) + 0x100)

        with self.staged_json(RICH_MODEL, shift_addresses) as rich:
            shifted = score_fixture(
                rich_model=rich,
                rich_model_image_base=RICH_MODEL_IMAGE_BASE + 0x100,
            )["twins"]["rich"]

        baseline = copy.deepcopy(baseline)
        shifted = copy.deepcopy(shifted)
        baseline["artifact"].pop("modelImageBase")
        shifted["artifact"].pop("modelImageBase")
        self.assertEqual(baseline, shifted)

    def test_base_mutation_is_visible_and_never_auto_corrected(self) -> None:
        report = score_fixture(rich_model_image_base=RICH_MODEL_IMAGE_BASE + 1)

        boundaries = report["twins"]["rich"]["boundaries"]
        self.assertEqual(0, boundaries["exactMatches"])
        self.assertEqual(0, boundaries["ignoredExcludedCount"])
        self.assertGreater(boundaries["falsePositives"], 1)

    def test_near_miss_bound_mutation_reclassifies_without_denominator_drift(self) -> None:
        def tighten_bound(data: dict[str, Any]) -> None:
            data["scoringPolicy"]["nearMissBytes"] = 1

        with self.staged_json(ORACLE, tighten_bound) as oracle:
            report = score_fixture(oracle)

        for twin in ("rich", "stripped"):
            boundaries = report["twins"][twin]["boundaries"]
            self.assertEqual(5, boundaries["referenceCount"])
            self.assertEqual(5, boundaries["scoredRecoveredCount"])
            self.assertEqual(0, boundaries["nearMisses"])
            self.assertEqual(2, boundaries["falsePositives"])
            self.assertEqual(2, boundaries["falseNegatives"])

    def test_noncanonical_or_underflowing_model_addresses_are_rejected(self) -> None:
        def leading_zero(data: dict[str, Any]) -> None:
            data["functions"][0]["address"] = "0x0400010"

        with self.staged_json(RICH_MODEL, leading_zero) as rich:
            with self.assertRaisesRegex(ScoringError, "canonical lowercase"):
                score_fixture(rich_model=rich)

        def underflow(data: dict[str, Any]) -> None:
            data["functions"][0]["address"] = "0x3fffff"

        with self.staged_json(RICH_MODEL, underflow) as rich:
            with self.assertRaisesRegex(ScoringError, "below.*program-model image base"):
                score_fixture(rich_model=rich)

        def wider_than_64_bits(data: dict[str, Any]) -> None:
            data["functions"][0]["rva"] = "0x10000000000000000"

        with self.staged_json(ORACLE, wider_than_64_bits) as oracle:
            with self.assertRaisesRegex(ScoringError, "hexadecimal address"):
                load_function_oracle(oracle)

    def test_strict_json_numbers_and_resource_errors_are_concise(self) -> None:
        source = ORACLE.read_text(encoding="utf-8")
        needle = '"nearMissBytes": 4'
        invalid_numbers = {
            "nan": "NaN",
            "infinity": "Infinity",
            "negative-infinity": "-Infinity",
            "huge-integer": "9" * 129,
            "huge-float": "1e100",
        }
        for label, token in invalid_numbers.items():
            with self.subTest(label=label):
                payload = source.replace(needle, f'"nearMissBytes": {token}')
                with self.staged_text(f"{label}.json", payload) as oracle:
                    with self.assertRaises(ScoringError):
                        load_function_oracle(oracle)

        payload = source.replace(needle, '"nearMissBytes": 4.0')
        with self.staged_text("float.json", payload) as oracle:
            with self.assertRaisesRegex(ScoringError, "must be an integer"):
                load_function_oracle(oracle)

        with patch.object(
            function_scorer.json,
            "loads",
            side_effect=ValueError("synthetic decoder failure"),
        ):
            with self.assertRaisesRegex(ScoringError, "invalid bounded JSON value"):
                load_function_oracle(ORACLE)

        with patch.object(
            function_scorer.json,
            "loads",
            side_effect=MemoryError("synthetic exhaustion"),
        ):
            with self.assertRaisesRegex(ScoringError, "not enough memory"):
                load_function_oracle(ORACLE)

        with patch.object(
            function_scorer.json.JSONEncoder,
            "iterencode",
            side_effect=MemoryError("synthetic exhaustion"),
        ):
            with self.assertRaisesRegex(ScoringError, "not enough memory"):
                report_json_bytes(score_fixture())

    def test_model_strings_use_payload_bound_without_weakening_identifier_bounds(self) -> None:
        def bounded_long_string(data: dict[str, Any]) -> None:
            data["functions"][0]["strings"] = ["x" * 5000]

        with self.staged_json(RICH_MODEL, bounded_long_string) as rich:
            boundaries = score_fixture(rich_model=rich)["twins"]["rich"][
                "boundaries"
            ]
            self.assertEqual(5, boundaries["referenceCount"])

        for field in ("calls", "referencedGlobals"):
            with self.subTest(field=field):
                def oversized_identifier(
                    data: dict[str, Any],
                    field: str = field,
                ) -> None:
                    data["functions"][0][field] = ["x" * 4097]

                with self.staged_json(RICH_MODEL, oversized_identifier) as rich:
                    with self.assertRaisesRegex(
                        ScoringError,
                        "at most 4096 characters",
                    ):
                        score_fixture(rich_model=rich)

        def oversized_string(data: dict[str, Any]) -> None:
            data["functions"][0]["strings"] = [
                "x" * (function_scorer.MAX_TEXT_CHARACTERS + 1)
            ]

        with self.staged_json(RICH_MODEL, oversized_string) as rich:
            with self.assertRaisesRegex(
                ScoringError,
                f"at most {function_scorer.MAX_TEXT_CHARACTERS} characters",
            ):
                score_fixture(rich_model=rich)

    def test_json_string_projection_matches_canonical_encoder_edges(self) -> None:
        samples = (
            "",
            "plain/ascii",
            'quote"slash\\',
            "\x00\b\f\n\r\t\x1f",
            "é\u2028",
            "💩",
            "\ud800",
        )
        for value in samples:
            with self.subTest(value=ascii(value)):
                expected = len(json.dumps(value, ensure_ascii=True).encode("ascii"))
                self.assertEqual(
                    expected,
                    function_scorer._json_string_encoded_size(value),
                )

    def test_unchecked_core_api_cannot_emit_production_status(self) -> None:
        oracle = load_function_oracle(ORACLE)
        production_claim = replace(
            oracle,
            scope="production",
            artifact_manifest_sha256="a" * 64,
        )
        recovered = {
            "rich": load_program_model(
                RICH_MODEL,
                twin="rich",
                artifact=oracle.artifacts["rich"],
                model_image_base=RICH_MODEL_IMAGE_BASE,
            ),
            "stripped": load_program_model(
                STRIPPED_MODEL,
                twin="stripped",
                artifact=oracle.artifacts["stripped"],
                model_image_base=STRIPPED_MODEL_IMAGE_BASE,
            ),
        }

        with self.assertRaisesRegex(
            ScoringError,
            "unchecked in-memory scoring cannot emit a production report",
        ):
            score_function_recovery(production_claim, recovered)

        self.assertEqual(
            "oracle.function_recovery",
            _minimum_cost_near_assignment.__module__,
        )
        self.assertEqual(
            "oracle.gcc.score_function_recovery",
            score_files.__module__,
        )

    def test_model_hash_and_normalized_start_uniqueness_are_enforced(self) -> None:
        def wrong_hash(data: dict[str, Any]) -> None:
            data["inputSha256"] = "f" * 64

        with self.staged_json(RICH_MODEL, wrong_hash) as rich:
            with self.assertRaisesRegex(ScoringError, "input SHA-256 does not match"):
                score_fixture(rich_model=rich)

        def duplicate_start(data: dict[str, Any]) -> None:
            duplicate = copy.deepcopy(data["functions"][0])
            duplicate["id"] = "duplicate-recovery"
            data["functions"].append(duplicate)

        with self.staged_json(RICH_MODEL, duplicate_start) as rich:
            with self.assertRaisesRegex(ScoringError, "normalize to RVA"):
                score_fixture(rich_model=rich)

    def test_formats_are_closed_and_expose_ratio_denominators(self) -> None:
        oracle_schema = json.loads(ORACLE_SCHEMA.read_text(encoding="utf-8"))
        score_schema = json.loads(SCORE_SCHEMA.read_text(encoding="utf-8"))
        oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
        report = score_fixture()

        self.assertFalse(oracle_schema["additionalProperties"])
        self.assertFalse(score_schema["additionalProperties"])
        self.assertEqual(set(oracle), set(oracle_schema["required"]))
        self.assertEqual(set(report), set(score_schema["required"]))
        self.assertEqual(
            {"numerator", "denominator", "value"},
            set(score_schema["$defs"]["ratio"]["required"]),
        )
        validate_json_schema(oracle_schema, oracle)
        validate_json_schema(score_schema, report)

        invalid_oracle = copy.deepcopy(oracle)
        invalid_oracle["functions"][0]["aliases"][0]["availability"][
            "stripped"
        ] = "unknown"
        with self.assertRaises(AssertionError):
            validate_json_schema(oracle_schema, invalid_oracle)

        invalid_report = copy.deepcopy(report)
        invalid_report["unexpected"] = True
        with self.assertRaises(AssertionError):
            validate_json_schema(score_schema, invalid_report)

        invalid_report = copy.deepcopy(report)
        invalid_report["twins"]["rich"]["artifact"][
            "modelImageBaseEvidence"
        ] = "inferred"
        with self.assertRaises(AssertionError):
            validate_json_schema(score_schema, invalid_report)

        boolean_version = copy.deepcopy(oracle)
        boolean_version["schemaVersion"] = True
        with self.assertRaises(AssertionError):
            validate_json_schema(oracle_schema, boolean_version)

        oversized_address = copy.deepcopy(oracle)
        oversized_address["functions"][0]["rva"] = "0x10000000000000000"
        with self.assertRaises(AssertionError):
            validate_json_schema(oracle_schema, oversized_address)

        mismatched_fixture_manifest = copy.deepcopy(oracle)
        mismatched_fixture_manifest["oracle"]["artifactManifestSha256"] = "a" * 64
        with self.assertRaises(AssertionError):
            validate_json_schema(oracle_schema, mismatched_fixture_manifest)

        mixed_verification = copy.deepcopy(report)
        mixed_verification["oracle"]["verification"][
            "artifactManifestVerified"
        ] = True
        with self.assertRaises(AssertionError):
            validate_json_schema(score_schema, mixed_verification)

    def test_oracle_must_retain_both_dwarf_and_symbol_evidence(self) -> None:
        def discard_symbols(data: dict[str, Any]) -> None:
            for function in data["functions"]:
                for alias in function["aliases"]:
                    alias["evidence"] = [
                        evidence
                        for evidence in alias["evidence"]
                        if evidence["kind"] != "elf-symbol"
                    ]
                    if not alias["evidence"]:
                        alias["evidence"] = [
                            {
                                "kind": "dwarf-subprogram",
                                "locator": f"fixture:{function['id']}:{alias['name']}",
                            }
                        ]

        with self.staged_json(ORACLE, discard_symbols) as oracle:
            with self.assertRaisesRegex(ScoringError, "both DWARF.*ELF symbol"):
                load_function_oracle(oracle)

    def test_input_entity_matching_and_report_limits_fail_closed(self) -> None:
        with patch.object(function_scorer, "MAX_JSON_INPUT_BYTES", 16):
            with self.assertRaisesRegex(ScoringError, "16-byte input limit"):
                load_function_oracle(ORACLE)

        with patch.object(function_scorer, "MAX_FUNCTION_RECORDS", 1):
            with self.assertRaisesRegex(ScoringError, "limit of 1 entries"):
                load_function_oracle(ORACLE)

        with patch.object(function_scorer, "MAX_ALIASES_PER_FUNCTION", 1):
            with self.assertRaisesRegex(ScoringError, "limit of 1 entries"):
                load_function_oracle(ORACLE)

        with patch.object(function_scorer, "MAX_EVIDENCE_PER_ALIAS", 1):
            with self.assertRaisesRegex(ScoringError, "limit of 1 entries"):
                load_function_oracle(ORACLE)

        oracle = [self.oracle_function("oracle", 2, "target")]
        recovered = [self.recovered_function("recovered", 1, "target")]
        with patch.object(function_scorer, "MAX_MATCHING_CELLS", 3):
            with self.assertRaisesRegex(ScoringError, "3-cell computation limit"):
                _minimum_cost_near_assignment(oracle, recovered, 1)

        tied_recovered = [
            self.recovered_function("lower", 1, "target"),
            self.recovered_function("upper", 3, "target"),
        ]
        with patch.object(function_scorer, "MAX_AMBIGUITY_EDGES", 1):
            with self.assertRaisesRegex(ScoringError, "1-edge report limit"):
                _minimum_cost_near_assignment(oracle, tied_recovered, 1)

        completed_report = score_fixture()
        with patch.object(function_scorer, "MAX_REPORT_BYTES", 16), patch.object(
            function_scorer,
            "_score_twin",
            side_effect=AssertionError("detail construction should not start"),
        ):
            with self.assertRaisesRegex(ScoringError, "16-byte output limit"):
                score_fixture()
        with patch.object(function_scorer, "MAX_REPORT_BYTES", 16):
            with self.assertRaisesRegex(ScoringError, "16-byte output limit"):
                report_json_bytes(completed_report)

    def test_production_scope_cannot_run_without_verified_artifact_manifest(self) -> None:
        def claim_production(data: dict[str, Any]) -> None:
            data["scope"] = "production"
            data["oracle"]["artifactManifestSha256"] = "a" * 64

        with self.staged_json(ORACLE, claim_production) as oracle:
            with self.assertRaisesRegex(
                ScoringError,
                "production scoring requires.*artifact-manifest",
            ):
                score_fixture(oracle)

    def test_production_manifest_binding_and_snapshot_are_verified_end_to_end(self) -> None:
        # The transient ELF pair is an arbitrary C program.  It proves the
        # benchmark adapter and manifest gate without making a GCC-quality claim.
        from oracle.gcc.verify_oracle_artifacts import create_oracle_manifest
        from tests.oracle.test_gcc_oracle_artifacts import GccOracleArtifactTest

        try:
            GccOracleArtifactTest.setUpClass()
        except unittest.SkipTest as error:
            self.skipTest(str(error))
        helper = GccOracleArtifactTest(
            "test_manifest_round_trip_proves_code_identity_and_metadata_removal"
        )
        try:
            with tempfile.TemporaryDirectory(
                prefix="function-score-production-manifest-"
            ) as temporary:
                directory = Path(temporary)
                source_lock = directory / "source-lock.json"
                shutil.copyfile(
                    REPOSITORY_ROOT / "oracle/gcc/16.2.0/source-lock.json",
                    source_lock,
                )
                for evidence_directory in ("keys", "tag"):
                    shutil.copytree(
                        REPOSITORY_ROOT
                        / "oracle/gcc/16.2.0"
                        / evidence_directory,
                        directory / evidence_directory,
                    )
                artifacts = directory / "artifacts"
                artifacts.mkdir()
                shutil.copyfile(
                    helper.full_fixture,
                    artifacts / "gcc-driver.full",
                )
                shutil.copyfile(
                    helper.stripped_fixture,
                    artifacts / "gcc-driver.stripped",
                )
                build_record = directory / "build-record.json"
                build_record.write_text(
                    json.dumps(
                        helper.build_record(source_lock),
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                manifest_path = directory / "oracle-manifest.json"
                manifest = create_oracle_manifest(
                    manifest_path,
                    source_lock,
                    build_record,
                )
                rich_metadata = _artifact_metadata_from_manifest(manifest, "rich")
                stripped_metadata = _artifact_metadata_from_manifest(
                    manifest,
                    "stripped",
                )
                executable = next(
                    (
                        item
                        for item in rich_metadata.executable_ranges
                        if item.end_exclusive - item.start >= 64
                    ),
                    None,
                )
                if executable is None:
                    self.skipTest("transient ELF has no 64-byte executable range")
                anchor = executable.start

                oracle_rvas = {
                    0x10: anchor + 4,
                    0x20: anchor + 12,
                    0x30: anchor + 20,
                    0x40: anchor + 28,
                    0x50: anchor + 36,
                    0x60: anchor + 44,
                }
                rich_rvas = {
                    0x10: anchor + 4,
                    0x22: anchor + 14,
                    0x40: anchor + 28,
                    0x50: anchor + 36,
                    0x60: anchor + 44,
                    0x80: anchor + 52,
                }
                stripped_rvas = {
                    0x10: anchor + 4,
                    0x20: anchor + 12,
                    0x2D: anchor + 17,
                    0x50: anchor + 36,
                    0x60: anchor + 44,
                    0x90: anchor + 52,
                }

                oracle_data = copy.deepcopy(
                    json.loads(ORACLE.read_text(encoding="utf-8"))
                )
                oracle_data["scope"] = "production"
                oracle_data["oracle"]["id"] = manifest["oracle"]["id"]
                oracle_data["oracle"]["artifactManifestSha256"] = hashlib.sha256(
                    manifest_path.read_bytes()
                ).hexdigest()
                for twin, metadata in (
                    ("rich", rich_metadata),
                    ("stripped", stripped_metadata),
                ):
                    oracle_data["artifacts"][twin] = {
                        "inputSha256": metadata.input_sha256,
                        "elfType": metadata.elf_type,
                        "elfImageBase": hex(metadata.elf_image_base),
                        "executableRvaRanges": [
                            {
                                "start": hex(item.start),
                                "endExclusive": hex(item.end_exclusive),
                            }
                            for item in metadata.executable_ranges
                        ],
                    }
                for function in oracle_data["functions"]:
                    if function["rva"] is not None:
                        function["rva"] = hex(
                            oracle_rvas[int(function["rva"], 16)]
                        )

                def production_model(
                    fixture: Path,
                    fixture_base: int,
                    model_base: int,
                    input_sha256: str,
                    rvas: dict[int, int],
                ) -> dict[str, Any]:
                    model = copy.deepcopy(
                        json.loads(fixture.read_text(encoding="utf-8"))
                    )
                    model["inputSha256"] = input_sha256
                    for function in model["functions"]:
                        old_rva = int(function["address"], 16) - fixture_base
                        function["address"] = hex(model_base + rvas[old_rva])
                    return model

                rich_model_base = rich_metadata.elf_image_base
                stripped_model_base = stripped_metadata.elf_image_base
                rich_data = production_model(
                    RICH_MODEL,
                    RICH_MODEL_IMAGE_BASE,
                    rich_model_base,
                    rich_metadata.input_sha256,
                    rich_rvas,
                )
                stripped_data = production_model(
                    STRIPPED_MODEL,
                    STRIPPED_MODEL_IMAGE_BASE,
                    stripped_model_base,
                    stripped_metadata.input_sha256,
                    stripped_rvas,
                )
                production_oracle = manifest_path.parent / "function-oracle.json"
                rich_model = manifest_path.parent / "rich-model.json"
                stripped_model = manifest_path.parent / "stripped-model.json"
                production_oracle.write_text(
                    json.dumps(oracle_data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                rich_model.write_text(
                    json.dumps(rich_data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                stripped_model.write_text(
                    json.dumps(stripped_data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

                def score_production(oracle_path: Path = production_oracle) -> dict[str, Any]:
                    return score_files(
                        oracle_path,
                        rich_model,
                        stripped_model,
                        rich_model_image_base=rich_model_base,
                        stripped_model_image_base=stripped_model_base,
                        artifact_manifest_path=manifest_path,
                    )

                report = score_production()
                self.assertEqual("production", report["oracle"]["scope"])
                self.assertEqual(
                    {
                        "status": "artifact-verified-model-unattested",
                        "artifactManifestVerified": True,
                        "programModelProvenance": "unattested-schema-v1",
                        "productionVerified": False,
                    },
                    report["oracle"]["verification"],
                )
                self.assertEqual(
                    "matches-manifest-elf-image-base",
                    report["twins"]["rich"]["artifact"][
                        "modelImageBaseValidation"
                    ],
                )

                manifest_limit = manifest_path.stat().st_size - 1
                with patch.object(
                    gcc_adapter,
                    "MAX_MANIFEST_BYTES",
                    manifest_limit,
                ):
                    with self.assertRaisesRegex(
                        ScoringError,
                        f"{manifest_limit}-byte input limit",
                    ):
                        score_production()

                supporting_limit = source_lock.stat().st_size - 1
                with patch.object(
                    gcc_adapter,
                    "MAX_SUPPORTING_INPUT_BYTES",
                    supporting_limit,
                ):
                    with self.assertRaises(ScoringError):
                        score_production()

                artifact_limit = (
                    artifacts.joinpath("gcc-driver.full").stat().st_size - 1
                )
                with patch.object(
                    gcc_adapter,
                    "MAX_ARTIFACT_BYTES",
                    artifact_limit,
                ):
                    with self.assertRaises(ScoringError):
                        score_production()

                with self.assertRaisesRegex(
                    ScoringError,
                    "must equal the manifest-validated ELF image base",
                ):
                    score_files(
                        production_oracle,
                        rich_model,
                        stripped_model,
                        rich_model_image_base=rich_model_base + 1,
                        stripped_model_image_base=stripped_model_base,
                        artifact_manifest_path=manifest_path,
                    )

                wrong_manifest_hash = copy.deepcopy(oracle_data)
                wrong_manifest_hash["oracle"]["artifactManifestSha256"] = "0" * 64
                wrong_hash_oracle = manifest_path.parent / "wrong-hash-oracle.json"
                wrong_hash_oracle.write_text(
                    json.dumps(wrong_manifest_hash, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ScoringError,
                    "manifest SHA-256 does not match",
                ):
                    score_production(wrong_hash_oracle)

                wrong_identity = copy.deepcopy(oracle_data)
                wrong_identity["oracle"]["id"] += "-other"
                wrong_identity_oracle = manifest_path.parent / "wrong-id-oracle.json"
                wrong_identity_oracle.write_text(
                    json.dumps(wrong_identity, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ScoringError,
                    "id does not match the artifact manifest oracle id",
                ):
                    score_production(wrong_identity_oracle)

                wrong_metadata = copy.deepcopy(oracle_data)
                for twin in ("rich", "stripped"):
                    wrong_metadata["artifacts"][twin]["elfImageBase"] = hex(
                        int(
                            wrong_metadata["artifacts"][twin]["elfImageBase"],
                            16,
                        )
                        + 1
                    )
                wrong_metadata_oracle = manifest_path.parent / "wrong-metadata-oracle.json"
                wrong_metadata_oracle.write_text(
                    json.dumps(wrong_metadata, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ScoringError,
                    "ELF image base does not match artifact manifest",
                ):
                    score_production(wrong_metadata_oracle)

                original_snapshot_reader = gcc_adapter._read_regular_snapshot

                def replace_manifest_after_snapshot(
                    path: Path,
                    label: str,
                    maximum_bytes: int,
                ) -> bytes | bytearray:
                    payload = original_snapshot_reader(path, label, maximum_bytes)
                    if label == "artifact manifest":
                        replacement = path.with_name(f".{path.name}.replacement")
                        replacement.write_text("{}\n", encoding="utf-8")
                        replacement.replace(path)
                    return payload

                with patch.object(
                    gcc_adapter,
                    "_read_regular_snapshot",
                    side_effect=replace_manifest_after_snapshot,
                ):
                    snapshot_report = score_production()
                self.assertEqual("production", snapshot_report["oracle"]["scope"])
                self.assertFalse(
                    snapshot_report["oracle"]["verification"]["productionVerified"]
                )
        finally:
            GccOracleArtifactTest.tearDownClass()

    def test_cli_requires_both_explicit_model_image_bases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="function-score-cli-base-") as temporary:
            output = Path(temporary) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCORER),
                    "--oracle",
                    str(ORACLE),
                    "--rich-model",
                    str(RICH_MODEL),
                    "--stripped-model",
                    str(STRIPPED_MODEL),
                    "--json-output",
                    str(output),
                ],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("--rich-model-image-base", result.stderr)
        self.assertIn("--stripped-model-image-base", result.stderr)
        self.assertFalse(output.exists())

    def test_one_command_emits_stable_json_and_concise_human_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="function-score-cli-") as temporary:
            directory = Path(temporary)
            first = directory / "first.json"
            second = directory / "second.json"

            def invoke(output: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        str(SCORER),
                        "--oracle",
                        str(ORACLE),
                        "--rich-model",
                        str(RICH_MODEL),
                        "--rich-model-image-base",
                        "0x400000",
                        "--stripped-model",
                        str(STRIPPED_MODEL),
                        "--stripped-model-image-base",
                        "0x500000",
                        "--json-output",
                        str(output),
                    ],
                    cwd=REPOSITORY_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            first_run = invoke(first)
            second_run = invoke(second)

            self.assertEqual(0, first_run.returncode, first_run.stderr)
            self.assertEqual(0, second_run.returncode, second_run.stderr)
            self.assertEqual(b"", first_run.stderr.encode())
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertIn(
                "[FIXTURE; FIXTURE-NON-PRODUCTION] function recovery",
                first_run.stdout,
            )
            self.assertIn("rich: boundary P 4/5=0.8000", first_run.stdout)
            self.assertIn("stripped: names overall 2/5=0.4000", first_run.stdout)
            self.assertEqual(7, len(first_run.stdout.splitlines()))

    def test_cli_failure_is_concise_and_does_not_write_a_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="function-score-cli-error-") as temporary:
            output = Path(temporary) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCORER),
                    "--oracle",
                    str(ORACLE),
                    "--rich-model",
                    str(STRIPPED_MODEL),
                    "--rich-model-image-base",
                    "0x400000",
                    "--stripped-model",
                    str(STRIPPED_MODEL),
                    "--stripped-model-image-base",
                    "0x500000",
                    "--json-output",
                    str(output),
                ],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(1, result.returncode)
            self.assertEqual("", result.stdout)
            self.assertIn("scoring failed: rich program model input SHA-256", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
