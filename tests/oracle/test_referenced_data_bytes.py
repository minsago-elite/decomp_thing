from __future__ import annotations

import copy
import ast
import tempfile
import sys
from unittest.mock import patch
import json
import hashlib
from pathlib import Path
import unittest

from oracle.referenced_data_bytes import COLLECTION_OMISSIONS, admit_program_model_bytes, decode_program_model_bytes, validate_evidence


def evidence() -> dict:
    return {"schemaVersion": 1, "windows": [{"address": "0x2000", "requestedLength": 8,
        "origin": {"instructionAddress": "0x1000", "referenceAddress": "0x2000", "operandIndex": 0, "widthBasis": "pcode_direct_read"},
        "availability": "available", "segments": [{"offset": 0, "length": 8, "availability": "available", "hex": "000000000000e03f", "reason": None}]}], "omissionReason": None}


def evidence_v2() -> dict:
    return dict(evidence(), schemaVersion=2, collectionOmissions=[])


class ReferencedDataBytesTest(unittest.TestCase):
    def test_archival_script_model_admission_uses_active_four_nonnull_v2_and_closed_bytes(self) -> None:
        root = Path(__file__).resolve().parents[2]
        script = (root / "scripts/validate-archival-docker.sh").read_text()
        body = script.split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
        tree = ast.parse(body)
        loop = next(item for item in tree.body if isinstance(item, ast.For))
        # Execute the actual script's model-admission prefix, before archive/Docker assertions.
        stop = next(i for i, item in enumerate(loop.body) if isinstance(item, ast.For) and isinstance(item.target, ast.Name) and item.target.id == "kind")
        loop.body = loop.body[:stop]
        tree.body = tree.body[:tree.body.index(loop) + 1]
        compiled = compile(tree, "archival-model-admission", "exec")
        parent = root / "build/python-test-tmp"
        parent.mkdir(exist_ok=True, parents=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            work = Path(directory)
            for name in ("symbols-a", "stripped-a"):
                path = work / name / "analysis/reports/program_model.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"schemaVersion": 4, "globals": [{"byteEvidence": evidence_v2()}]}))
            with patch.object(sys, "argv", ["archival", str(work)]):
                exec(compiled, {})
                path = work / "symbols-a/analysis/reports/program_model.json"
                path.write_text(json.dumps({"schemaVersion": 2, "globals": []}))
                with self.assertRaises(AssertionError):
                    exec(compiled, {})
                path.write_text(json.dumps({"schemaVersion": 4, "globals": [{"byteEvidence": None}]}))
                with self.assertRaises(AssertionError):
                    exec(compiled, {})
                value = evidence_v2(); value["unchecked"] = True
                path.write_text(json.dumps({"schemaVersion": 4, "globals": [{"byteEvidence": value}]}))
                with self.assertRaises(ValueError):
                    exec(compiled, {})
                duplicate = json.dumps({"schemaVersion": 4, "globals": [{"byteEvidence": evidence_v2()}]})
                duplicate = duplicate.replace('"widthBasis": "pcode_direct_read"',
                    '"widthBasis":"guessed","widthBasis":"pcode_direct_read"')
                path.write_text(duplicate)
                with self.assertRaisesRegex(ValueError, "duplicate byte evidence field"):
                    exec(compiled, {})

    def test_recovery_population_schema_and_registered_digest_admit_only_one_through_four(self) -> None:
        import fastjsonschema
        root = Path(__file__).resolve().parents[2]
        path = root / "oracle/unassessed-recovery-population.schema.json"
        validate = fastjsonschema.compile(json.loads(path.read_bytes()))
        population = {"schemaVersion": 1, "state": "unassessed", "modelSchemaVersion": 3,
            "modelSha256": "a" * 64, "unassessedEntityIds": ["authored"], "assessedEntityIds": []}
        for version in (1, 2, 3, 4):
            validate(dict(population, modelSchemaVersion=version))
        for version in (True, 5, "4"):
            with self.assertRaises(fastjsonschema.JsonSchemaException):
                validate(dict(population, modelSchemaVersion=version))
        for mutation in ({"state": "assessed"}, {"assessedEntityIds": ["authored"]}, {"extra": True}):
            with self.assertRaises(fastjsonschema.JsonSchemaException):
                validate(dict(population, **mutation))
        inventory = json.loads((root / "oracle/kotlin-schema-inventory-v1.json").read_bytes())
        matches = [item for item in inventory["schemas"] if item["path"] == str(path.relative_to(root))]
        self.assertEqual(1, len(matches))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), matches[0]["schemaSha256"])

    def test_known_unknown_partial_and_all_width_origins(self) -> None:
        for basis in ("pcode_load", "pcode_store", "pcode_direct_read", "pcode_direct_write"):
            value = evidence()
            value["windows"][0]["origin"]["widthBasis"] = basis
            budget = [0, 0]
            validate_evidence(value, budget)
            self.assertEqual([1, 8], budget)
        value = evidence()
        window = value["windows"][0]
        window.update(requestedLength=None, availability="unknown", segments=[])
        window["origin"]["widthBasis"] = "unknown_width"
        value["omissionReason"] = "unknown_access_width"
        validate_evidence(value, [0, 0])
        value = evidence()
        window = value["windows"][0]
        window["availability"] = "partial"
        window["segments"] = [{"offset": 0, "length": 1, "availability": "available", "hex": "00", "reason": None},
            {"offset": 1, "length": 7, "availability": "unavailable", "hex": None, "reason": "unmapped"}]
        validate_evidence(value, [0, 0])

    def test_closed_fields_width_coverage_identity_and_aggregate_limits(self) -> None:
        mutations = [
            lambda v: v.update(extra=1),
            lambda v: v["windows"][0]["origin"].update(extra=1),
            lambda v: v["windows"][0].update(requestedLength=True),
            lambda v: v["windows"][0].update(requestedLength=257),
            lambda v: v["windows"][0]["origin"].update(referenceAddress="0x2001"),
            lambda v: v["windows"][0]["segments"][0].update(hex="00"),
            lambda v: v["windows"][0]["segments"][0].update(hex="000000000000E03F"),
            lambda v: v["windows"][0]["segments"][0].update(offset=1),
            lambda v: v["windows"][0].update(availability="partial"),
            lambda v: v["windows"][0]["origin"].update(widthBasis="guessed_type"),
            lambda v: v["windows"].append(copy.deepcopy(v["windows"][0])),
            lambda v: v.update(omissionReason="unknown_access_width"),
        ]
        for mutate in mutations:
            value = evidence(); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_evidence(value, [0, 0])
        for budget in ([4096, 0], [0, 65529]):
            with self.assertRaises(ValueError):
                validate_evidence(evidence(), list(budget))
        validate_evidence(evidence(), [4095, 65528])

    def test_decoded_duplicate_evidence_keys_reject_before_malformed_value(self) -> None:
        first = json.dumps(evidence())
        prefixes = [
            '{"globals":[{"byteEvidence":' + first + ',"byteEvidence":{"windows":[{"segments":[{"hex":"',
            '{"globals":[{"byteEvidence":' + first + ',"byte\\u0045vidence":{"windows":[{"segments":[{"hex":"',
            '{"globals":[],"globals":[{"byteEvidence":{"windows":[{"segments":[{"hex":"',
            '{"globals":[],"glo\\u0062als":[{"byteEvidence":{"windows":[{"segments":[{"hex":"',
            '{"globals":[{"byteEvidence":{"schemaVersion":1,"schemaVersion":"',
            '{"globals":[{"byteEvidence":{"windows":[{"address":"0x2000","address":"',
            '{"globals":[{"byteEvidence":{"windows":[{"origin":{"widthBasis":"pcode_load","widthBasis":"',
            '{"globals":[{"byteEvidence":{"windows":[{"segments":[{"hex":"00","hex":"',
            '{"globals":[{"byteEvidence":{"windows":[{"segments":[{"hex":"00","h\\u0065x":"',
        ]
        for prefix in prefixes:
            # The suffix cannot be decoded as JSON; this exact reason proves lexical
            # rejection after the decoded key and before its value, not the pairs hook.
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, "duplicate byte evidence field"):
                admit_program_model_bytes(prefix.encode() + b"x" * 1_000_000)

    def test_preallocation_bounds_reject_before_malformed_large_suffix(self) -> None:
        good = json.dumps(evidence()["windows"][0], separators=(",", ":"))
        admit_program_model_bytes(b'{"unused":' + b'[' * 31 + b'0' + b']' * 31 + b'}')
        attacks = [
            ('["', "root must be an object"),
            ('{"unused":' + '[' * 32 + '"', "nesting bound"),
            ('{"globals":[{"byteEvidence":{"windows":[' + ','.join([good] * 32) + ',{"huge":"', "window bound"),
            ('{"globals":[{"byteEvidence":{"windows":[{"segments":[' + ','.join(['{}'] * 256) + ',{"huge":"', "segment bound"),
            ('{"globals":[{"byteEvidence":{"windows":[{"requestedLength":65537,"huge":"', "requested byte bound"),
            ('{"globals":[{"byteEvidence":{"windows":[{"segments":[{"hex":"', "string bound"),
            ('{"globals":[{"byteEvidence":{"unexpected":"', "unexpected field"),
        ]
        for prefix, message in attacks:
            for bom in (b"", b"\xef\xbb\xbf"):
                with self.subTest(message=message, bom=bom), self.assertRaisesRegex(ValueError, message):
                    admit_program_model_bytes(bom + prefix.encode() + b"x" * 1_000_000)
        unknown = {"address": "0x2000", "requestedLength": None,
            "origin": {"instructionAddress": "0x1000", "referenceAddress": "0x2000", "operandIndex": None, "widthBasis": "unknown_width"},
            "availability": "unknown", "segments": []}
        prefix = '{"globals":[' + ','.join(json.dumps({"byteEvidence": {"windows": [unknown] * 32}}) for _ in range(128))
        with self.assertRaisesRegex(ValueError, "window bound"):
            admit_program_model_bytes((prefix + ',{"byteEvidence":{"windows":[{"huge":"').encode() + b'x' * 1_000_000)
        known = evidence()["windows"][0]
        known["requestedLength"] = 256
        prefix = '{"globals":[' + ','.join(json.dumps({"byteEvidence": {"windows": [known] * 32}}) for _ in range(8))
        with self.assertRaisesRegex(ValueError, "model requested byte bound"):
            admit_program_model_bytes((prefix + ',{"byteEvidence":{"windows":[{"requestedLength":1,"huge":"').encode() + b'x' * 1_000_000)
        admit_program_model_bytes(json.dumps({"schemaVersion": 3, "globals": [{"byteEvidence": evidence()}]}).encode())

    def test_v2_empty_cutoffs_local_boundary_and_unknown_width_are_distinct(self) -> None:
        for reason in COLLECTION_OMISSIONS[1:]:
            value = {"schemaVersion": 2, "windows": [], "omissionReason": None, "collectionOmissions": [reason]}
            budget = [0, 0]; validate_evidence(value, budget, schema_version=2); self.assertEqual([0, 0], budget)
        value = evidence_v2(); value["windows"] = [copy.deepcopy(value["windows"][0]) for _ in range(32)]
        for index, window in enumerate(value["windows"]): window["origin"]["instructionAddress"] = hex(0x1000 + index)
        for reasons in (["global_window_limit"], ["global_window_limit", "model_window_limit"]):
            value["collectionOmissions"] = reasons; validate_evidence(value, [0, 0], schema_version=2)
        window = value["windows"][0]; window.update(requestedLength=None, availability="unknown", segments=[])
        window["origin"]["widthBasis"] = "unknown_width"; value["omissionReason"] = "unknown_access_width"
        validate_evidence(value, [0, 0], schema_version=2)

    def test_v2_omission_shapes_order_cardinality_and_generation_pairing_refuse(self) -> None:
        cases = []
        for reasons in (["global_window_limit"], ["reference_work_limit", "global_window_limit"],
                        ["model_window_limit", "reference_work_limit"], ["reference_work_limit"] * 2,
                        ["global_window_limit", "model_window_limit", "reference_work_limit"], ["unknown"], [None], [True], "reference_work_limit"):
            value = evidence_v2(); value["collectionOmissions"] = reasons; cases.append(value)
        for reasons in ([], ["global_window_limit"]):
            value = evidence_v2(); value.update(windows=[], collectionOmissions=reasons); cases.append(value)
        value = evidence_v2(); value.update(windows=[], omissionReason="unknown_access_width", collectionOmissions=["reference_work_limit"]); cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError): validate_evidence(value, [0, 0], schema_version=2)
        with self.assertRaises(ValueError): validate_evidence(evidence(), [0, 0], schema_version=2)
        with self.assertRaises(ValueError): validate_evidence(evidence_v2(), [0, 0])
        with self.assertRaises(ValueError): validate_evidence(None, [0, 0], schema_version=2)

    def test_v2_origin_conflicts_refuse_without_widening_historical_v1(self) -> None:
        value = evidence(); other = copy.deepcopy(value["windows"][0]); other["origin"]["widthBasis"] = "pcode_store"; value["windows"].append(other)
        validate_evidence(value, [0, 0])
        value.update(schemaVersion=2, collectionOmissions=[])
        with self.assertRaisesRegex(ValueError, "duplicate/conflicting"): validate_evidence(value, [0, 0], schema_version=2)
        value["windows"][1]["origin"]["operandIndex"] = 1; validate_evidence(value, [0, 0], schema_version=2)

    def test_v2_null_lexical_dispatch_and_omission_bounds_precede_large_suffix(self) -> None:
        for version in (1, 2, 3, 4):
            value = {"globals": [{"byteEvidence": None}], "schemaVersion": version}
            self.assertEqual(value, decode_program_model_bytes(json.dumps(value).encode()))
        attacks = [
            ('{"globals":[{"byteEvidence":null,"byteEvid\\u0065nce":"', "duplicate byte evidence"),
            ('{"globals":[{"byteEvidence":"null', "object or exact null"),
            ('{"globals":[{"byteEvidence":null', "object or exact null"),
            ('{"globals":[{"byteEvidence":nul', "object or exact null"),
            ('{"globals":[{"byteEvidence":[', "object or exact null"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":["global_window_limit","model_window_limit",', "omission bound"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":[{', "scalar strings"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":[null', "scalar strings"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":["', "string bound"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":"', "must be an array"),
            ('{"globals":[{"byteEvidence":{"collectionOmissions":[],"collectionOmi\\u0073sions":"', "duplicate byte evidence"),
        ]
        for prefix, message in attacks:
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, message):
                admit_program_model_bytes(prefix.encode() + b"x" * 1_000_000)
        admit_program_model_bytes(json.dumps({"globals": [{"byteEvidence": evidence_v2()}], "schemaVersion": 4}).encode())

    def test_v2_payload_budgets_still_apply_when_collection_stopped(self) -> None:
        value = evidence_v2(); value["collectionOmissions"] = ["reference_work_limit"]
        validate_evidence(value, [4095, 65528], schema_version=2)
        for budget in ([4096, 0], [0, 65529]):
            with self.assertRaises(ValueError): validate_evidence(value, list(budget), schema_version=2)
        value["windows"][0]["requestedLength"] = 257
        with self.assertRaises(ValueError): validate_evidence(value, [0, 0], schema_version=2)
        unknown = evidence_v2(); unknown["windows"][0].update(requestedLength=None, availability="unknown", segments=[])
        unknown["windows"][0]["origin"]["widthBasis"] = "unknown_width"; unknown["omissionReason"] = "unknown_access_width"
        budget = [4095, 65536]; validate_evidence(unknown, budget, schema_version=2); self.assertEqual([4096, 65536], budget)


    def test_exporter_inventory_binds_new_schema_without_replacing_historical_twelve(self) -> None:
        root = Path(__file__).resolve().parents[2]
        value = json.loads((root / "oracle/kotlin-schema-inventory-v1.json").read_bytes())
        self.assertEqual(len(value["schemas"]), value["schemaCount"])
        self.assertEqual(sum(row["registration"] == "shared-kotlin" for row in value["schemas"]), value["sharedCatalogCount"])
        self.assertEqual(len(value["schemas"]), len({row["name"] for row in value["schemas"]}))
        for version, expected in [(12, "324aa87b637272b23a68db11b846908a9ad37088e60dde4b285a85f5b08b2171"), (13, "5b8c6b6a6a48c15be8f4966bee0466313766854f9e380a98898a9274bc554725")]:
            rows = [row for row in value["schemas"] if row["name"] == f"gcc/compiler-engines-exporter{version}"]
            self.assertEqual(1, len(rows)); row = rows[0]
            self.assertEqual("shared-kotlin", row["registration"])
            self.assertEqual(expected, row["schemaSha256"])
            self.assertEqual(expected, hashlib.sha256((root / row["path"]).read_bytes()).hexdigest())

    def test_v2_decoded_duplicate_unknown_metadata_and_extra_window_still_refuse(self) -> None:
        value = evidence_v2()
        raw = json.dumps({"globals": [{"byteEvidence": value}], "schemaVersion": 4})
        duplicate = raw.replace('"collectionOmissions": []', '"collectionOmissions":[],"collectionOmi\\u0073sions":[]')
        with self.assertRaisesRegex(ValueError, "duplicate byte evidence"): decode_program_model_bytes(duplicate.encode())
        for mutate in [lambda item: item.update(extra=True), lambda item: item["windows"][0]["origin"].update(extra=True), lambda item: item["windows"][0]["segments"][0].update(extra=True), lambda item: item["windows"][0]["origin"].update(operandIndex=-1)]:
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError): validate_evidence(changed, [0, 0], schema_version=2)
        changed = copy.deepcopy(value); changed["windows"] *= 33; changed["collectionOmissions"] = ["global_window_limit", "model_window_limit"]
        with self.assertRaises(ValueError): validate_evidence(changed, [0, 0], schema_version=2)


if __name__ == "__main__":
    unittest.main()
