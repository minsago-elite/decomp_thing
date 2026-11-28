"""Bounded address projection and final JSON publication regressions."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from oracle.function_recovery import load_program_model
from oracle.gcc import report_accuracy_coverage as coverage
from oracle.gcc import report_call_edges as calls


class CallEdgeOutputBoundsTest(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[2] / "build/python-test-tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="gcc-call-bounds-", dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "model.json"

    def bound_model(self, targets):
        model = {
            "schemaVersion": 1, "inputSha256": "a" * 64, "globals": [], "types": [],
            "functions": [{
                "id": "fn_400100", "name": "caller", "address": "0x400100",
                "prototype": "", "status": "recovered", "calls": targets,
                "referencedGlobals": [], "strings": [], "decompiledC": None,
            }],
        }
        payload = json.dumps(model).encode()
        self.path.write_bytes(payload)
        record = {"path": self.path.name, "bytes": len(payload),
                  "sha256": hashlib.sha256(payload).hexdigest()}
        artifact = SimpleNamespace(input_sha256="a" * 64, executable_ranges=(
            SimpleNamespace(start=0x100, end_exclusive=0x1000),))
        # Admission and the second snapshot check run unchanged. Only the
        # independent artifact/binding handoff is synthetic in these controls.
        loaded = load_program_model(self.path, twin="stripped", artifact=artifact,
                                    model_image_base=0x400000,
                                    expected_sha256=record["sha256"], expected_bytes=len(payload))
        return SimpleNamespace(
            model=loaded, model_record=record, binding_record={}, qualification_record={},
            provenance={"artifactManifestSha256": "b" * 64},
            oracle=SimpleNamespace(functions=()),
        )

    def score(self, bound):
        with mock.patch.object(calls, "load_bound_stripped_model", return_value=bound), \
             mock.patch.object(calls, "_full_artifact", return_value=(b"fixture", "c" * 64)), \
             mock.patch.object(calls, "_oracle_edges", return_value=calls.OracleCallPopulation(
                 {}, set(), Counter(), {})):
            return calls.score_report(self.path.parent, self.path, self.path, self.path).report

    def test_unknown_addresses_are_bounded_before_conversion(self):
        for target in ("fn_" + "f" * 17, "fn_" + "f" * 4093,
                       "fn_-1", "fn_+1", "fn_0x1", "fn_1_0", "fn_FF", "fn_", "fn_ 1"):
            with self.subTest(target=target[:30]):
                bound = self.bound_model([target])
                with self.assertRaisesRegex(coverage.CoverageError, "call list is malformed"):
                    calls._recovered_edges(self.path, bound)

    def test_valid_address_limits_zero_padding_and_known_opaque_identifiers(self):
        targets = ["fn_0", "fn_0000000000000000", "fn_ffffffffffffffff", "fn_400100"]
        bound = self.bound_model(targets)
        self.assertEqual(calls._recovered_edges(self.path, bound), {
            (0x100, -0x400000), (0x100, (1 << 64) - 1 - 0x400000), (0x100, 0x100),
        })

    def test_loader_admitted_long_identifiers_cannot_bypass_scaled_output_cap(self):
        bound = self.bound_model([f"fn_{index:02x}" + "f" * 4091 for index in range(20)])
        with mock.patch.object(calls, "MAX_REPORT_BYTES", 32768):
            with self.assertRaisesRegex(coverage.CoverageError, "call list is malformed"):
                self.score(bound)

    def test_projection_charges_actual_excluded_coordinate_lengths(self):
        bound = self.bound_model([])
        huge_edges = {(0x100, (1 << 16000) + index) for index in range(20)}
        with mock.patch.object(calls, "MAX_REPORT_BYTES", 32768), \
             mock.patch.object(calls, "_recovered_edges", return_value=huge_edges):
            with self.assertRaisesRegex(coverage.CoverageError, "projected output byte limit"):
                self.score(bound)

    def test_final_writer_enforces_exact_serialized_cap_before_publication(self):
        path = Path(self.directory.name) / "report.json"
        report = {"escaped": "\u265e" * 1000}
        expected = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        with mock.patch.object(coverage, "MAX_REPORT_BYTES", len(expected)):
            coverage._write_json(path, report)
        self.assertEqual(path.read_bytes(), expected)
        for existing in (True, False):
            with self.subTest(existing=existing):
                if not existing:
                    path.unlink()
                with mock.patch.object(coverage, "MAX_REPORT_BYTES", len(expected) - 1):
                    with self.assertRaisesRegex(coverage.CoverageError, "output byte limit"):
                        coverage._write_json(path, report)
                self.assertEqual(path.exists(), existing)
                if existing:
                    self.assertEqual(path.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
