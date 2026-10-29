#!/usr/bin/env python3
"""Authored reconciler controls; no compiler, JVM, provider or hosted execution."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hosted_case_reconciler", ROOT / "scripts/reconcile-module-compilation-hosted-cases.py"
)
RECONCILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECONCILER)

SOURCE = {
    "commit": "a" * 40,
    "treeSha1": "b" * 40,
    "files": [{"path": "scripts/x.py", "bytes": 1, "sha256": "c" * 64}],
}
RUN_ID = "987654321"
RUN_ATTEMPT = "2"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class HostedCaseReconcilerControls(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / "build/task-tmp/hosted-case-reconciler-tests"
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source_patch = patch.object(RECONCILER, "source_identity", return_value=copy.deepcopy(SOURCE))
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        self.environment_patch = patch.dict(os.environ, {
            "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        })
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)
        self.sequence = 0
        self.create_fixture()

    def create_fixture(self):
        self.sequence += 1
        self.fixture = self.root / f"fixture-{self.sequence}"
        self.fixture.mkdir()
        self.directory = self.fixture / "cases"
        self.inventory = self.fixture / "compiled-live-tests.json"
        self.reports = self.fixture / "reports"
        self.reports.mkdir()
        self.index = RECONCILER.initialize(self.directory, RUN_ID, RUN_ATTEMPT)
        self.expected = copy.deepcopy(list(RECONCILER.EXPECTED_CASES))
        self.records = {}
        for expected in self.expected:
            case_dir = self.directory / expected["caseId"]
            case_dir.mkdir()
            payload = ("authored evidence for " + expected["caseId"] + "\n").encode()
            (case_dir / "evidence.bin").write_bytes(payload)
            self.records[expected["caseId"]] = {
                "schemaVersion": 1,
                "provider": "contained-module-hosted-case-v1",
                **expected,
                "status": "passed",
                "stage": "verified",
                "artifacts": [{"path": "evidence.bin", "bytes": len(payload), "sha256": digest(payload)}],
                "failure": None,
            }
            self.write_record(expected["caseId"])
        pairs = sorted({(row["testClass"], row["testMethod"]) for row in self.expected})
        pairs.append(("decompengine.project.UnrelatedHostedControl", "unrelated compiled live control"))
        self.inventory_value = {
            "schemaVersion": 1,
            "provider": "contained-module-compilation-test-inventory-v1",
            "classes": sorted({name for name, _ in pairs}),
            "testCount": len(pairs),
            "tests": [{"class": name, "method": method, "reportName": method + "()"}
                      for name, method in pairs],
        }
        self.write_inventory()
        self.write_reports()

    def write_record(self, case_id):
        path = self.directory / case_id / "case.json"
        path.write_bytes(RECONCILER.canonical(self.records[case_id]))
        return path

    def write_inventory(self):
        self.inventory.write_bytes(RECONCILER.canonical(self.inventory_value))

    def write_reports(self):
        for name in self.inventory_value["classes"]:
            methods = [row["method"] for row in self.inventory_value["tests"] if row["class"] == name]
            suite = ET.Element("testsuite", {
                "name": name, "tests": str(len(methods)), "failures": "0", "errors": "0", "skipped": "0",
            })
            for method in methods:
                ET.SubElement(suite, "testcase", {"classname": name, "name": method + "()", "time": "0.001"})
            ET.SubElement(suite, "system-out").text = "authored XML control"
            ET.SubElement(suite, "system-err")
            ET.ElementTree(suite).write(self.report_path(name), encoding="utf-8", xml_declaration=True)

    def report_path(self, name=None):
        return self.reports / f"TEST-{name or self.expected[0]['testClass']}.xml"

    def finalize(self, exit_code=0, phase="complete"):
        return RECONCILER.finalize(self.directory, self.inventory, self.reports, exit_code, phase)

    def case_summary(self, summary, case_id):
        return next(row for row in summary["cases"] if row["expected"]["caseId"] == case_id)

    def assert_incomplete(self, summary, case_id=None):
        self.assertEqual("incomplete", summary["status"])
        self.assertEqual(13, len(summary["cases"]))
        if case_id is not None:
            row = self.case_summary(summary, case_id)
            self.assertNotEqual("passed", row["reconciliationStatus"])
        self.assertEqual(summary, json.loads((self.directory / "case-summary.json").read_bytes()))

    def run_cli(self, exit_code="0", phase="complete"):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = RECONCILER.main([
                "finalize", "--directory", str(self.directory), "--inventory", str(self.inventory),
                "--reports", str(self.reports), "--gradle-exit-code", exit_code, "--phase", phase,
            ])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_expected_universe_has_thirteen_cells_eight_methods_and_exact_provenance(self):
        self.assertEqual(13, len(self.expected))
        self.assertEqual(13, len({row["caseId"] for row in self.expected}))
        self.assertEqual(8, len({(row["testClass"], row["testMethod"]) for row in self.expected}))
        self.assertEqual(10, sum(row["profileId"] is not None for row in self.expected))
        self.assertEqual(3, sum(row["profileId"] is None for row in self.expected))
        self.assertEqual(SOURCE, self.index["source"])
        self.assertEqual({"id": RUN_ID, "attempt": 2}, self.index["run"])
        self.assertEqual(self.expected, self.index["cases"])
        self.assertEqual(self.index, json.loads((self.directory / "expected-case-index.json").read_bytes()))

    def test_complete_raw_cells_and_exact_xml_allow_one_fresh_summary(self):
        index_bytes = (self.directory / "expected-case-index.json").read_bytes()
        summary = self.finalize()
        self.assertEqual("passed", summary["status"])
        self.assertEqual(0, summary["gradleExitCode"])
        self.assertEqual(SOURCE, summary["source"])
        self.assertEqual({"id": RUN_ID, "attempt": 2}, summary["run"])
        self.assertEqual(digest(index_bytes), summary["expectedIndexSha256"])
        self.assertEqual([], summary["errors"])
        self.assertEqual(13, len(summary["cases"]))
        for expected in self.expected:
            row = self.case_summary(summary, expected["caseId"])
            self.assertEqual("passed", row["recordStatus"])
            self.assertEqual("passed", row["reconciliationStatus"])
            self.assertEqual(self.records[expected["caseId"]], row["record"])
            self.assertEqual(digest((self.directory / expected["caseId"] / "case.json").read_bytes()),
                             row["recordSha256"])
            self.assertEqual(1, len(row["verifiedArtifacts"]))
            self.assertEqual([], row["errors"])
        output = self.directory / "case-summary.json"
        before = output.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.finalize()
        self.assertEqual(before, output.read_bytes())

    def test_initialize_cli_is_fresh_and_requires_the_current_actions_identity(self):
        destination = self.fixture / "fresh-index"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = RECONCILER.main([
                "initialize", "--directory", str(destination), "--run-id", RUN_ID,
                "--run-attempt", RUN_ATTEMPT,
            ])
        self.assertEqual(0, code)
        self.assertEqual({"expected-case-index.json"}, {path.name for path in destination.iterdir()})
        before = (destination / "expected-case-index.json").read_bytes()
        with self.assertRaises((ValueError, OSError)):
            RECONCILER.initialize(destination, RUN_ID, RUN_ATTEMPT)
        self.assertEqual(before, (destination / "expected-case-index.json").read_bytes())
        mismatch = self.fixture / "wrong-run"
        with self.assertRaises(ValueError):
            RECONCILER.initialize(mismatch, "111", RUN_ATTEMPT)
        self.assertFalse(mismatch.exists())

    def test_current_run_requires_bounded_positive_decimal_environment(self):
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            for value in (None, "", "0", "-1", "1.0", "01", "true", "9" * 30):
                with self.subTest(key=key, value=value), patch.dict(os.environ):
                    if value is None: os.environ.pop(key, None)
                    else: os.environ[key] = value
                    with self.assertRaises(ValueError):
                        RECONCILER.current_run()

    def test_partial_run_preserves_missing_running_failed_and_completed_raw_evidence(self):
        missing, running, failed, passed = [row["caseId"] for row in self.expected[:4]]
        (self.directory / missing / "case.json").unlink()
        self.records[running].update(status="running", stage="worker-started")
        self.write_record(running)
        self.records[failed].update(status="failed", stage="worker-failed",
                                    failure={"type": "java.lang.IllegalStateException", "message": "authored refusal"})
        self.write_record(failed)
        summary = self.finalize(1, "live-gradle")
        self.assert_incomplete(summary)
        for case_id, record_status, status in ((missing, None, "incomplete"),
                                               (running, "running", "incomplete"),
                                               (failed, "failed", "failed"),
                                               (passed, "passed", "passed")):
            row = self.case_summary(summary, case_id)
            self.assertEqual(record_status, row["recordStatus"])
            self.assertEqual(status, row["reconciliationStatus"])
            if case_id != missing:
                self.assertEqual(self.records[case_id], row["record"])
                self.assertEqual(1, len(row["verifiedArtifacts"]))
        self.assertEqual("authored refusal", self.case_summary(summary, failed)["record"]["failure"]["message"])

    def test_absent_case_directory_is_retained_as_not_started(self):
        case_id = self.expected[0]["caseId"]
        case_dir = self.directory / case_id
        for member in case_dir.iterdir():
            member.unlink()
        case_dir.rmdir()
        summary = self.finalize()
        self.assert_incomplete(summary, case_id)
        self.assertEqual("not-started", self.case_summary(summary, case_id)["reconciliationStatus"])

    def test_nonzero_gradle_or_not_started_cannot_pass_even_with_complete_evidence(self):
        for exit_code, phase in ((1, "live-gradle"), (137, "live-gradle"), (255, "complete"),
                                 (None, "prerequisites"), (None, "configuration")):
            with self.subTest(exit_code=exit_code, phase=phase):
                self.create_fixture()
                summary = self.finalize(exit_code, phase)
                self.assert_incomplete(summary)
                self.assertEqual(exit_code, summary["gradleExitCode"])
                self.assertEqual(phase, summary["phase"])

    def test_failed_cli_retains_summary_without_printing_success(self):
        code, stdout, _ = self.run_cli("17", "live-gradle")
        self.assertNotEqual(0, code)
        self.assertNotIn("verified", stdout.lower())
        self.assertNotIn("passed", stdout.lower())
        self.assert_incomplete(json.loads((self.directory / "case-summary.json").read_bytes()))

    def test_cli_not_started_retains_null_exit_code(self):
        code, stdout, _ = self.run_cli("not-started", "prerequisites")
        self.assertNotEqual(0, code)
        self.assertNotIn("passed", stdout.lower())
        summary = json.loads((self.directory / "case-summary.json").read_bytes())
        self.assertIsNone(summary["gradleExitCode"])
        self.assert_incomplete(summary)

    def test_stale_index_source_run_and_expected_inventory_cannot_be_rebound(self):
        def altered(index, kind):
            if kind == "commit": index["source"]["commit"] = "d" * 40
            elif kind == "tree": index["source"]["treeSha1"] = "d" * 40
            elif kind == "source-file": index["source"]["files"][0]["sha256"] = "d" * 64
            elif kind == "run": index["run"]["id"] = "111"
            elif kind == "attempt": index["run"]["attempt"] = 1
            elif kind == "duplicate": index["cases"][-1] = copy.deepcopy(index["cases"][0])
            elif kind == "missing": index["cases"].pop()
            elif kind == "extra": index["cases"].append({**index["cases"][0], "caseId": "unexpected"})
            elif kind == "method": index["cases"][0]["testMethod"] = "unrelated compiled live control"
            elif kind == "profile": index["cases"][0]["profileId"] = "other-profile"
        for kind in ("commit", "tree", "source-file", "run", "attempt", "duplicate", "missing", "extra", "method", "profile"):
            with self.subTest(kind=kind):
                self.create_fixture()
                value = copy.deepcopy(self.index)
                altered(value, kind)
                (self.directory / "expected-case-index.json").write_bytes(RECONCILER.canonical(value))
                summary = self.finalize()
                self.assert_incomplete(summary)
                self.assertTrue(summary["errors"])

    def test_changed_current_source_or_run_rejects_old_index(self):
        for kind in ("source", "run", "attempt"):
            with self.subTest(kind=kind):
                self.create_fixture()
                if kind == "source":
                    with patch.object(RECONCILER, "source_identity", return_value={**SOURCE, "commit": "d" * 40}):
                        summary = self.finalize()
                else:
                    key = "GITHUB_RUN_ID" if kind == "run" else "GITHUB_RUN_ATTEMPT"
                    with patch.dict(os.environ, {key: "999"}):
                        summary = self.finalize()
                self.assert_incomplete(summary)

    def test_strict_json_rejects_duplicates_nonfinite_overflow_surrogates_and_trailing_documents(self):
        invalid = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}',
                   b'{"x":1.5}', b'{"x":' + b'9' * 256 + b'}', b'{"x":"\\ud800"}',
                   b'{"\\udfff":1}', b'{} {}', b'{} trailing', b'\xff', b'{"x":']
        for payload in invalid:
            with self.subTest(payload=payload[:60]), self.assertRaises(ValueError):
                RECONCILER.parse_json(payload)
        self.assertEqual({"x": "valid \U0001f600", "n": 1},
                         RECONCILER.parse_json(b'{"x":"valid \\ud83d\\ude00","n":1}'))

    def test_malformed_missing_or_wrong_typed_index_still_retains_failure_summary(self):
        for payload in (None, b'{"schemaVersion":1,"schemaVersion":1}', b'{} trailing', b'[]',
                        RECONCILER.canonical({**self.index, "schemaVersion": True})):
            with self.subTest(payload=payload):
                self.create_fixture()
                path = self.directory / "expected-case-index.json"
                if payload is None: path.unlink()
                else: path.write_bytes(payload)
                summary = self.finalize()
                self.assert_incomplete(summary)
                self.assertTrue(summary["errors"])

    def test_invalid_raw_metadata_remains_unaccepted_without_hiding_other_cells(self):
        edits = [("schemaVersion", True), ("provider", "other"), ("caseId", "other-case"),
                 ("testClass", "decompengine.OtherTest"), ("testMethod", "different method"),
                 ("profileId", "unselected-profile"), ("status", "skipped"), ("status", None),
                 ("stage", "not a stage"), ("stage", "x" * 65), ("stage", "initializing"), ("extra", "field"),
                 ("failure", {"type": "Failure", "message": "passed must not claim failure"})]
        for field, value in edits:
            with self.subTest(field=field, value=value):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                self.records[case_id][field] = value
                self.write_record(case_id)
                summary = self.finalize()
                self.assert_incomplete(summary, case_id)
                self.assertTrue(self.case_summary(summary, case_id)["errors"])
                self.assertEqual("passed", self.case_summary(summary, self.expected[1]["caseId"])["reconciliationStatus"])

    def test_malformed_raw_json_is_distinct_from_an_absent_case(self):
        case_id = self.expected[0]["caseId"]
        (self.directory / case_id / "case.json").write_bytes(b'{"status":"passed","status":"failed"}')
        summary = self.finalize()
        self.assert_incomplete(summary, case_id)
        self.assertEqual("invalid", self.case_summary(summary, case_id)["reconciliationStatus"])

    def test_artifact_substitution_and_manifest_hash_size_types_reject(self):
        for kind in ("substitution", "digest", "size", "boolean-size", "float-size", "null-size"):
            with self.subTest(kind=kind):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                artifact = self.records[case_id]["artifacts"][0]
                if kind == "substitution":
                    path = self.directory / case_id / artifact["path"]
                    path.write_bytes(b"x" * path.stat().st_size)
                else:
                    field, value = {"digest": ("sha256", "d" * 64), "size": ("bytes", artifact["bytes"] + 1),
                                    "boolean-size": ("bytes", True), "float-size": ("bytes", 1.0),
                                    "null-size": ("bytes", None)}[kind]
                    artifact[field] = value
                    self.write_record(case_id)
                summary = self.finalize()
                self.assert_incomplete(summary, case_id)

    def test_artifact_inventory_rejects_missing_extra_duplicate_and_empty_success(self):
        for kind in ("missing", "extra", "duplicate", "empty", "empty-file"):
            with self.subTest(kind=kind):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                path = self.directory / case_id / "evidence.bin"
                if kind == "missing": path.unlink()
                elif kind == "extra": (path.parent / "unlisted.bin").write_bytes(b"extra")
                elif kind == "duplicate": self.records[case_id]["artifacts"] *= 2
                elif kind == "empty":
                    path.unlink()
                    self.records[case_id]["artifacts"] = []
                else:
                    path.write_bytes(b"")
                    self.records[case_id]["artifacts"] = [{"path": "evidence.bin", "bytes": 0, "sha256": digest(b"")}]
                self.write_record(case_id)
                self.assert_incomplete(self.finalize(), case_id)

    def test_artifact_paths_reject_traversal_absolute_aliases_and_control_characters(self):
        for name in ("../evidence.bin", "/evidence.bin", "./evidence.bin", "part/../evidence.bin",
                     "part//evidence.bin", "part\\evidence.bin", "evidence.bin\n", "case.json"):
            with self.subTest(name=name):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                self.records[case_id]["artifacts"][0]["path"] = name
                self.write_record(case_id)
                self.assert_incomplete(self.finalize(), case_id)

    def test_artifact_symlink_hardlink_and_fifo_are_rejected_without_following(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                path = self.directory / case_id / "evidence.bin"
                saved = self.fixture / "saved-evidence.bin"
                path.rename(saved)
                if kind == "symlink": path.symlink_to(saved)
                elif kind == "hardlink": os.link(saved, path)
                else: os.mkfifo(path)
                self.assert_incomplete(self.finalize(), case_id)

    def test_raw_record_symlink_hardlink_and_fifo_are_invalid_not_absent(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                path = self.directory / case_id / "case.json"
                saved = self.fixture / "saved-case.json"
                path.rename(saved)
                if kind == "symlink": path.symlink_to(saved)
                elif kind == "hardlink": os.link(saved, path)
                else: os.mkfifo(path)
                summary = self.finalize()
                self.assert_incomplete(summary, case_id)
                self.assertEqual("invalid", self.case_summary(summary, case_id)["reconciliationStatus"])

    def test_symlinked_case_directory_cannot_supply_another_cells_evidence(self):
        case_id = self.expected[0]["caseId"]
        path = self.directory / case_id
        saved = self.fixture / "saved-case"
        path.rename(saved)
        path.symlink_to(saved, target_is_directory=True)
        self.assert_incomplete(self.finalize(), case_id)

    def test_unknown_case_directory_cannot_be_ignored_for_success(self):
        (self.directory / "unselected-case").mkdir()
        summary = self.finalize()
        self.assert_incomplete(summary)
        self.assertTrue(summary["errors"])

    def test_excess_root_entries_still_publish_a_failure_summary(self):
        for number in range(65):
            (self.directory / f"unselected-{number}").mkdir()
        summary = self.finalize()
        self.assert_incomplete(summary)
        self.assertTrue(summary["errors"])

    def test_late_raw_replacement_after_first_reconciliation_cannot_pass(self):
        verify = RECONCILER.verify_coverage
        case_id = self.expected[0]["caseId"]

        def replacing_verifier(inventory, reports):
            result = verify(inventory, reports)
            path = self.directory / case_id / "evidence.bin"
            path.write_bytes(b"x" * path.stat().st_size)
            return result

        with patch.object(RECONCILER, "verify_coverage", side_effect=replacing_verifier):
            summary = self.finalize()
        self.assert_incomplete(summary, case_id)
        self.assertTrue(self.case_summary(summary, case_id)["errors"])

    def test_late_index_and_source_changes_are_not_hidden_by_valid_xml(self):
        verify = RECONCILER.verify_coverage
        for change in ("index", "source"):
            with self.subTest(change=change):
                self.create_fixture()
                changed = False

                def changing_verifier(inventory, reports):
                    nonlocal changed
                    result = verify(inventory, reports)
                    changed = True
                    if change == "index":
                        (self.directory / "expected-case-index.json").write_bytes(b"{}\n")
                    return result

                def changing_source():
                    return {**SOURCE, "commit": "e" * 40} if changed and change == "source" else copy.deepcopy(SOURCE)

                with patch.object(RECONCILER, "verify_coverage", side_effect=changing_verifier), \
                        patch.object(RECONCILER, "source_identity", side_effect=changing_source):
                    summary = self.finalize()
                self.assert_incomplete(summary)
                self.assertTrue(summary["errors"])

    def test_empty_unrecorded_directories_and_symlink_ancestors_fail_the_census(self):
        for kind in ("empty-directory", "symlink-parent"):
            with self.subTest(kind=kind):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                case = self.directory / case_id
                if kind == "empty-directory":
                    (case / "unrecorded").mkdir()
                else:
                    saved = self.fixture / "saved-members"
                    saved.mkdir()
                    (case / "evidence.bin").rename(saved / "evidence.bin")
                    (case / "linked").symlink_to(saved, target_is_directory=True)
                    self.records[case_id]["artifacts"][0]["path"] = "linked/evidence.bin"
                    self.write_record(case_id)
                self.assert_incomplete(self.finalize(), case_id)

    def test_path_byte_and_segment_bounds_apply_to_declared_members(self):
        for path in ("a" * 513, "/".join(["a"] * 17), "nonascii-\u00e9"):
            with self.subTest(path=path):
                self.create_fixture()
                case_id = self.expected[0]["caseId"]
                self.records[case_id]["artifacts"][0]["path"] = path
                self.write_record(case_id)
                self.assert_incomplete(self.finalize(), case_id)

    def test_member_case_and_entry_bounds_fail_with_small_authored_inputs(self):
        for constant, limit in (("MAX_MEMBER_BYTES", 1), ("MAX_CASE_BYTES", 1), ("MAX_MEMBERS", 1)):
            with self.subTest(constant=constant):
                self.create_fixture()
                if constant == "MAX_MEMBERS":
                    case_id = self.expected[0]["caseId"]
                    payload = b"second member\n"
                    (self.directory / case_id / "second.bin").write_bytes(payload)
                    self.records[case_id]["artifacts"].append({
                        "path": "second.bin", "bytes": len(payload), "sha256": digest(payload),
                    })
                    self.write_record(case_id)
                with patch.object(RECONCILER, constant, limit):
                    self.assert_incomplete(self.finalize())

    def test_json_depth_and_node_bounds_precede_large_object_acceptance(self):
        with patch.object(RECONCILER, "MAX_METADATA_BYTES", 2):
            with self.assertRaises(ValueError):
                RECONCILER.parse_json(b'{"value":1}')
        with patch.object(RECONCILER, "MAX_JSON_DEPTH", 2):
            with self.assertRaises(ValueError):
                RECONCILER.parse_json(b'{"outer":{"inner":{"value":1}}}')
        with patch.object(RECONCILER, "MAX_JSON_NODES", 3):
            with self.assertRaises(ValueError):
                RECONCILER.parse_json(b'{"values":[1,2,3,4]}')

    def test_missing_or_malformed_xml_cannot_pass_thirteen_completed_cells(self):
        for kind in ("missing", "malformed", "entity", "wrong-class", "extra-report"):
            with self.subTest(kind=kind):
                self.create_fixture()
                path = self.report_path()
                if kind == "missing": path.unlink()
                elif kind == "malformed": path.write_bytes(b'<testsuite')
                elif kind == "entity": path.write_bytes(b'<!DOCTYPE testsuite [<!ENTITY x "x">]><testsuite/>')
                elif kind == "wrong-class":
                    tree = ET.parse(path)
                    tree.getroot().set("name", "decompengine.OtherTest")
                    tree.write(path, encoding="utf-8", xml_declaration=True)
                else: (self.reports / "TEST-unexpected.xml").write_bytes(path.read_bytes())
                summary = self.finalize()
                self.assert_incomplete(summary)
                self.assertTrue(summary["errors"])

    def test_xml_failure_error_and_skip_elements_or_counters_block_success(self):
        for kind in ("failure", "error", "skipped", "failures-count", "errors-count", "skipped-count"):
            with self.subTest(kind=kind):
                self.create_fixture()
                path = self.report_path()
                tree = ET.parse(path)
                suite = tree.getroot()
                if kind.endswith("-count"): suite.set(kind.removesuffix("-count"), "1")
                else: ET.SubElement(suite.find("testcase"), kind)
                tree.write(path, encoding="utf-8", xml_declaration=True)
                self.assert_incomplete(self.finalize())

    def test_matching_xml_totals_cannot_hide_replaced_or_duplicate_methods(self):
        for kind in ("replacement", "duplicate"):
            with self.subTest(kind=kind):
                self.create_fixture()
                path = self.report_path()
                tree = ET.parse(path)
                suite = tree.getroot()
                first = suite.find("testcase")
                if kind == "replacement": first.set("name", "unselected replacement()")
                else:
                    suite.append(copy.deepcopy(first))
                    suite.set("tests", str(int(suite.get("tests")) + 1))
                tree.write(path, encoding="utf-8", xml_declaration=True)
                self.assert_incomplete(self.finalize())

    def test_unrelated_compiled_inventory_method_also_requires_exact_xml(self):
        path = self.report_path("decompengine.project.UnrelatedHostedControl")
        path.unlink()
        self.assert_incomplete(self.finalize())

    def test_inventory_and_xml_cannot_jointly_omit_an_affected_method(self):
        removed = self.inventory_value["tests"][0]
        self.inventory_value["tests"] = [row for row in self.inventory_value["tests"] if row != removed]
        self.inventory_value["testCount"] -= 1
        if not any(row["class"] == removed["class"] for row in self.inventory_value["tests"]):
            self.inventory_value["classes"].remove(removed["class"])
            self.report_path(removed["class"]).unlink()
        self.write_inventory()
        self.write_reports()
        self.assert_incomplete(self.finalize())

    def test_missing_malformed_stale_or_mistyped_inventory_preserves_failure(self):
        for kind in ("missing", "malformed", "wrong-provider", "boolean-count", "duplicate-method"):
            with self.subTest(kind=kind):
                self.create_fixture()
                if kind == "missing": self.inventory.unlink()
                elif kind == "malformed": self.inventory.write_bytes(b'{} {}')
                else:
                    if kind == "wrong-provider": self.inventory_value["provider"] = "historical-inventory"
                    elif kind == "boolean-count": self.inventory_value["testCount"] = True
                    else:
                        self.inventory_value["tests"].append(copy.deepcopy(self.inventory_value["tests"][0]))
                        self.inventory_value["testCount"] += 1
                    self.write_inventory()
                self.assert_incomplete(self.finalize())

    def test_existing_summary_symlink_and_regular_file_are_never_overwritten(self):
        for kind in ("regular", "symlink"):
            with self.subTest(kind=kind):
                self.create_fixture()
                output = self.directory / "case-summary.json"
                sentinel = self.fixture / "sentinel.json"
                sentinel.write_bytes(b"preserve this previous evidence\n")
                if kind == "regular": output.write_bytes(sentinel.read_bytes())
                else: output.symlink_to(sentinel)
                with self.assertRaises((ValueError, OSError)):
                    self.finalize()
                self.assertEqual(b"preserve this previous evidence\n", sentinel.read_bytes())
                self.assertEqual(b"preserve this previous evidence\n", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
