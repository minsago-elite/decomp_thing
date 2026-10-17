#!/usr/bin/env python3
"""Exercise CI routing and verify placement of retained JUnit partition reports."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


REPOSITORY = Path(__file__).resolve().parents[1]
BASE = ["--no-daemon", "verifyReconstructionNeutrality", "test"]
ISOLATED = [
    "v3BoundaryFinalStagingIsolated",
    "v3BoundaryPublicationIsolated",
    "v3BoundaryCensusIsolated",
]


def check_partition_reports(root):
    owners = {}
    partitions = {}
    inputs = []
    for role in ["core", "oracle", "live"]:
        directory = root / f"kotlin-{role}-test-reports"
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"missing or linked {role} report directory")
        outcomes = Counter()
        identities = set()
        for path in sorted(directory.rglob("*.xml")):
            if path.is_symlink():
                raise ValueError(f"linked JUnit report: {path.name}")
            raw = path.read_bytes()
            try:
                suite = ET.fromstring(raw)
            except ET.ParseError as failure:
                raise ValueError(f"malformed {role} JUnit report: {path.name}") from failure
            inputs.append({"partition": role, "path": str(path.relative_to(root)),
                           "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            for case in suite.iter("testcase"):
                classname, name = case.get("classname"), case.get("name")
                if not classname or not name:
                    raise ValueError(f"missing JUnit test identity in {role}: {path.name}")
                oracle = classname.startswith("decompengine.oracle.")
                if role == "core" and oracle:
                    raise ValueError(f"core contains oracle test: {classname}.{name}")
                if role == "oracle" and not oracle:
                    raise ValueError(f"oracle contains non-oracle test: {classname}.{name}")
                identity = (classname, name)
                if identity in owners and owners[identity] != role:
                    raise ValueError(f"test reported by more than one partition: {classname}.{name}")
                owners[identity] = role
                identities.add(identity)
                if case.find("failure") is not None or case.find("error") is not None:
                    raise ValueError(f"failed JUnit test in {role}: {classname}.{name}")
                outcomes["SKIP" if case.find("skipped") is not None else "PASS"] += 1
        if not sum(outcomes.values()):
            raise ValueError(f"no JUnit test cases in {role}")
        partitions[role] = {"executions": sum(outcomes.values()), "PASS": outcomes["PASS"],
                            "SKIP": outcomes["SKIP"], "uniqueClassMethodPairs": len(identities)}
    return {"schemaVersion": 1, "status": "passed", "partitions": partitions,
            "executions": sum(p["executions"] for p in partitions.values()),
            "uniqueClassMethodPairs": len(owners), "crossPartitionDuplicates": 0, "inputs": inputs,
            "scope": "JUnit partition placement; full original-inventory comparison remains separate"}


def report_command(arguments):
    parser = argparse.ArgumentParser(description="Check the three standard CI JUnit report artifacts")
    parser.add_argument("--check-reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)
    try:
        report = check_partition_reports(options.check_reports)
    except (ValueError, OSError) as failure:
        report = {"schemaVersion": 1, "status": "failed", "reason": str(failure)}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


BROWSER_EXPIRY_CLASS = "decompengine.web.BrowserSessionExpiryTest"
BROWSER_EXPIRY_METHOD = "expired browser session rejects private reads and accepts only an explicit fresh operator link()"


def check_browser_expiry_report(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("missing or linked browser report directory")
    path = root / f"TEST-{BROWSER_EXPIRY_CLASS}.xml"
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or linked browser expiry report")
    # Gradle also writes a small binary/ directory. Inventory the complete bounded tree,
    # allowing those regular non-XML files but never a second or hidden XML input.
    pending = [(root, 0)]
    xml_reports = []
    scanned_entries = 0
    while pending:
        directory, depth = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                scanned_entries += 1
                if scanned_entries > 128:
                    raise ValueError("browser report inventory exceeds its entry bound")
                if entry.is_symlink():
                    raise ValueError("linked browser expiry report input")
                if entry.is_dir(follow_symlinks=False):
                    if depth >= 8:
                        raise ValueError("browser report inventory exceeds its depth bound")
                    pending.append((Path(entry.path), depth + 1))
                elif not entry.is_file(follow_symlinks=False):
                    raise ValueError("nonregular browser expiry report input")
                elif entry.name.lower().endswith(".xml"):
                    xml_reports.append(Path(entry.path))
                    if len(xml_reports) > 1:
                        raise ValueError("unexpected or duplicate browser expiry XML report")
    if xml_reports != [path]:
        raise ValueError("unexpected or missing browser expiry XML report")
    with path.open("rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("browser expiry report exceeds its byte bound")
    try:
        suite = ET.fromstring(raw)
    except ET.ParseError as failure:
        raise ValueError("malformed browser expiry report") from failure
    cases = list(suite.iter("testcase"))
    names = [case.get("name") for case in cases]
    if not cases or any(case.get("classname") != BROWSER_EXPIRY_CLASS or not case.get("name") for case in cases):
        raise ValueError("missing or foreign browser expiry test identity")
    if len(set(names)) != len(names):
        raise ValueError("duplicate browser expiry test identity")
    if BROWSER_EXPIRY_METHOD not in names:
        raise ValueError("required real browser expiry case is missing")
    if any(case.find(kind) is not None for case in cases for kind in ("skipped", "failure", "error")):
        raise ValueError("browser expiry case failed or skipped")
    if suite.tag != "testsuite" or suite.get("name") != BROWSER_EXPIRY_CLASS:
        raise ValueError("browser expiry suite identity differs")
    for field, expected in (("tests", len(cases)), ("skipped", 0), ("failures", 0), ("errors", 0)):
        if suite.get(field) != str(expected):
            raise ValueError("browser expiry suite counts differ")
    return {"schemaVersion": 1, "status": "passed", "scope": "packaged browser expiry JVM selection",
            "PASS": len(cases), "SKIP": 0, "className": BROWSER_EXPIRY_CLASS,
            "xmlReports": [path.name], "scannedEntries": scanned_entries,
            "methods": sorted(names), "input": {"path": path.name, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}}


def browser_report_command(arguments):
    parser = argparse.ArgumentParser(description="Require positive real-browser expiry JUnit evidence")
    parser.add_argument("--check-browser-reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)
    try:
        report = check_browser_expiry_report(options.check_browser_reports)
    except (ValueError, OSError) as failure:
        report = {"schemaVersion": 1, "status": "failed", "reason": str(failure)}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


class CiPartitionRoutingTest(unittest.TestCase):
    def setUp(self):
        build = REPOSITORY / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="ci partition routing ", dir=build)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts/ci.sh").write_bytes((REPOSITORY / "scripts/ci.sh").read_bytes())
        (self.root / "scripts/test-repair-validation-snapshot.sh").write_bytes(
            (REPOSITORY / "scripts/test-repair-validation-snapshot.sh").read_bytes()
        )
        (self.root / "build").mkdir()
        (self.root / "bin").mkdir()
        # Exercise the real nested shell routing, with no namespaces, mounts or Gradle execution.
        unshare = self.root / "bin/unshare"
        unshare.write_text(
            '#!/usr/bin/env bash\n[[ "$1" == "-Ur" && "$2" == "-m" ]] || exit 97\n'
            'shift 2\nexec "$@"\n',
            encoding="utf-8",
        )
        unshare.chmod(0o700)
        for name in ["mount", "umount"]:
            command = self.root / "bin" / name
            command.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            command.chmod(0o700)
        gradle = self.root / "gradlew"
        gradle.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "with pathlib.Path('arguments.jsonl').open('a') as output:\n"
            "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        gradle.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, selector):
        environment = os.environ.copy()
        environment.pop("DECOMP_CI_TEST_SHARD", None)
        if selector is not None:
            environment["DECOMP_CI_TEST_SHARD"] = selector
        capture = self.root / "arguments.jsonl"
        if capture.exists():
            capture.unlink()
        result = subprocess.run(
            ["bash", str(self.root / "scripts/ci.sh")],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        invocations = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
        return result, invocations

    def assert_selection(self, selector, expected):
        result, invocations = self.invoke(selector)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([expected], invocations)

    def invoke_repair(self, selector):
        environment = os.environ.copy()
        environment.pop("DECOMP_CI_TEST_SHARD", None)
        environment.pop("DECOMP_TEST_FRONTEND_NODE_HOME", None)
        if selector is not None:
            environment["DECOMP_CI_TEST_SHARD"] = selector
        environment["GRADLE_USER_HOME"] = str(self.root / "gradle-user-home")
        environment["PATH"] = str(self.root / "bin") + os.pathsep + environment["PATH"]
        capture = self.root / "arguments.jsonl"
        if capture.exists():
            capture.unlink()
        result = subprocess.run(
            ["bash", str(self.root / "scripts/test-repair-validation-snapshot.sh"), "--ci-verify-installed-analysis-io"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        invocations = [json.loads(line) for line in capture.read_text().splitlines()] if capture.exists() else []
        return result, invocations

    def test_full_and_unset_entry_points_keep_all_isolated_checks(self):
        for selector in [None, "", "full"]:
            with self.subTest(selector=selector):
                self.assert_selection(selector, BASE + ISOLATED + ["-PisolateV3BoundaryTests=true"])

    def test_legacy_core_still_selects_the_complete_non_live_suite(self):
        self.assert_selection("core", BASE + ISOLATED + ["-PciTestShard=core", "-PisolateV3BoundaryTests=true"])

    def test_main_partition_selects_the_complement_without_isolated_oracle_tasks(self):
        self.assert_selection("core-main", BASE + ["-PciTestShard=core-main"])

    def test_oracle_partition_requires_all_three_isolated_boundary_tasks(self):
        self.assert_selection("core-oracle", BASE + ISOLATED + ["-PciTestShard=core-oracle", "-PisolateV3BoundaryTests=true"])

    def test_live_entry_point_keeps_its_original_selection(self):
        self.assert_selection("live", BASE + ["-PciTestShard=live"])

    def test_unsupported_selections_refuse_before_any_gradle_invocation(self):
        for selector in ["core-other", "../../core"]:
            with self.subTest(selector=selector):
                result, invocations = self.invoke(selector)
                self.assertEqual(2, result.returncode)
                self.assertIn("unsupported DECOMP_CI_TEST_SHARD", result.stderr)
                self.assertEqual([], invocations)

    def assert_repair_selection(self, selector, extra):
        result, invocations = self.invoke_repair(selector)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([
            [":verifyAnalysisIoHelperInstalled", ":testClasses", ":installDist", ":stageOracleNativeLibraries", "--no-daemon"],
            ["cleanTest", "test", "--tests", "decompengine.project.GeneratedCValidationSnapshotFixtureTest",
             "-x", ":buildLlvmBehaviorHelper", "-x", ":buildAnalysisIoHelper", "--no-daemon", *extra],
        ], invocations)

    def test_quota_followup_keeps_main_partition_and_host_preparation(self):
        self.assert_repair_selection("core-main", ["-PciTestShard=core-main"])

    def test_legacy_quota_followup_keeps_its_original_selection(self):
        self.assert_repair_selection(None, [])

    def test_quota_followup_refuses_nonowning_or_unknown_ci_partitions_before_gradle(self):
        for selector in ["core-oracle", "live", "bad"]:
            with self.subTest(selector=selector):
                result, invocations = self.invoke_repair(selector)
                self.assertEqual(2, result.returncode)
                self.assertIn("unsupported repair snapshot CI partition", result.stderr)
                self.assertEqual([], invocations)


class CiPartitionReportTest(unittest.TestCase):
    def setUp(self):
        build = REPOSITORY / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="ci-report-placement-", dir=build)
        self.root = Path(self.temporary.name)
        self.index = 0
        self.core = self.write("core", "decompengine.project.ExampleTest", "ordinary")
        self.oracle = self.write("oracle", "decompengine.oracle.ExampleTest", "oracle")
        self.live = self.write("live", "decompengine.acp.LiveTest", "live")

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, role, classname, name, outcome="PASS"):
        self.index += 1
        path = self.root / f"kotlin-{role}-test-reports/test-results/test/TEST-{self.index}.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        suite = ET.Element("testsuite")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if outcome != "PASS":
            ET.SubElement(case, {"SKIP": "skipped", "FAIL": "failure", "ERROR": "error"}[outcome])
        ET.ElementTree(suite).write(path, encoding="utf-8")
        return path

    def test_valid_placement_preserves_same_partition_skip_and_followup_executions(self):
        self.write("core", "decompengine.project.SnapshotTest", "quota", "SKIP")
        self.write("core", "decompengine.project.SnapshotTest", "quota")
        report = check_partition_reports(self.root)
        self.assertEqual(5, report["executions"])
        self.assertEqual(4, report["uniqueClassMethodPairs"])
        self.assertEqual(1, report["partitions"]["core"]["SKIP"])

    def test_oracle_check_leaking_into_core_is_refused(self):
        self.write("core", "decompengine.oracle.gcc.GccCompilerEnginePlanningTest", "isolated")
        with self.assertRaisesRegex(ValueError, "core contains oracle"):
            check_partition_reports(self.root)

    def test_nonoracle_check_leaking_into_oracle_is_refused(self):
        self.write("oracle", "decompengine.project.ExampleTest", "wrong partition")
        with self.assertRaisesRegex(ValueError, "oracle contains non-oracle"):
            check_partition_reports(self.root)

    def test_duplicate_across_live_and_core_is_refused(self):
        self.write("live", "decompengine.project.ExampleTest", "ordinary")
        with self.assertRaisesRegex(ValueError, "more than one partition"):
            check_partition_reports(self.root)

    def test_missing_partition_artifact_is_refused(self):
        shutil.rmtree(self.root / "kotlin-oracle-test-reports")
        with self.assertRaisesRegex(ValueError, "missing or linked oracle"):
            check_partition_reports(self.root)

    def test_empty_partition_is_refused(self):
        self.oracle.write_text("<testsuite/>", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no JUnit test cases in oracle"):
            check_partition_reports(self.root)

    def test_malformed_report_is_refused(self):
        self.core.write_text("<testsuite", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "malformed core JUnit"):
            check_partition_reports(self.root)

    def test_missing_test_identity_is_refused(self):
        self.core.write_text('<testsuite><testcase name="anonymous"/></testsuite>', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing JUnit test identity"):
            check_partition_reports(self.root)

    def test_failed_or_errored_case_is_refused(self):
        for outcome in ["FAIL", "ERROR"]:
            with self.subTest(outcome=outcome):
                path = self.write("core", "decompengine.project.ExampleTest", outcome, outcome)
                with self.assertRaisesRegex(ValueError, "failed JUnit test"):
                    check_partition_reports(self.root)
                path.unlink()

    def test_linked_report_is_refused(self):
        self.core.with_name("linked.xml").symlink_to(self.core)
        with self.assertRaisesRegex(ValueError, "linked JUnit report"):
            check_partition_reports(self.root)


class BrowserExpiryReportTest(unittest.TestCase):
    def setUp(self):
        build = REPOSITORY / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="ci browser report ", dir=build)
        self.root = Path(self.temporary.name)
        self.path = self.root / f"TEST-{BROWSER_EXPIRY_CLASS}.xml"
        self.write()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, names=None, outcome=None, classname=BROWSER_EXPIRY_CLASS):
        case_names = names if names is not None else [BROWSER_EXPIRY_METHOD, "HTTP expiry()", "cleanup()"]
        suite = ET.Element("testsuite", name=BROWSER_EXPIRY_CLASS, tests=str(len(case_names)),
                           skipped="0", failures="0", errors="0")
        for name in case_names:
            case = ET.SubElement(suite, "testcase", classname=classname, name=name)
            if outcome is not None:
                ET.SubElement(case, outcome)
        ET.ElementTree(suite).write(self.path, encoding="utf-8")

    def test_positive_browser_case_and_companions_bind_exact_report_bytes(self):
        report = check_browser_expiry_report(self.root)
        self.assertEqual(3, report["PASS"])
        self.assertEqual(0, report["SKIP"])
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), report["input"]["sha256"])
        self.assertIn(BROWSER_EXPIRY_METHOD, report["methods"])

    def test_skipped_failed_or_errored_browser_case_is_refused(self):
        for outcome in ("skipped", "failure", "error"):
            with self.subTest(outcome=outcome):
                self.write(outcome=outcome)
                with self.assertRaisesRegex(ValueError, "failed or skipped"):
                    check_browser_expiry_report(self.root)

    def test_passing_companions_cannot_replace_required_browser_journey(self):
        self.write(names=["HTTP expiry()", "cleanup()"])
        with self.assertRaisesRegex(ValueError, "required real browser expiry case is missing"):
            check_browser_expiry_report(self.root)

    def test_duplicate_browser_execution_identity_is_refused(self):
        self.write(names=[BROWSER_EXPIRY_METHOD, BROWSER_EXPIRY_METHOD])
        with self.assertRaisesRegex(ValueError, "duplicate browser expiry test identity"):
            check_browser_expiry_report(self.root)

    def test_foreign_class_with_the_same_method_cannot_satisfy_browser_evidence(self):
        self.write(classname="decompengine.web.UnrelatedTest")
        with self.assertRaisesRegex(ValueError, "foreign browser expiry test identity"):
            check_browser_expiry_report(self.root)

    def test_malformed_and_oversized_reports_are_refused(self):
        for payload, reason in [(b"<testsuite", "malformed"), (b"x" * (1024 * 1024 + 1), "byte bound")]:
            with self.subTest(reason=reason):
                self.path.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, reason):
                    check_browser_expiry_report(self.root)

    def test_missing_and_linked_reports_are_refused(self):
        self.path.unlink()
        with self.assertRaisesRegex(ValueError, "missing or linked"):
            check_browser_expiry_report(self.root)
        target = self.root / "target.xml"
        target.write_text("<testsuite/>", encoding="utf-8")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "missing or linked"):
            check_browser_expiry_report(self.root)

    def test_suite_identity_and_counts_must_match_actual_positive_cases(self):
        for field, value in (("name", "foreign"), ("tests", "4"), ("skipped", "1"),
                             ("failures", "1"), ("errors", "1"), ("tests", "03"), ("tests", None)):
            with self.subTest(field=field, value=value):
                self.write()
                suite = ET.parse(self.path).getroot()
                if value is None:
                    suite.attrib.pop(field)
                else:
                    suite.set(field, value)
                ET.ElementTree(suite).write(self.path, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "suite identity|suite counts"):
                    check_browser_expiry_report(self.root)
        self.write()
        suite = ET.parse(self.path).getroot()
        suite.tag = "testsuites"
        ET.ElementTree(suite).write(self.path, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "suite identity"):
            check_browser_expiry_report(self.root)

    def test_gradle_binary_directory_keeps_one_exact_xml_input(self):
        binary = self.root / "binary"
        binary.mkdir()
        for name in ("output.bin", "output.bin.idx", "results.bin"):
            (binary / name).write_bytes(b"synthetic fixture")
        report = check_browser_expiry_report(self.root)
        self.assertEqual([self.path.name], report["xmlReports"])
        self.assertEqual(5, report["scannedEntries"])
        self.assertEqual(3, report["PASS"])

    def test_extra_foreign_and_duplicate_sibling_or_nested_xml_reports_refuse(self):
        for relative in ("unexpected.xml", "unexpected.XML", "nested/unexpected.xml",
                         f"nested/{self.path.name}"):
            with self.subTest(relative=relative):
                extra = self.root / relative
                extra.parent.mkdir(exist_ok=True)
                extra.write_bytes(self.path.read_bytes())
                with self.assertRaisesRegex(ValueError, "unexpected or duplicate"):
                    check_browser_expiry_report(self.root)
                extra.unlink()

    def test_linked_extra_report_and_linked_report_directory_refuse(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                link = self.root / ("linked-directory" if directory else "linked.xml")
                link.symlink_to(self.root if directory else self.path, target_is_directory=directory)
                with self.assertRaisesRegex(ValueError, "linked browser expiry report input"):
                    check_browser_expiry_report(self.root)
                link.unlink()

    def test_inventory_entry_and_depth_exact_and_one_over_bounds(self):
        for index in range(127):
            (self.root / f"binary-{index}.bin").write_bytes(b"")
        self.assertEqual(128, check_browser_expiry_report(self.root)["scannedEntries"])
        extra = self.root / "one-over.bin"
        extra.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "entry bound"):
            check_browser_expiry_report(self.root)
        extra.unlink()
        for index in range(127):
            (self.root / f"binary-{index}.bin").unlink()
        nested = self.root
        for _ in range(8):
            nested = nested / "nested"
            nested.mkdir()
        self.assertEqual(9, check_browser_expiry_report(self.root)["scannedEntries"])
        (nested / "one-over").mkdir()
        with self.assertRaisesRegex(ValueError, "depth bound"):
            check_browser_expiry_report(self.root)

    def test_empty_and_unnamed_case_reports_are_refused(self):
        for names in ([], [""]):
            with self.subTest(names=names):
                self.write(names=names)
                with self.assertRaisesRegex(ValueError, "missing or foreign"):
                    check_browser_expiry_report(self.root)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check-reports":
        sys.exit(report_command(sys.argv[1:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--check-browser-reports":
        sys.exit(browser_report_command(sys.argv[1:]))
    unittest.main()
