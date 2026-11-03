#!/usr/bin/env python3
"""Execute the source-only Kotlin gate and bind fresh actual XML to its exact source head."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "build/gcc-signed-source-qualification"
RESULTS = ROOT / "build/test-results/gccSignedSourceQualification"
EXPECTED = {
    "decompengine.oracle.gcc.GccSourceOpenPgpTest": 10,
    "decompengine.oracle.gcc.GccSourceArchiveTest": 13,
    "decompengine.oracle.gcc.GccSignedSourceTest": 12,
    "decompengine.oracle.gcc.GccSignedSourceQualificationTest": 1,
}
EXPECTED_METHODS = json.loads((ROOT / "scripts/gcc-signed-source-test-inventory.json").read_text())
if set(EXPECTED_METHODS) != set(EXPECTED) or any(
        len(EXPECTED_METHODS[name]) != count or len(set(EXPECTED_METHODS[name])) != count
        for name, count in EXPECTED.items()):
    raise ValueError("reviewed GCC source method inventory is inconsistent")
FALSE_AUTHORITY = {name: False for name in (
    "runtimeAuthenticated", "captureAuthenticated", "ownershipComplete", "nominalIdentityComplete",
    "modelBound", "sealed", "scored", "complete", "productionVerified", "releaseEligible")}


def inspect_xml(directory):
    suites, failures = [], []
    expected_files = {f"TEST-{name}.xml" for name in EXPECTED}
    if {path.name for path in directory.glob("TEST-*.xml")} != expected_files:
        failures.append("Missing or extra required suite XML")
    for name, expected in EXPECTED.items():
        path = directory / f"TEST-{name}.xml"
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("missing, linked or oversized XML")
            raw = path.read_bytes()
            suite = ET.fromstring(raw)
            cases = list(suite.findall("testcase"))
            names = [case.get("name") for case in cases]
            counts = {key: int(suite.get(key, "-1")) for key in ("tests", "failures", "errors", "skipped")}
            valid = (suite.tag == "testsuite" and suite.get("name") == name and expected > 0
                     and len(cases) == expected and len(set(names)) == expected and all(names)
                     and set(names) == set(EXPECTED_METHODS[name])
                     and counts == {"tests": expected, "failures": 0, "errors": 0, "skipped": 0}
                     and all(case.get("classname") == name and not any(case.find(tag) is not None
                         for tag in ("failure", "error", "skipped")) for case in cases))
            if not valid:
                failures.append(f"Failed, skipped, duplicated or changed required inventory: {name}")
            suites.append({"suite": name, **counts, "methods": names, "xmlSha256": hashlib.sha256(raw).hexdigest()})
        except (OSError, ET.ParseError, ValueError) as error:
            failures.append(f"Invalid suite {name}: {error}")
    return suites, failures


def bounded_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError(f"missing, linked or oversized evidence: {path.name}")
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError(f"evidence grew past its bound: {path.name}")
    return raw, json.loads(raw)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for name in ("summary.json", "evidence-first.json", "evidence-second.json", "qualification.json"):
        (EVIDENCE / name).unlink(missing_ok=True)
    if RESULTS.exists():
        shutil.rmtree(RESULTS)
    before_head, before_status = git("rev-parse", "HEAD"), git("status", "--porcelain")
    started = time.monotonic()
    environment = dict(os.environ, DECOMP_REQUIRE_GCC_SIGNED_SOURCE="1")
    command = [str(ROOT / "gradlew"), "--no-daemon", "--max-workers=2", "--console=plain", "gccSignedSourceQualification"]
    with (EVIDENCE / "gradle.log").open("w") as output:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
    suites, failures = inspect_xml(RESULTS)
    after_head, after_status = git("rev-parse", "HEAD"), git("status", "--porcelain")
    expected_head = os.environ.get("EXPECTED_SOURCE_HEAD", before_head)
    clean = not before_status and not after_status
    if not clean or before_head != after_head or after_head != expected_head:
        failures.append("Source head changed, differs from requested exact head, or is dirty")
    outputs = {}
    try:
        first, source = bounded_json(EVIDENCE / "evidence-first.json")
        second, _ = bounded_json(EVIDENCE / "evidence-second.json")
        if first != second:
            raise ValueError("independent source evidence differs")
        if source.get("scope") != "exact-signed-source-release-only" or source.get("sourceAuthenticated") is not True:
            raise ValueError("source scope differs")
        if source.get("authority") != FALSE_AUTHORITY:
            raise ValueError("report claims authority beyond signed source")
        if source.get("archive") != {"bytes": 107200820, "sha256": "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e"}:
            raise ValueError("actual archive identity differs")
        _, qualification = bounded_json(EVIDENCE / "qualification.json")
        phases = ["METADATA_VERIFIED", "INPUTS_PINNED", "SIGNATURE_VERIFIED", "ARCHIVE_SCANNED", "BEFORE_HANDOFF"]
        if (qualification.get("status") != "passed" or qualification.get("deterministic") is not True
                or qualification.get("phaseSubstitutionRefusals") != phases
                or any(qualification.get(key) is not True for key in ("afterHandoffSubstitutionRefused",
                    "copyIsolationVerified", "closeSemanticsVerified", "factoryIssuanceAndRevocationVerified",
                    "retainedReportConstructorCloneRefused"))
                or qualification.get("evidenceFirstSha256") != hashlib.sha256(first).hexdigest()
                or qualification.get("evidenceSecondSha256") != hashlib.sha256(second).hexdigest()):
            raise ValueError("actual source lifecycle qualification is incomplete")
        observations = qualification.get("observations", {})
        if (not 0 < observations.get("jvmMaximumHeapBytes", 0) <= 536870912
                or observations.get("processVmHwmKiB", 0) <= 0
                or observations.get("wallNanos", 0) <= 0
                or len(qualification.get("verifications", [])) != 7
                or qualification.get("afterHandoffSubstitutionTarget") != "archive"):
            raise ValueError("bounded JVM observations or archive substitution proof are missing")
        tool = qualification.get("tool", {})
        if (not all(isinstance(tool.get(key), str) and tool[key] for key in
                    ("javaVersion", "javaVendor", "javaVmVersion"))
                or any(not isinstance(tool.get(key), str) or len(tool[key]) != 64
                       or any(character not in "0123456789abcdef" for character in tool[key])
                       for key in ("javaExecutableSha256", "javaReleaseSha256"))):
            raise ValueError("exact JVM tool identity is missing")
        outputs = {name: hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest()
                   for name in ("evidence-first.json", "evidence-second.json", "qualification.json")}
    except (OSError, ValueError, TypeError) as error:
        failures.append(str(error))
    if result.returncode:
        failures.append(f"Gradle exit {result.returncode}")
    summary = {"schemaVersion": 1, "gate": "gcc-signed-source-v1", "sourceHead": after_head,
        "expectedSourceHead": expected_head, "sourceClean": clean, "forcedTestExecution": True,
        "gradleExitCode": result.returncode, "wallSeconds": time.monotonic() - started, "command": command,
        "gradleWrapperSha256": hashlib.sha256((ROOT / "gradle/wrapper/gradle-wrapper.jar").read_bytes()).hexdigest(),
        "gradleWrapperPropertiesSha256": hashlib.sha256((ROOT / "gradle/wrapper/gradle-wrapper.properties").read_bytes()).hexdigest(),
        "passed": not failures, "suites": suites, "outputSha256": outputs, "failures": failures,
        "authority": FALSE_AUTHORITY}
    (EVIDENCE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
