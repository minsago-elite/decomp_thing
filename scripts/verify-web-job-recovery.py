#!/usr/bin/env python3
"""Check individual benign recovery scenarios; optionally run their existing suites."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


SUITES = tuple("decompengine." + name for name in (
    "jobs.JobStoreTest",
    "jobs.JobStoreDirectoriesTest",
    "jobs.JobStoreDirectoriesCrashTest",
    "jobs.JobMetadataPublicationTest",
    "jobs.JobMetadataCrashTest",
    "jobs.JobUploadCrashTest",
    "jobs.JobRecoveryInventoryTest",
    "jobs.JobRecoveryAdmissionTest",
    "web.UploadServerTest",
    "web.UploadUncertaintyHttpTest",
    "web.WebShutdownTest",
    "web.WebRequestLifetimeTest",
    "web.WebRecoveryAdmissionTest",
    "jobs.StagedJobUploadTest",
    "jobs.UploadStagingRecoveryTest",
    "jobs.WorkflowAttemptStoreTest",
    "web.WebJobServiceTest",
    "web.UploadServerShutdownTest",
    "web.WebApiControllerTest",
))


def source_test_methods(source):
    """The selected corpus uses literal, zero-argument Kotlin @Test declarations.

    This deliberately includes nested declarations: a source scenario that Jupiter
    cannot discover must be reported missing, not silently dropped. It is not a
    general Kotlin/JUnit parser. Other test forms need an explicit extension.
    """
    if re.search(r"@(?:[A-Za-z_][A-Za-z_0-9]*\.)*(ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\b", source) or re.search(
            r"import\s+[A-Za-z_][A-Za-z_0-9.]*\.(?:Test|ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\s+as\b", source):
        raise ValueError("unsupported recovery test declaration form")
    annotations = list(re.finditer(r"@(?:[A-Za-z_][A-Za-z_0-9]*\.)*Test\b", source))
    declarations = list(re.finditer(r"@Test\s+fun\s+`([^`\r\n]+)`\s*\(\s*\)", source))
    if not declarations or [match.start() for match in annotations] != [match.start() for match in declarations]:
        raise ValueError("recovery test annotations do not match the supported literal form")
    methods = [match.group(1) + "()" for match in declarations]
    if len(set(methods)) != len(methods):
        raise ValueError("duplicate recovery scenario declaration")
    return methods


def required_cases(root):
    required = {}
    sources = []
    for suite in SUITES:
        relative = "src/test/kotlin/" + suite.replace(".", "/") + ".kt"
        payload = (root / relative).read_bytes()
        required[suite] = source_test_methods(payload.decode("utf-8"))
        sources.append(dict(path=relative, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
    return required, sources


def inspect_reports(required, reports, allow_unrelated=False):
    """Compare actual case identities/outcomes and counts, never suite counts alone."""
    failures = []
    suites = {}
    totals = dict(tests=0, failures=0, errors=0, skipped=0)
    for report, payload in sorted(reports.items()):
        try:
            node = ET.fromstring(payload)
            if node.tag != "testsuite":
                raise ValueError("unsupported JUnit root")
            name = node.attrib["name"]
            if name not in required:
                if not allow_unrelated:
                    failures.append("Unexpected suite: " + name)
                continue
            if name in suites:
                failures.append("Duplicate suite: " + name)
                continue
            rows = node.findall("testcase")
            counts = dict(tests=len(rows), failures=0, errors=0, skipped=0)
            cases = []
            identities = []
            for case in rows:
                method = case.attrib["name"]
                if case.attrib["classname"] != name:
                    raise ValueError("testcase class differs from its suite")
                markers = [key for key in ("failure", "error", "skipped") if case.find(key) is not None]
                if len(markers) > 1:
                    raise ValueError("testcase has conflicting outcomes")
                status = {"failure": "FAIL", "error": "ERROR", "skipped": "SKIP"}.get(
                    markers[0] if markers else "", "PASS")
                if markers:
                    counts[{"failure": "failures", "error": "errors", "skipped": "skipped"}[markers[0]]] += 1
                identities.append(method)
                cases.append(dict(className=name, method=method, status=status))
            if not rows or any(int(node.attrib.get(key, 0)) != value for key, value in counts.items()):
                raise ValueError("suite counts differ from actual testcase outcomes")
            if len(set(identities)) != len(identities):
                failures.append("Duplicate testcase: " + name)
            expected, actual = set(required[name]), set(identities)
            failures.extend("Missing testcase: " + name + "::" + method for method in sorted(expected - actual))
            failures.extend("Unexpected testcase: " + name + "::" + method for method in sorted(actual - expected))
            suites[name] = dict(counts, cases=cases, report=report,
                                xmlBytes=len(payload), xmlSha256=hashlib.sha256(payload).hexdigest())
            for key in totals:
                totals[key] += counts[key]
        except (ET.ParseError, KeyError, ValueError) as error:
            failures.append("Invalid JUnit report: " + report + ": " + type(error).__name__)
    failures.extend("Missing suite: " + name for name in required if name not in suites)
    if any(totals[key] for key in ("failures", "errors", "skipped")):
        failures.append("Recovery scenarios contain failures, errors or skipped tests")
    return dict(totals=totals, suites=suites, verificationFailures=failures)


def source_binding(root):
    def capture(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root)
    return dict(commit=capture("rev-parse", "HEAD").decode("ascii").strip(),
                tree=capture("rev-parse", "HEAD^{tree}").decode("ascii").strip(),
                worktreeDirty=bool(capture("status", "--porcelain").strip()),
                trackedDiffSha256=hashlib.sha256(capture("diff", "HEAD", "--binary")).hexdigest())


def coverage_only(root, reports, output):
    reports, output = reports.resolve(), output.resolve()
    if not reports.is_relative_to(root) or not output.is_relative_to(root):
        raise ValueError("recovery evidence must remain inside the repository")
    required, sources = required_cases(root)
    inspected = inspect_reports(required, {path.name: path.read_bytes()
        for path in reports.glob("TEST-*.xml")}, allow_unrelated=True)
    document = dict(schemaVersion=2, scope="source-declared recovery scenario coverage only",
        status="failed" if inspected["verificationFailures"] else "passed",
        fullMatrixQualified=False, sourceBinding=source_binding(root), requiredSuites=SUITES,
        requiredCases=required, declarationSources=sources, **inspected,
        limitations=["Does not execute tests; consumes the existing core JVM reports",
                     "Literal zero-argument @Test corpus only; other declaration forms are refused",
                     "No per-case runtime/filesystem capture or complete supported-configuration qualification",
                     "Source snapshots alone do not authenticate the reports' compiled source; retain the CI checkout/compile join",
                     "No power-loss, external-process, provider/model or release authority"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(dict(status=document["status"], totals=inspected["totals"],
                          fullMatrixQualified=False, manifest=str(output))))
    return 1 if inspected["verificationFailures"] else 0


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, help="inspect existing core JUnit XML without invoking Gradle")
    parser.add_argument("--output", type=Path, help="repository-local scenario coverage JSON")
    options = parser.parse_args(arguments)
    if (options.reports is None) != (options.output is None):
        parser.error("--reports and --output must be provided together")
    root = Path(__file__).resolve().parents[1]
    if options.reports is not None:
        return coverage_only(root, options.reports, options.output)
    evidence_root = root / "build/web-job-recovery-verification"
    evidence_root.mkdir(parents=True, exist_ok=True)
    # Serialize this runner's builds; unrelated Gradle invocations must still be kept separate.
    with (evidence_root / "runner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return verify(root, evidence_root)


def verify(root, evidence_root):
    required, sources = required_cases(root)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    output = Path(tempfile.mkdtemp(prefix=stamp, dir=evidence_root))
    temporary = output / "tmp"
    temporary.mkdir()
    env = dict(os.environ)
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        env.pop(name, None)
    env["TMPDIR"] = str(temporary)
    env["GRADLE_OPTS"] = shlex.quote("-Djava.io.tmpdir=" + str(temporary))

    def capture(*command):
        return subprocess.check_output(command, cwd=root, env=env, stderr=subprocess.STDOUT, text=True).strip()

    config = output / "config.json"
    config.write_text(json.dumps({"output": str(output), "temporary": str(temporary)}))
    init = output / "recovery.init.gradle"
    init.write_text("""def config = new groovy.json.JsonSlurper().parse(new File(System.getProperty('recovery.config')))
allprojects {
    tasks.withType(Test).configureEach {
        systemProperty 'java.io.tmpdir', config.temporary
        if (project == rootProject && name == 'test') {
            reports.junitXml.outputLocation.set(new File(config.output, 'xml'))
            reports.html.outputLocation.set(new File(config.output, 'html'))
            binaryResultsDirectory.set(new File(config.output, 'binary'))
            outputs.upToDateWhen { false }
            outputs.cacheIf { false }
        }
    }
}
""")
    command = [str(root / "gradlew"), "--offline", "--no-daemon", "--console=plain",
               "-Dorg.gradle.jvmargs=-Xmx2048m " + shlex.quote("-Djava.io.tmpdir=" + str(temporary)),
               "-Drecovery.config=" + str(config), "-I", str(init),
               "-Pkotlin.compiler.execution.strategy=in-process", "-Pkotlin.incremental=false", "test"]
    for suite in SUITES:
        command.extend(("--tests", suite))
    manifest = {
        "schemaVersion": 1, "status": "running", "scope": "benign web job recovery",
        "startedAt": stamp.rstrip("-"), "commit": capture("git", "rev-parse", "HEAD"),
        "worktreeDirty": bool(capture("git", "status", "--porcelain")),
        "trackedDiffSha256": hashlib.sha256(subprocess.check_output(
            ["git", "diff", "HEAD", "--binary"], cwd=root)).hexdigest(),
        "java": capture("java", "-version"), "kernel": capture("uname", "-sr"),
        "testFilesystem": capture("stat", "-f", "-c", "%T", str(temporary)),
        "command": command, "requiredSuites": SUITES,
        "requiredCases": required, "declarationSources": sources,
        "sourceBinding": source_binding(root), "fullMatrixQualified": False,
        "limitations": ["Not full CI or B-series release qualification",
                        "No per-case runtime/filesystem capture or full supported-configuration matrix",
                        "No vulnerability reproduction lane is selected",
                        "No power-loss, kernel-I/O interruption or safe reclamation proof"],
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Recovery evidence: " + str(output), flush=True)
    with (output / "gradle.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    inspected = inspect_reports(required, {path.name: path.read_bytes()
        for path in (output / "xml").glob("TEST-*.xml")})
    failures = inspected["verificationFailures"]
    totals = inspected["totals"]
    if result.returncode:
        failures.append("Gradle exited " + str(result.returncode))
    manifest.update(status="failed" if failures else "passed", gradleExit=result.returncode,
                    totals=totals, suites=inspected["suites"], verificationFailures=failures)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": manifest["status"], "totals": totals, "manifest": str(manifest_path)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
