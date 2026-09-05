#!/usr/bin/env python3
"""Run the scoped benign #242 matrix and retain fresh, fail-closed evidence."""

import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
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
    "web.UploadServerTest",
    "web.UploadUncertaintyHttpTest",
    "web.WebShutdownTest",
    "web.WebRequestLifetimeTest",
))


def main():
    root = Path(__file__).resolve().parents[1]
    evidence_root = root / "build/web-job-recovery-verification"
    evidence_root.mkdir(parents=True, exist_ok=True)
    # Serialize this runner's builds; unrelated Gradle invocations must still be kept separate.
    with (evidence_root / "runner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return verify(root, evidence_root)


def verify(root, evidence_root):
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
        "limitations": ["Not full CI or B-series release qualification",
                        "No vulnerability reproduction lane is selected",
                        "No power-loss, kernel-I/O interruption or safe reclamation proof"],
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Recovery evidence: " + str(output), flush=True)
    with (output / "gradle.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    failures = []
    suites = {}
    totals = dict(tests=0, failures=0, errors=0, skipped=0)
    for report in sorted((output / "xml").glob("TEST-*.xml")):
        try:
            node = ET.parse(report).getroot()
            name = node.attrib["name"]
            counts = {key: int(node.attrib.get(key, 0)) for key in totals}
            if name in suites or name not in SUITES:
                failures.append("Unexpected or duplicate suite: " + name)
            if counts["tests"] <= 0 or counts["tests"] != len(node.findall("testcase")):
                failures.append("Missing test cases: " + name)
            suites[name] = dict(counts, xmlSha256=hashlib.sha256(report.read_bytes()).hexdigest())
            for key in totals:
                totals[key] += counts[key]
        except (ET.ParseError, KeyError, ValueError) as error:
            failures.append("Invalid JUnit report: " + report.name + ": " + type(error).__name__)
    failures.extend("Missing suite: " + name for name in SUITES if name not in suites)
    if result.returncode:
        failures.append("Gradle exited " + str(result.returncode))
    if any(totals[key] for key in ("failures", "errors", "skipped")):
        failures.append("Matrix contains failures, errors or skipped tests")
    manifest.update(status="failed" if failures else "passed", gradleExit=result.returncode,
                    totals=totals, suites=suites, verificationFailures=failures)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": manifest["status"], "totals": totals, "manifest": str(manifest_path)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
