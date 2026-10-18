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
    "jobs.WorkflowCancellationReceiptTest",
    "jobs.WorkflowStartReceiptTest",
    "web.DurableWebWorkflowStartTest",
    "web.WebWorkflowStartControllerTest",
    "web.WebJobServiceTest",
    "web.WebAttemptCancellationTest",
    "web.UploadServerShutdownTest",
    "web.WebApiControllerTest",
))

CONTEXT_PREFIX = "web-job-recovery-context-v1 "
RUNTIME_FIELDS = {"javaRuntimeVersion", "javaVendor", "javaVmName", "osName", "osVersion", "osArch"}
ROOT_FIELDS = {"ordinal", "provider", "scheme", "type", "blockSizeBytes", "blockSizeStatus",
               "readOnly", "supportsPosix", "supportsUnix"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture context key")
        result[key] = value
    return result


def public_text(value, maximum):
    return (isinstance(value, str) and 0 < len(value) <= maximum and
            all(32 <= ord(char) <= 126 and char not in "/\\" for char in value))


def fixture_contexts(node, suite, methods):
    contexts = {}
    for output in node.iter("system-out"):
        for line in (output.text or "").splitlines():
            if not line.startswith(CONTEXT_PREFIX):
                continue
            if len(line) > 256 * 1024 or len(line.encode("utf-8")) > 256 * 1024:
                raise ValueError("fixture context exceeds its byte bound")
            item = json.loads(line[len(CONTEXT_PREFIX):], object_pairs_hook=unique_object)
            if (not isinstance(item, dict) or set(item) != {"schemaVersion", "scope", "caseClass",
                    "caseMethod", "runtime", "fixtureRoots", "filesystemDisposition"} or
                    type(item["schemaVersion"]) is not int or item["schemaVersion"] != 1 or
                    item["scope"] != "benign-recovery-fixture-runtime" or item["caseClass"] != suite or
                    not isinstance(item["caseMethod"], str) or len(item["caseMethod"]) > 1024 or
                    item["caseMethod"] not in methods or item["caseMethod"] in contexts):
                raise ValueError("fixture context has invalid or duplicate identity")
            runtime, roots = item["runtime"], item["fixtureRoots"]
            if (not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS or
                    any(not public_text(value, 128) for value in runtime.values()) or
                    not isinstance(roots, list) or len(roots) > 256):
                raise ValueError("invalid fixture runtime or root inventory")
            for ordinal, root in enumerate(roots, 1):
                if not isinstance(root, dict) or set(root) != ROOT_FIELDS:
                    raise ValueError("invalid fixture filesystem fields")
                if (type(root["ordinal"]) is not int or root["ordinal"] != ordinal or
                        not public_text(root["provider"], 160) or
                        not re.fullmatch(r"[A-Za-z_$][A-Za-z_0-9$]*(\.[A-Za-z_$][A-Za-z_0-9$]*)*", root["provider"]) or
                        not public_text(root["scheme"], 32) or
                        not re.fullmatch(r"[a-z][a-z0-9+.-]*", root["scheme"]) or
                        not public_text(root["type"], 64) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", root["type"]) or
                        any(type(root[key]) is not bool for key in ("readOnly", "supportsPosix", "supportsUnix"))):
                    raise ValueError("invalid fixture filesystem facts")
                block_size, status = root["blockSizeBytes"], root["blockSizeStatus"]
                if not ((status == "UNSUPPORTED" and block_size is None) or
                        (status == "CAPTURED" and type(block_size) is int and 0 < block_size <= 2**63 - 1)):
                    raise ValueError("invalid fixture block-size observation")
            if item["filesystemDisposition"] != ("OBSERVED" if roots else "NOT_EXERCISED"):
                raise ValueError("fixture filesystem disposition contradicts its roots")
            contexts[item["caseMethod"]] = item
    if set(contexts) != set(methods):
        raise ValueError("required testcase fixture context is missing")
    return contexts


def configuration_coverage(suites, required):
    cases = [case for suite in suites.values() for case in suite["cases"] if "context" in case]
    no_roots, unsupported, configurations = [], [], {}
    roots_count = 0
    for case in cases:
        context = case["context"]
        if not context["fixtureRoots"]:
            no_roots.append(dict(className=case["className"], method=case["method"]))
        for root in context["fixtureRoots"]:
            roots_count += 1
            configuration = dict(runtime=context["runtime"], filesystem={k: v for k, v in root.items() if k != "ordinal"})
            configurations[json.dumps(configuration, sort_keys=True)] = configuration
            if root["blockSizeStatus"] == "UNSUPPORTED":
                unsupported.append(dict(className=case["className"], method=case["method"], ordinal=root["ordinal"]))
    return dict(required=required, caseContexts=len(cases), fixtureRoots=roots_count,
                casesWithoutFixtureRoots=no_roots, unsupportedBlockSizeObservations=unsupported,
                observedConfigurations=[configurations[key] for key in sorted(configurations)])


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


def require_fixture_instrumentation(source):
    if (source.count("import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory") != 1 or
            source.count("@ExtendWith(RecoveryMatrixEvidence::class)") != 1 or
            re.search(r"\b[A-Za-z_][A-Za-z_0-9.]*\s*(?:\.|::)\s*createTempDirectory\b", source) or
            re.search(r"\bcreateTempDir\b", source) or
            re.search(r"\b(?:fun|val|var)\s+`?createTempDirectory`?\b", source)):
        raise ValueError("selected recovery source bypasses its fixture context contract")


def required_cases(root):
    required = {}
    sources = []
    for suite in SUITES:
        relative = "src/test/kotlin/" + suite.replace(".", "/") + ".kt"
        payload = (root / relative).read_bytes()
        source = payload.decode("utf-8")
        require_fixture_instrumentation(source)
        required[suite] = source_test_methods(source)
        sources.append(dict(path=relative, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
    return required, sources


def inspect_reports(required, reports, allow_unrelated=False, require_context=False):
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
            if require_context:
                contexts = fixture_contexts(node, name, expected)
                for case in cases:
                    if case["method"] in contexts:
                        case["context"] = contexts[case["method"]]
            suites[name] = dict(counts, cases=cases, report=report,
                                xmlBytes=len(payload), xmlSha256=hashlib.sha256(payload).hexdigest())
            for key in totals:
                totals[key] += counts[key]
        except (ET.ParseError, KeyError, ValueError) as error:
            failures.append("Invalid JUnit report: " + report + ": " + type(error).__name__)
    failures.extend("Missing suite: " + name for name in required if name not in suites)
    if any(totals[key] for key in ("failures", "errors", "skipped")):
        failures.append("Recovery scenarios contain failures, errors or skipped tests")
    return dict(totals=totals, suites=suites, verificationFailures=failures,
                configurationCoverage=configuration_coverage(suites, require_context))


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
        for path in reports.glob("TEST-*.xml")}, allow_unrelated=True, require_context=True)
    document = dict(schemaVersion=3, scope="source-declared recovery scenario and observed fixture configuration coverage",
        status="failed" if inspected["verificationFailures"] else "passed",
        fullMatrixQualified=False, sourceBinding=source_binding(root), requiredSuites=SUITES,
        requiredCases=required, declarationSources=sources, **inspected,
        limitations=["Does not execute tests; consumes the existing core JVM reports",
                     "Literal zero-argument @Test corpus only; other declaration forms are refused",
                     "Runtime/filesystem facts are observed fixture metadata, not immutable host or execution authority",
                     "No-root cases and unsupported block-size observations are explicit; full supported-configuration qualification remains separate",
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
        "schemaVersion": 2, "status": "running", "scope": "benign web job recovery",
        "startedAt": stamp.rstrip("-"), "commit": capture("git", "rev-parse", "HEAD"),
        "worktreeDirty": bool(capture("git", "status", "--porcelain")),
        "trackedDiffSha256": hashlib.sha256(subprocess.check_output(
            ["git", "diff", "HEAD", "--binary"], cwd=root)).hexdigest(),
        "launcherJava": capture("java", "-version"), "launcherKernel": capture("uname", "-sr"),
        "launcherTemporaryFilesystem": capture("stat", "-f", "-c", "%T", str(temporary)),
        "command": command, "requiredSuites": SUITES,
        "requiredCases": required, "declarationSources": sources,
        "sourceBinding": source_binding(root), "fullMatrixQualified": False,
        "limitations": ["Not full CI or B-series release qualification",
                        "Per-case fixture observations do not qualify the full supported-configuration matrix or immutable host authority",
                        "No vulnerability reproduction lane is selected",
                        "No power-loss, kernel-I/O interruption or safe reclamation proof"],
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Recovery evidence: " + str(output), flush=True)
    with (output / "gradle.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    inspected = inspect_reports(required, {path.name: path.read_bytes()
        for path in (output / "xml").glob("TEST-*.xml")}, require_context=True)
    failures = inspected["verificationFailures"]
    totals = inspected["totals"]
    if result.returncode:
        failures.append("Gradle exited " + str(result.returncode))
    manifest.update(status="failed" if failures else "passed", gradleExit=result.returncode,
                    totals=totals, suites=inspected["suites"], verificationFailures=failures,
                    configurationCoverage=inspected["configurationCoverage"])
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": manifest["status"], "totals": totals, "manifest": str(manifest_path)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
