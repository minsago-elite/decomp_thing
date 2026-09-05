#!/usr/bin/env python3
"""Run and inventory the required local/contained C0 fixtures; never certify a workflow release."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "decompengine.agent.AgentExecutionContractTest": 8,
    "decompengine.builtin.BuiltinAgentHarnessTest": 14,
    "decompengine.builtin.BuiltinFilesystemToolsTest": 7,
    "decompengine.builtin.BuiltinCapturedContextToolsTest": 6,
    "decompengine.builtin.BuiltinContextPackageTest": 5,
    "decompengine.builtin.BuiltinTerminalToolsTest": 7,
    "decompengine.builtin.provider.OpenAiCompatibleModelProviderTest": 23,
}


def main():
    evidence = ROOT / "build/builtin-contract-qualification"
    evidence.mkdir(parents=True, exist_ok=True)
    # Invalidate any prior verdict before attempting a new run.
    summary = evidence / "summary.json"
    summary.unlink(missing_ok=True)
    environment = dict(os.environ, DECOMP_REQUIRE_LIVE_ACP_CONTRACT="1")
    result = subprocess.run(
        [str(ROOT / "gradlew"), "--no-daemon", "--rerun-tasks", "test", "--tests", "decompengine.builtin.*",
         "--tests", "decompengine.agent.*", "--console=plain"], cwd=ROOT, env=environment,
    )
    suites, failures = [], []
    for name, expected in EXPECTED.items():
        path = ROOT / "build/test-results/test" / f"TEST-{name}.xml"
        if not path.is_file():
            failures.append(f"Missing suite: {name}")
            continue
        raw = path.read_bytes()
        try:
            suite = ET.fromstring(raw)
            cases = list(suite.findall("testcase"))
            names = [case.get("name") for case in cases]
            counts = {key: int(suite.get(key, "-1")) for key in ("tests", "failures", "errors", "skipped")}
            valid = (suite.get("name") == name and len(cases) == expected and len(set(names)) == expected
                     and counts == {"tests": expected, "failures": 0, "errors": 0, "skipped": 0}
                     and all(not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in cases))
            if not valid:
                failures.append(f"Failed, skipped or changed required inventory: {name}")
            suites.append({"suite": name, **counts, "xmlSha256": hashlib.sha256(raw).hexdigest()})
        except (ET.ParseError, ValueError):
            failures.append(f"Malformed suite: {name}")
    source_clean = not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    if not source_clean:
        failures.append("Source worktree is not clean")
    verdict = {
        "schemaVersion": 1, "corpus": "builtin-core-contract-v3",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "requiredHost": True, "sourceClean": source_clean, "forcedTestExecution": True, "gradleExitCode": result.returncode,
        "passed": result.returncode == 0 and not failures,
        "realProviderQualified": False, "workflowReleaseQualified": False,
        "suites": suites, "failures": failures,
    }
    summary.write_text(json.dumps(verdict, indent=2) + "\n")
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
