#!/usr/bin/env python3
"""Require installed bundled-Ghidra probes to pass in JUnit XML."""
import argparse
from collections import Counter
from itertools import islice
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


# Exact Gradle/JUnit identities are the hosted gate. Keep the existing GCC
# deployment probes mandatory alongside the #1893 default-dot qualifier.
REQUIRED = {
    (
        "decompengine.oracle.gcc.GccBundledGhidraDeploymentReferenceTest",
        "installed opener selects its own application exporter despite an earlier shadow resource()",
    ),
    (
        "decompengine.oracle.gcc.GccBundledGhidraDeploymentReferenceTest",
        "installed opener rejects reference root and paired overrides before source selection()",
    ),
    (
        "decompengine.project.GhidraDotDirectoryInvocationQualificationTest",
        "installed bundled worker records default dot directory invocation()",
    ),
}
# The dedicated job emits Gradle testsuite documents, not arbitrary XML wrappers.
MAX_REPORT_FILES = 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def verify(report_root: Path) -> list[str]:
    errors = []
    xml_files = sorted(islice(report_root.glob("TEST-*.xml"), MAX_REPORT_FILES + 1)) if report_root.is_dir() else []
    if len(xml_files) > MAX_REPORT_FILES:
        return ["JUnit report file count exceeds its bound"]
    if not xml_files:
        return [f"no JUnit XML reports found under {report_root}"]
    found = Counter()
    total_bytes = 0
    for report in xml_files:
        try:
            if report.is_symlink() or not report.is_file():
                errors.append(f"JUnit report is not an ordinary file: {report}")
                continue
            with report.open("rb") as stream:
                raw = stream.read(MAX_REPORT_BYTES + 1)
            total_bytes += len(raw)
            if len(raw) > MAX_REPORT_BYTES or total_bytes > MAX_TOTAL_BYTES:
                return errors + [f"JUnit report byte bound exceeded: {report}"]
            root = ET.fromstring(raw)
        except (ET.ParseError, OSError) as exc:
            errors.append(f"cannot parse {report}: {exc}")
            continue
        cases = root.findall("testcase")
        if root.tag != "testsuite" or not root.get("name") or len(list(root.iter("testcase"))) != len(cases):
            errors.append(f"unsupported Gradle JUnit report structure: {report}")
            continue
        for case in cases:
            identity = (case.get("classname", ""), case.get("name", ""))
            if identity not in REQUIRED:
                continue
            if root.get("name") != identity[0]:
                errors.append(f"required testcase has the wrong suite identity: {report}")
                continue
            found[identity] += 1
            outcomes = [child.tag for child in case if child.tag in {"skipped", "failure", "error"}]
            if outcomes:
                errors.append(f"{identity[1]}: report contains {', '.join(outcomes)} in {report}")
    for identity in sorted(REQUIRED):
        classname, name = identity
        count = found[identity]
        if count == 0:
            errors.append(f"missing required passing testcase: {classname}#{name}")
        elif count > 1:
            errors.append(f"duplicate testcase identity ({count} reports): {classname}#{name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_root", type=Path)
    args = parser.parse_args()
    errors = verify(args.report_root)
    if errors:
        print("Bundled Ghidra installed-probe qualification FAILED:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Bundled Ghidra installed-probe qualification PASSED (all three required identities, once each).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
