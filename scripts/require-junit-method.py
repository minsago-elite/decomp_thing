#!/usr/bin/env python3
"""Require that one JUnit test method executed and passed in a Gradle XML report.

A missing report, a missing method, a duplicate method, or a skipped, failed or erroring case is
refused, so an opt-in job cannot stay green when its required test did not really run.
"""
import argparse
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

MAXIMUM_REPORT_BYTES = 16 * 1024 * 1024


def require_method(reports: Path, class_name: str, method: str) -> str:
    path = reports / f"TEST-{class_name}.xml"
    try:
        raw = path.read_bytes()
    except OSError as failure:
        raise ValueError(f"report for {class_name} is missing") from failure
    if len(raw) > MAXIMUM_REPORT_BYTES:
        raise ValueError(f"report for {class_name} exceeds its byte bound")
    try:
        suite = ET.fromstring(raw)
    except ET.ParseError as failure:
        raise ValueError(f"report for {class_name} is malformed") from failure
    if suite.tag != "testsuite" or suite.get("name") != class_name:
        raise ValueError(f"report suite identity differs from {class_name}")
    cases = [case for case in suite.iter("testcase")
             if case.get("classname") == class_name and case.get("name") in (method, f"{method}()")]
    if len(cases) != 1:
        raise ValueError(f"{class_name}.{method} ran {len(cases)} times, not exactly once")
    for kind in ("skipped", "failure", "error"):
        if cases[0].find(kind) is not None:
            raise ValueError(f"{class_name}.{method} did not pass: {kind}")
    return f"{class_name}.{method} passed"


def self_test() -> None:
    method = "required case"
    suite = "decompengine.Example"

    def report(directory: Path, body: str, name: str = suite) -> Path:
        directory.joinpath(f"TEST-{suite}.xml").write_text(
            f'<testsuite name="{name}" tests="1">{body}</testsuite>', encoding="utf-8")
        return directory

    def case(extra: str = "", name: str = method) -> str:
        return f'<testcase name="{name}()" classname="{suite}">{extra}</testcase>'

    parent = Path.cwd() / "build"
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as scratch:
        root = Path(scratch)
        require_method(report(root, case()), suite, method)
        refusals = {
            "missing report": None,
            "missing method": case(name="another case"),
            "skipped": case("<skipped/>"),
            "failed": case("<failure/>"),
            "errored": case("<error/>"),
            "duplicate": case() + case(),
            "foreign suite": "foreign",
        }
        for label, body in refusals.items():
            directory = root / label.replace(" ", "-")
            directory.mkdir()
            if body == "foreign":
                report(directory, case(), name="decompengine.Other")
            elif body is not None:
                report(directory, body)
            try:
                require_method(directory, suite, method)
            except ValueError:
                continue
            raise AssertionError(f"{label} was not refused")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--class", dest="class_name")
    parser.add_argument("--method")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        print("require-junit-method self-test passed")
        return 0
    if not (arguments.reports and arguments.class_name and arguments.method):
        parser.error("--reports, --class and --method are required")
    try:
        print(require_method(arguments.reports, arguments.class_name, arguments.method))
    except ValueError as failure:
        print(f"required JUnit method check failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
