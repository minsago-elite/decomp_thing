#!/usr/bin/env python3
"""Require the one fresh configured interface qualification method; never mint authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import xml.etree.ElementTree as ET

CLASS = "decompengine.oracle.gcc.GccInferredInterfaceQualificationTest"
METHOD = "live pinned driver retains complete owned raw interface observations()"
MAXIMUM_REPORT_BYTES = 1024 * 1024


def inspect(report: Path, gradle_exit: int) -> dict:
    result = {"provider": "gcc-interface-qualification-execution-inventory-v1", "schemaVersion": 1,
              "class": CLASS, "method": METHOD, "gradleExitCode": gradle_exit,
              "complete": False, "productionInterfacesAdmitted": False, "releaseEligible": False}
    try:
        descriptor = os.open(report, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAXIMUM_REPORT_BYTES:
                raise ValueError("execution report is not one bounded regular file")
            data = stream.read(MAXIMUM_REPORT_BYTES + 1)
            after = os.fstat(stream.fileno())
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
                        value.st_mtime_ns, value.st_ctime_ns)
            if (identity(before) != identity(after) or identity(after) != identity(os.stat(report, follow_symlinks=False))
                    or len(data) != before.st_size):
                raise ValueError("execution report changed during capture")
        result["reportSha256"] = hashlib.sha256(data).hexdigest()
        result["reportBytes"] = len(data)
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            raise ValueError("execution report may not declare document entities")
        root = ET.fromstring(data)
        if root.tag != "testsuite" or root.attrib.get("name") != CLASS:
            raise ValueError("execution report does not describe the selected class")
        required = {"tests": "1", "failures": "0", "errors": "0", "skipped": "0"}
        if any(root.attrib.get(key) != value for key, value in required.items()):
            raise ValueError("qualification did not execute exactly one successful unskipped method")
        cases = list(root.iter("testcase"))
        if len(cases) != 1 or cases[0].attrib.get("classname") != CLASS or cases[0].attrib.get("name") != METHOD:
            raise ValueError("qualification executed a different or incomplete method inventory")
        if any(node.tag in {"failure", "error", "skipped"} for node in root.iter()):
            raise ValueError("qualification contains failure/error/skip evidence")
        if gradle_exit != 0:
            raise ValueError("Gradle did not finish successfully")
        result.update(executedMethods=1, failures=0, errors=0, skips=0, executionVerified=True)
    except (OSError, ValueError, ET.ParseError) as failure:
        result.update(executionVerified=False, error=str(failure)[:1024])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gradle-exit", required=True, type=int)
    arguments = parser.parse_args()
    result = inspect(arguments.report, arguments.gradle_exit)
    data = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return 0 if result["executionVerified"] else 1


if __name__ == "__main__":
    sys.exit(main())
