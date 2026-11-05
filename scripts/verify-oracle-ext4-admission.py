#!/usr/bin/env python3
"""Require the named actual mounted-state admission controls, with no skipped credit."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


CLASS = "decompengine.oracle.fulltree.FullTreeDiskScratchAdmissionMountedTest"
REQUIRED = (
    "mounted exact ext4 root pins capacity and rejects a second lock",
    "mounted ext4 total byte maximum is enforced",
    "mounted ext4 total inode maximum is enforced",
    "mounted ext4 available byte minimum is enforced",
    "mounted ext4 available inode minimum is enforced",
    "mounted ext4 without nodev is refused",
    "mounted ext4 without nosuid is refused",
    "mounted ext4 without noexec is refused",
    "mounted ext4 without noatime is refused",
    "mounted read only ext4 is refused",
    "mounted tmpfs is refused",
    "mounted nested filesystem is refused",
    "mounted bind subtree is refused",
    "mounted visible same device alias is refused",
    "mounted root owned by another user is refused",
    "mounted root with permissive mode is refused",
    "mounted ordinary subdirectory and symlink are refused without changing alien canary",
    "mounted replacement refuses stale lease release and preserves both filesystems",
)


def verify(reports: Path) -> dict:
    if reports.is_symlink() or not reports.is_dir():
        raise ValueError("missing or linked JUnit report directory")
    path = reports / f"TEST-{CLASS}.xml"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("missing, linked, or oversized mounted-admission JUnit report")
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("declarations are not admitted in JUnit reports")
    suite = ET.fromstring(raw)
    observed = Counter()
    for case in suite.iter("testcase"):
        if case.get("classname") != CLASS:
            raise ValueError("unexpected test class in mounted-admission report")
        name = case.get("name", "")
        if name.endswith("()"):
            name = name[:-2]
        if name not in REQUIRED:
            raise ValueError(f"unexpected mounted-admission control: {name}")
        if any(case.find(status) is not None for status in ("failure", "error", "skipped")):
            raise ValueError(f"mounted-admission control did not pass: {name}")
        observed[name] += 1
    if observed != Counter(REQUIRED):
        raise ValueError("mounted-admission report lacks exactly one execution of every named control")
    return {
        "schemaVersion": 1,
        "status": "passed",
        "scope": "actual kernel mount admission; not JSON mutation, worker START, crash-reset, or full-tree scoring qualification",
        "class": CLASS,
        "passed": len(REQUIRED),
        "skipped": 0,
        "controls": list(REQUIRED),
        "reportBytes": len(raw),
        "reportSha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.reports)
    except (OSError, ValueError, ET.ParseError) as failure:
        report = {"schemaVersion": 1, "status": "failed", "reason": str(failure)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
