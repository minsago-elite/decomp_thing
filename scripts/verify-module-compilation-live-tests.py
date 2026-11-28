#!/usr/bin/env python3
"""Reconcile compiled ci-live inventory with fresh Gradle XML; grants no runtime authority."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PROVIDER = "contained-module-compilation-test-inventory-v1"
MAX_CLASSES = 256
MAX_TESTS = 8192
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_REPORT_BYTES = 64 * 1024 * 1024
CLASS_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build_path(value):
    path = Path(os.path.abspath(value))
    build = ROOT / "build"
    require(path != build and path.is_relative_to(build) and path.resolve() == path,
            "coverage artifacts must belong to checkout/build without symbolic links")
    return path


def read_bounded(path, limit):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), f"artifact is not a regular file: {path.name}")
    require(0 < metadata.st_size <= limit, f"artifact exceeds its size bound or is empty: {path.name}")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    require(0 < len(payload) <= limit, f"artifact exceeds its size bound or is empty: {path.name}")
    return payload


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def bounded_integer(text):
    require(len(text) <= 10, "JSON integer exceeds its bound")
    return int(text)


def reject_number(text):
    raise ValueError(f"non-integer JSON number is unsupported: {text}")


def exact_fields(value, fields, location):
    require(type(value) is dict and set(value) == set(fields), f"unexpected JSON fields at {location}")


def load_inventory(payload):
    require(0 < len(payload) <= MAX_INVENTORY_BYTES, "inventory exceeds its byte bound")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_int=bounded_integer, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as failure:
        raise ValueError("inventory is not bounded valid UTF-8 JSON") from failure
    exact_fields(value, {"schemaVersion", "provider", "classes", "testCount", "tests"}, "inventory")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and
            value["provider"] == INVENTORY_PROVIDER, "unsupported inventory schema or provider")
    classes = value["classes"]
    require(type(classes) is list and 1 <= len(classes) <= MAX_CLASSES and
            all(type(name) is str and len(name) <= 2048 and CLASS_NAME.fullmatch(name) for name in classes),
            "invalid selected classes")
    require(len(set(classes)) == len(classes), "duplicate selected class")
    tests = value["tests"]
    require(type(tests) is list and 1 <= len(tests) <= MAX_TESTS and
            type(value["testCount"]) is int and value["testCount"] == len(tests), "inventory test count differs")
    expected = Counter()
    represented_classes = set()
    for test in tests:
        exact_fields(test, {"class", "method", "reportName"}, "test")
        name, method, report_name = test["class"], test["method"], test["reportName"]
        require(type(name) is str and name in classes and type(method) is str and 1 <= len(method) <= 2048 and
                all(ord(character) >= 32 and ord(character) != 127 and not 0xD800 <= ord(character) <= 0xDFFF
                    for character in method) and type(report_name) is str and report_name == method + "()",
                "invalid class, JVM method, or standard JUnit report name")
        expected[(name, report_name)] += 1
        represented_classes.add(name)
    require(all(count == 1 for count in expected.values()), "duplicate inventory test")
    require(represented_classes == set(classes), "selected class has no inventoried ci-live test")
    return value, expected


def count_attribute(suite, field):
    value = suite.get(field)
    require(value is not None and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None,
            f"missing or invalid XML {field} count")
    return int(value)


def read_report(payload, selected_class):
    try:
        text = payload.decode("utf-8")
        require("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "XML DTDs and entities are forbidden")
        suite = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, RecursionError) as failure:
        raise ValueError("report is not bounded valid UTF-8 XML") from failure
    require(suite.tag == "testsuite" and suite.get("name") == selected_class, "XML suite class differs from report file")
    require(set(suite.attrib) <= {"name", "tests", "failures", "errors", "skipped", "timestamp", "hostname", "time"},
            "unsupported XML suite attributes")
    counts = {field: count_attribute(suite, field) for field in ("tests", "failures", "errors", "skipped")}
    require(counts["failures"] == counts["errors"] == counts["skipped"] == 0, "live suite has failures, errors, or skips")
    require(1 <= counts["tests"] <= MAX_TESTS, "invalid live suite test count")
    actual = Counter()
    for child in suite:
        if child.tag == "testcase":
            require(set(child.attrib) <= {"name", "classname", "time"} and
                    child.get("classname") == selected_class and child.get("name") is not None,
                    "testcase class or attributes differ from selected suite")
            require(all(node.tag in {"system-out", "system-err"} and len(node) == 0 for node in child),
                    "live testcase has a failure, error, skip, or unsupported child")
            actual[(selected_class, child.get("name"))] += 1
        elif child.tag == "properties":
            require(all(node.tag == "property" and len(node) == 0 for node in child), "unsupported XML properties")
        else:
            require(child.tag in {"system-out", "system-err"} and len(child) == 0, "unsupported XML suite child")
    require(sum(actual.values()) == counts["tests"], "XML declared test total differs from actual testcases")
    require(all(count == 1 for count in actual.values()), "duplicate XML testcase")
    return actual


def verify(inventory_path, reports_path):
    inventory_path, reports_path = build_path(inventory_path), build_path(reports_path)
    inventory_bytes = read_bounded(inventory_path, MAX_INVENTORY_BYTES)
    inventory, expected = load_inventory(inventory_bytes)
    require(reports_path.is_dir(), "report directory is absent")
    files = {}
    with os.scandir(reports_path) as entries:
        for index, entry in enumerate(entries):
            require(index < 4096, "report directory exceeds its entry bound")
            if entry.name.startswith("TEST") and entry.name.endswith(".xml"):
                require(entry.is_file(follow_symlinks=False), "XML report is not a regular file")
                files[entry.name] = Path(entry.path)
    expected_files = {f"TEST-{name}.xml": name for name in inventory["classes"]}
    require(set(files) == set(expected_files),
            f"report file membership differs; missing={sorted(set(expected_files) - set(files))}, "
            f"unexpected={sorted(set(files) - set(expected_files))}")
    actual = Counter()
    reports = []
    total_bytes = 0
    for filename, name in sorted(expected_files.items()):
        payload = read_bounded(files[filename], MAX_REPORT_BYTES)
        total_bytes += len(payload)
        require(total_bytes <= MAX_TOTAL_REPORT_BYTES, "XML reports exceed their aggregate byte bound")
        cases = read_report(payload, name)
        actual.update(cases)
        reports.append({"file": filename, "class": name, "testCount": sum(cases.values())})
    require(actual == expected,
            f"live test membership differs; missing={sorted((expected - actual).elements())}, "
            f"unexpected={sorted((actual - expected).elements())}")
    return {
        "schemaVersion": 1, "provider": "contained-module-compilation-live-test-verification-v1", "status": "passed",
        "inventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "classCount": len(inventory["classes"]), "testCount": sum(actual.values()), "reportCount": len(reports),
        "failures": 0, "errors": 0, "skipped": 0, "reports": reports,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--reports", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        output = build_path(arguments.output)
        require(not output.exists(), "coverage summary must be fresh")
        summary = verify(arguments.inventory, arguments.reports)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(summary, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
        print(f"Verified {summary['testCount']} compiled ci-live tests across {summary['classCount']} classes; zero skips")
        return 0
    except (ValueError, OSError) as failure:
        print(f"module compilation live coverage rejected: {failure}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
