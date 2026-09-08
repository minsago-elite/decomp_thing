#!/usr/bin/env python3
"""Lexical regression gate for reconstruction neutrality (#84)."""

from __future__ import annotations

import argparse
import bisect
import json
import re
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

MAXIMUM_PATHS = 20_000
MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 128 * 1024 * 1024
TEXT_SUFFIXES = {".kt", ".java", ".kts", ".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".properties", ".txt", ".c", ".h"}
RULES = {
    "benchmark-version": re.compile(r"\b(?:gcc[-_/ :]\s*|gcc_version=)[0-9]+(?:\.[0-9]+){1,2}\b", re.IGNORECASE),
    "benchmark-target": re.compile(r'''["'](?:cc1|cc1plus|lto1|gcc-(?:elf-)?driver|gcc-compiler-engines?)(?:-v[0-9]+)?["']'''),
    "generic-suffix": re.compile(r'''(?:endsWith|removeSuffix|matches|glob)\s*\(\s*["'](?:\*|\\)?\.(?:c|h)["']'''),
    "generic-layout": re.compile(r'''["'](?:Makefile|build/reconstructed(?:/[^"'\r\n]*)?|(?:src|include)(?:/[^"'\r\n]*)?)["']'''),
    "generic-tool": re.compile(r'''["'](?:make|ninja|gcc|cc|clang|clang\+\+)["']'''),
    "generic-compiler-flag": re.compile(r"(?<![A-Za-z0-9_])-(?:std=c[A-Za-z0-9+]*|Werror|Wall|Wextra|fsyntax-only|Iinclude)\b"),
    "generic-adapter-reference": re.compile(r"\b(?:GeneratedC[A-Za-z0-9_]*|MakeProjectBuilder|ProjectBuildConfiguration|RecoveredCModuleReconstructor)\b"),
}
RULE_IDS = set(RULES) | {"benchmark-hash"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    text: str


@dataclass
class ScanResult:
    scanned_files: int
    scanned_bytes: int
    findings: list[Finding]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def normalized_path(value: object) -> str:
    require(isinstance(value, str) and bool(value), "policy path must be a nonempty string")
    path = PurePosixPath(value)
    require(bool(path.parts) and value != "." and not path.is_absolute() and path.as_posix() == value and
            all(part not in {".", ".."} for part in path.parts) and "\\" not in value and
            not any(ord(char) < 32 for char in value), f"policy path is not normalized: {value!r}")
    return value


def within(path: str, roots: list[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def regular_path(root: Path, relative: str, *, directory_allowed: bool = False) -> Path:
    path = root
    parts = PurePosixPath(normalized_path(relative)).parts
    for index, part in enumerate(parts):
        path = path / part
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise PolicyError(f"scan path is unavailable: {relative}") from error
        last = index == len(parts) - 1
        require(stat.S_ISDIR(mode) if not last else
                (stat.S_ISREG(mode) or directory_allowed and stat.S_ISDIR(mode)),
                f"scan path is indirect or has an unsupported file type: {relative}")
    return path


def read_text(root: Path, relative: str) -> tuple[str, int]:
    path = regular_path(root, relative)
    with path.open("rb") as stream:
        data = stream.read(MAXIMUM_FILE_BYTES + 1)
    require(len(data) <= MAXIMUM_FILE_BYTES, f"scan file exceeds its byte bound: {relative}")
    return data.decode("utf-8", errors="strict"), len(data)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate policy JSON field: {key}")
        result[key] = value
    return result


def read_json(root: Path, relative: str) -> dict:
    result = json.loads(read_text(root, relative)[0], object_pairs_hook=unique_object)
    require(isinstance(result, dict), f"policy document must be an object: {relative}")
    return result


def exact_fields(value: object, fields: set[str], subject: str) -> None:
    require(isinstance(value, dict) and set(value) == fields, f"unsupported {subject} fields")


def reason(value: object) -> None:
    require(isinstance(value, str) and bool(value.strip()), "policy exception must explain its ownership")


def load_policy(root: Path, relative: str) -> tuple[dict, re.Pattern]:
    policy = read_json(root, normalized_path(relative))
    exact_fields(policy, {"schemaVersion", "genericRoots", "benchmarkRoots", "adapterFiles", "allowances", "benchmarkCatalog"}, "neutrality policy")
    require(type(policy["schemaVersion"]) is int and policy["schemaVersion"] == 1, "unsupported neutrality policy schema")
    for name in ("genericRoots", "benchmarkRoots"):
        roots = policy[name]
        require(isinstance(roots, list) and roots, f"{name} must be a nonempty list")
        for item in roots:
            regular_path(root, normalized_path(item), directory_allowed=True)
        require(len(roots) == len(set(roots)), f"{name} contains duplicate roots")
        require(not any(a != b and a.startswith(b + "/") for a in roots for b in roots), f"{name} contains overlapping roots")
    require(set(policy["genericRoots"]).isdisjoint(policy["benchmarkRoots"]),
            "genericRoots and benchmarkRoots must be disjoint")
    require(isinstance(policy["adapterFiles"], list), "adapterFiles must be a list")
    adapters = set()
    for entry in policy["adapterFiles"]:
        exact_fields(entry, {"path", "reason"}, "adapter ownership")
        path = normalized_path(entry["path"])
        reason(entry["reason"])
        regular_path(root, path)
        require(within(path, policy["genericRoots"]) and path not in adapters, f"duplicate or out-of-scope adapter ownership: {path}")
        adapters.add(path)
    require(isinstance(policy["allowances"], list), "allowances must be a list")
    seen = set()
    for entry in policy["allowances"]:
        exact_fields(entry, {"path", "rule", "fragment", "count", "reason"}, "literal allowance")
        path = normalized_path(entry["path"])
        regular_path(root, path)
        require(isinstance(entry["rule"], str) and entry["rule"] in RULE_IDS, "allowance has an unknown rule")
        require(isinstance(entry["fragment"], str) and bool(entry["fragment"]), "allowance fragment must be nonempty")
        require(type(entry["count"]) is int and entry["count"] > 0, "allowance count must be positive")
        reason(entry["reason"])
        key = (path, entry["rule"], entry["fragment"])
        require(key not in seen, f"duplicate literal allowance: {path}")
        seen.add(key)
    catalog_path = normalized_path(policy["benchmarkCatalog"])
    require(within(catalog_path, policy["benchmarkRoots"]), "benchmark identity catalog must have benchmark ownership")
    catalog = read_json(root, catalog_path)
    exact_fields(catalog, {"schemaVersion", "identities"}, "benchmark catalog")
    require(type(catalog["schemaVersion"]) is int and catalog["schemaVersion"] == 1 and
            isinstance(catalog["identities"], list) and catalog["identities"], "unsupported or empty benchmark catalog")
    hashes, names = set(), set()
    for entry in catalog["identities"]:
        exact_fields(entry, {"name", "sha256"}, "benchmark identity")
        require(isinstance(entry["name"], str) and bool(entry["name"].strip()) and entry["name"] not in names, "benchmark identity name is missing or duplicated")
        require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None and entry["sha256"] not in hashes,
                "benchmark identity digest is invalid or duplicated")
        names.add(entry["name"])
        hashes.add(entry["sha256"])
    return policy, re.compile(r"(?<![0-9a-f])(?:" + "|".join(sorted(hashes)) + r")(?![0-9a-f])", re.IGNORECASE)


def inventory(root: Path) -> list[str]:
    result = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    paths = sorted(set(result.stdout.decode("utf-8", errors="strict").rstrip("\0").split("\0")) - {""})
    require(len(paths) <= MAXIMUM_PATHS, "repository scan exceeds its path bound")
    return [normalized_path(path) for path in paths]


def scan_repository(root: Path, policy_path: str = "oracle/gcc/reconstruction-neutrality-policy.json") -> ScanResult:
    root = root.resolve()
    policy, hashes = load_policy(root, policy_path)
    adapters = {entry["path"] for entry in policy["adapterFiles"]}
    allowances = policy["allowances"]
    matched_allowances = set()
    result = ScanResult(0, 0, [])
    rules = RULES | {"benchmark-hash": hashes}
    for relative in inventory(root):
        path = PurePosixPath(relative)
        # Markdown documentation is an explicit exception in #84; unsupported binary formats are not decoded.
        if path.suffix.lower() not in TEXT_SUFFIXES and not (
                path.name == "Dockerfile" or path.name.startswith("Dockerfile.") or path.suffix == ".Dockerfile"):
            continue
        benchmark_owned = within(relative, policy["benchmarkRoots"])
        generic = within(relative, policy["genericRoots"]) and relative not in adapters
        selected = {name: pattern for name, pattern in rules.items()
                    if generic and name.startswith("generic-") or not benchmark_owned and name.startswith("benchmark-")}
        if not selected:
            continue
        # Git's cached inventory retains ordinary unstaged deletions. Policy-owned
        # paths are checked separately by load_policy and still must exist.
        try:
            (root / relative).lstat()
        except FileNotFoundError:
            continue
        content, size = read_text(root, relative)
        result.scanned_files += 1
        result.scanned_bytes += size
        require(result.scanned_bytes <= MAXIMUM_TOTAL_BYTES, "repository scan exceeds its aggregate byte bound")
        line_starts = [0] + [match.end() for match in re.finditer("\n", content)]
        spans: dict[str, list[tuple[int, int, int]]] = {}
        all_spans: list[tuple[int, int, int]] = []
        for index, entry in enumerate(allowances):
            if entry["path"] != relative:
                continue
            require(entry["rule"] in selected, f"allowance is outside checked rules: {relative}: {entry['rule']}")
            occurrences = list(re.finditer(re.escape(entry["fragment"]), content))
            require(len(occurrences) == entry["count"], f"stale allowance count: {relative}: {entry['rule']}: expected {entry['count']}, found {len(occurrences)}")
            existing = spans.setdefault(entry["rule"], [])
            for occurrence in occurrences:
                require(not any(occurrence.start() < end and start < occurrence.end() for start, end, _ in all_spans),
                        f"overlapping literal allowances: {relative}: {entry['rule']}")
                span = (occurrence.start(), occurrence.end(), index)
                existing.append(span)
                all_spans.append(span)
        for name, pattern in selected.items():
            for match in pattern.finditer(content):
                permitted = [index for start, end, index in spans.get(name, []) if start <= match.start() and match.end() <= end]
                if permitted:
                    matched_allowances.update(permitted)
                else:
                    result.findings.append(Finding(relative, bisect.bisect_right(line_starts, match.start()), name, match.group()[:200]))
    require(matched_allowances == set(range(len(allowances))),
            "unused literal allowances: " + ", ".join(f"{entry['path']} ({entry['rule']})" for index, entry in enumerate(allowances) if index not in matched_allowances))
    result.findings.sort(key=lambda finding: (finding.path, finding.line, finding.rule, finding.text))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--policy", default="oracle/gcc/reconstruction-neutrality-policy.json")
    parser.add_argument("--json", action="store_true", help="print structured findings")
    arguments = parser.parse_args()
    try:
        result = scan_repository(arguments.root, arguments.policy)
    except (PolicyError, OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}) if arguments.json else f"ERROR: {error}")
        return 2
    if arguments.json:
        print(json.dumps(asdict(result), sort_keys=True))
    else:
        for finding in result.findings:
            print(f"{finding.path}:{finding.line}: {finding.rule}: {finding.text}")
        status = "FAIL" if result.findings else "PASS"
        print(f"{status}: {len(result.findings)} lexical neutrality findings in {result.scanned_files} files ({result.scanned_bytes} bytes)")
        print("Scope: supported source/scripts/resources; benchmark namespaces and Markdown exempt; generic rules use declared roots and exact adapter ownership.")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
