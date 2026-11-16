#!/usr/bin/env python3
"""Initialize authored case expectations, then reconcile actual hosted artifacts.

initialize --directory DIR --run-id ID --run-attempt ATTEMPT runs before prerequisites.
finalize --directory DIR --inventory FILE --reports DIR --gradle-exit-code CODE
         --phase PHASE runs even after failure; CODE may be "not-started".

The finalizer publishes a fresh case-summary.json and returns success only for all
13 completed cases, intact raw files, the existing exact inventory/XML gate, and
an actual zero Gradle exit. The caller must preserve its original nonzero status.
This is artifact reconciliation, not a runtime capability or a replacement for
the live methods' assertions. Authored expectations never imply execution.
"""

import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_CASE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 64
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 32768
MAX_PATH_BYTES = 512
MAX_PATH_SEGMENTS = 16
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
STAGE = re.compile(r"[a-z][a-z0-9-]{0,63}")
PHASES = {"initialization", "prerequisites", "configuration", "live-gradle", "xml-verification", "complete"}
CASE_PROVIDER = "contained-module-hosted-case-v1"
INDEX_PROVIDER = "contained-module-hosted-case-index-v1"
SUMMARY_PROVIDER = "contained-module-hosted-case-reconciliation-v1"
MODULE_CLASS = "decompengine.project.ContainedModuleCompilationLiveTest"
TERMINAL_CLASS = "decompengine.oracle.fulltree.ContainedCommandTerminalResourceLiveTest"
VISIBILITY_CLASS = "decompengine.oracle.fulltree.ContainedCommandRetainedInputVisibilityTest"
MODULE_METHODS = (
    ("exact-snapshot", "real compilation issues live authority only for the exact current source and header snapshot"),
    ("source-tree-rejection", "real compiler rejection preserves the earlier accepted SourceTree revision and checkpoint"),
    ("source-tree-cancellation", "interrupting an observed real compiler restores prior acceptance and removes its processes scope and scratch"),
    ("output-refusal", "configured module output refusal preserves acceptance and permits a clean retry"),
    ("inherited-hard-refusal", "unsupported inherited descriptor hard limit refuses before module START and preserves acceptance"),
)
EXPECTED_CASES = tuple(
    {"caseId": f"module-{profile}-{suffix}", "testClass": MODULE_CLASS,
     "testMethod": method, "profileId": f"generated-c-{profile}-v1"}
    for profile in ("make", "ninja") for suffix, method in MODULE_METHODS
) + (
    {"caseId": "generic-default-512", "testClass": TERMINAL_CLASS,
     "testMethod": "strict generic command accepts clean exit and rejects handled task limit with zero exit",
     "profileId": None},
    {"caseId": "generic-visibility-v4", "testClass": TERMINAL_CLASS,
     "testMethod": "configured visibility only command retains selected files and proves owned cleanup", "profileId": None},
    {"caseId": "generated-visibility-canaries", "testClass": VISIBILITY_CLASS,
     "testMethod": "actual generated strict namespaces hide every forbidden sibling and preserve only bounded active writes",
     "profileId": None},
)
FIXED_SOURCE_PATHS = (
    "src/main/kotlin/decompengine/oracle/fulltree/ContainedCommandFileDescriptorPolicy.kt",
    "src/main/kotlin/decompengine/oracle/fulltree/ContainedCommandTerminalResourceEvidence.kt",
    "src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationIsolatedRunner.kt",
    "src/main/kotlin/decompengine/oracle/fulltree/KotlinContainedCommandProtocol.kt",
    "src/main/kotlin/decompengine/project/ContainedModuleCompilationPolicy.kt",
    "src/main/kotlin/decompengine/project/ContainedModuleCompilationProof.kt",
    "src/test/kotlin/decompengine/oracle/fulltree/ContainedCommandTerminalResourceLiveTest.kt",
    "src/test/kotlin/decompengine/oracle/fulltree/ContainedCommandRetainedInputVisibilityTest.kt",
    "src/test/kotlin/decompengine/project/ContainedModuleCompilationLiveTest.kt",
    "src/test/kotlin/decompengine/project/ContainedModuleHostedCase.kt",
    "scripts/module-compilation-live-classes.txt",
    "scripts/module-compilation-qualification.init.gradle",
    "scripts/qualify-contained-module-compilation.sh",
    "scripts/verify-module-compilation-live-tests.py",
    "scripts/reconcile-module-compilation-hosted-cases.py",
    ".github/workflows/module-compilation-qualification.yml",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def bounded_integer(value):
    require(len(value) <= 20, "JSON integer exceeds its token bound")
    return int(value)


def reject_number(_value):
    raise ValueError("non-integer JSON number is unsupported")


def parse_json(payload):
    require(0 < len(payload) <= MAX_METADATA_BYTES, "JSON metadata exceeds its byte bound")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_int=bounded_integer, parse_float=reject_number, parse_constant=reject_number)
        pending, count = [(value, 0)], 0
        while pending:
            node, depth = pending.pop()
            count += 1
            require(count <= MAX_JSON_NODES and depth <= MAX_JSON_DEPTH, "JSON structure exceeds its bound")
            if type(node) is dict:
                pending.extend((child, depth + 1) for pair in node.items() for child in pair)
            elif type(node) is list:
                pending.extend((child, depth + 1) for child in node)
            elif type(node) is str:
                require(not any(0xD800 <= ord(char) <= 0xDFFF for char in node), "JSON contains an unpaired surrogate")
        return value
    except (UnicodeError, RecursionError, json.JSONDecodeError) as failure:
        raise ValueError("metadata is not bounded valid UTF-8 JSON") from failure


def exact_fields(value, fields, location):
    require(type(value) is dict and set(value) == set(fields), f"unexpected fields at {location}")


def relative_parts(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= MAX_PATH_BYTES and "\\" not in value,
            "invalid relative artifact path")
    parts = value.split("/")
    require(len(parts) <= MAX_PATH_SEGMENTS and all(
        part not in {"", ".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
        for part in parts), "noncanonical relative artifact path")
    return parts


def build_path(value):
    raw = os.fspath(value)
    require(type(raw) is str and "\x00" not in raw and ".." not in Path(raw).parts,
            "invalid build artifact path")
    path = Path(os.path.abspath(raw))
    require(path != ROOT / "build" and path.is_relative_to(ROOT / "build"),
            "artifacts must belong to checkout/build")
    return path


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def directory_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid)


class Directory:
    """Pin each absolute ancestor; never resolve symlinks or open special leaves."""

    def __init__(self, path, create=False):
        self.path = Path(path)
        self.fds, self.links = [], []
        try:
            require(self.path.is_absolute(), "directory path must be absolute")
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.fds.append(descriptor)
            for part in self.path.parts[1:]:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                self.fds.append(child)
                self.links.append((descriptor, part, child, directory_identity(os.fstat(child))))
                descriptor = child
            self.fd = descriptor
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_unused):
        self.close()

    def close(self):
        for descriptor in reversed(self.fds):
            os.close(descriptor)
        self.fds = []

    def recheck(self):
        for parent, name, child, original in self.links:
            require(directory_identity(os.fstat(child)) == original and
                    directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original,
                    "directory ancestry changed during reconciliation")

    @contextmanager
    def parent_of(self, name):
        parts = relative_parts(name)
        opened, links = [], []
        parent = self.fd
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                opened.append(child)
                links.append((parent, part, child, directory_identity(os.fstat(child))))
                parent = child
            yield parent, parts[-1]
            for ancestor, part, child, original in links:
                require(directory_identity(os.fstat(child)) == original and
                        directory_identity(os.stat(part, dir_fd=ancestor, follow_symlinks=False)) == original,
                        "artifact ancestry changed during read")
            self.recheck()
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def read(self, name, limit, minimum=0):
        with self.parent_of(name) as (parent, leaf):
            descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                        "artifact must be a single-link regular file")
                require(minimum <= before.st_size <= limit, "artifact exceeds its byte bound")
                chunks, remaining = [], before.st_size + 1
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                payload = b"".join(chunks)
                require(len(payload) == before.st_size and identity(os.fstat(descriptor)) == identity(before) and
                        identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == identity(before),
                        "artifact changed during descriptor read")
                return payload
            finally:
                os.close(descriptor)

    def names(self, limit):
        names = []
        with os.scandir(self.fd) as entries:
            for entry in entries:
                require(len(names) < limit, "directory entry count exceeds its bound")
                relative_parts(entry.name)
                names.append(entry.name)
        self.recheck()
        return set(names)

    def census(self):
        rows = {}

        def visit(descriptor, prefix):
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    name = prefix + entry.name
                    relative_parts(name)
                    require(len(rows) < MAX_MEMBERS * MAX_PATH_SEGMENTS + 1, "case entry census exceeds its bound")
                    metadata = entry.stat(follow_symlinks=False)
                    rows[name] = identity(metadata)
                    if stat.S_ISDIR(metadata.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=descriptor)
                        try:
                            require(identity(os.fstat(child)) == identity(metadata), "directory changed during census")
                            visit(child, name + "/")
                            require(identity(os.fstat(child)) == identity(metadata) and
                                    identity(os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)) == identity(metadata),
                                    "directory changed during census")
                        finally:
                            os.close(child)
                    else:
                        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                                "case census contains a linked or nonregular member")

        visit(self.fd, "")
        self.recheck()
        return rows

    def publish(self, name, value, limit=MAX_METADATA_BYTES):
        relative_parts(name)
        require("/" not in name, "publication must be a direct directory member")
        payload = canonical(value)
        require(len(payload) <= limit, "publication exceeds metadata byte bound")
        temporary = ".reconcile-" + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.fd)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self.recheck()
            # link is an atomic no-replace publication of the complete bytes.
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
        finally:
            os.unlink(temporary, dir_fd=self.fd)
        os.fsync(self.fd)
        self.recheck()


def run_identity(run_id, run_attempt):
    require(type(run_id) is str and re.fullmatch(r"[1-9][0-9]{0,19}", run_id), "invalid Actions run id")
    require(type(run_attempt) is str and re.fullmatch(r"[1-9][0-9]{0,8}", run_attempt), "invalid Actions run attempt")
    return {"id": run_id, "attempt": int(run_attempt)}


def current_run():
    return run_identity(os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT"))


def git_output(*arguments):
    # Commands return only fixed-size identities, the bounded selected path list,
    # or no output. No network, hooks, pager or external diff is involved.
    result = subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", *arguments],
                            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    require(result.returncode == 0, "source checkout command refused or tracked source is dirty")
    require(len(result.stdout) <= MAX_METADATA_BYTES and len(result.stderr) <= MAX_METADATA_BYTES,
            "source checkout command output exceeds its bound")
    return result.stdout


def source_identity():
    git_output("diff", "--no-ext-diff", "--quiet", "HEAD", "--")
    identities = git_output("rev-parse", "HEAD", "HEAD^{tree}").decode("ascii").splitlines()
    require(len(identities) == 2 and all(GIT_SHA1.fullmatch(value) for value in identities), "invalid Git source identities")
    project_directory = ROOT / "src/test/kotlin/decompengine/project"
    with Directory(project_directory) as directory:
        discovered = {
            "src/test/kotlin/decompengine/project/" + name
            for name in directory.names(4096)
            if re.fullmatch(r"ContainedModule[A-Za-z0-9]*Hosted[A-Za-z0-9]*\.kt", name)
        }
    paths = sorted(set(FIXED_SOURCE_PATHS) | discovered)
    require(len(paths) <= MAX_SOURCE_FILES, "source pin population exceeds its bound")
    tracked = git_output("ls-files", "--stage", "-z", "--", *paths).split(b"\x00")
    entries = {}
    for entry in tracked:
        if not entry:
            continue
        description, path_bytes = entry.split(b"\t", 1)
        mode, blob, stage = description.decode("ascii").split(" ")
        path = path_bytes.decode("utf-8")
        require(path not in entries and mode in {"100644", "100755"} and stage == "0" and GIT_SHA1.fullmatch(blob),
                "source pin is unmerged or not a tracked regular file")
        entries[path] = blob
    require(set(entries) == set(paths), "a required source pin is absent or untracked")
    files, total = [], 0
    with Directory(ROOT) as directory:
        for path in paths:
            payload = directory.read(path, MAX_SOURCE_BYTES, 1)
            total += len(payload)
            require(total <= MAX_TOTAL_SOURCE_BYTES, "source pins exceed their aggregate byte bound")
            require(hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest() == entries[path],
                    "source bytes differ from tracked checkpoint")
            files.append({"path": path, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    git_output("diff", "--no-ext-diff", "--quiet", "HEAD", "--")
    require(git_output("rev-parse", "HEAD", "HEAD^{tree}").decode("ascii").splitlines() == identities,
            "source checkout changed during pinning")
    return {"commit": identities[0], "treeSha1": identities[1], "files": files}


def initialize(directory, run_id, run_attempt):
    path = build_path(directory)
    run = run_identity(run_id, run_attempt)
    require(run == current_run(), "initialization run differs from current Actions identity")
    source = source_identity()
    with Directory(path, create=True) as pinned:
        require(not pinned.names(1), "case directory must be empty before initialization")
        index = {"schemaVersion": 1, "provider": INDEX_PROVIDER, "run": run,
                 "source": source, "cases": list(EXPECTED_CASES)}
        pinned.publish("expected-case-index.json", index)
    return index


def bounded_failure(failure):
    message = str(failure)
    return {"type": type(failure).__name__,
            "message": "".join(char if 32 <= ord(char) < 127 else "?" for char in message[:1024])}


def validate_case(record, expected):
    exact_fields(record, {"schemaVersion", "provider", "caseId", "testClass", "testMethod", "profileId",
                          "status", "stage", "artifacts", "failure"}, "case")
    require(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1 and
            record["provider"] == CASE_PROVIDER, "unsupported case schema or provider")
    require(all(record[key] == value and type(record[key]) is type(value) for key, value in expected.items()),
            "case identity differs from authored expectation")
    require(type(record["status"]) is str and record["status"] in {"running", "passed", "failed"}, "invalid case status")
    require(type(record["stage"]) is str and STAGE.fullmatch(record["stage"]), "invalid bounded case stage")
    if record["status"] == "failed":
        exact_fields(record["failure"], {"type", "message"}, "case failure")
        require(all(type(record["failure"][key]) is str and 1 <= len(record["failure"][key].encode("utf-8")) <= 1024 and
                    all(ord(char) >= 32 and ord(char) != 127 for char in record["failure"][key])
                    for key in ("type", "message")), "invalid sanitized case failure")
    else:
        require(record["failure"] is None, "nonfailed case has a failure record")
    rows = record["artifacts"]
    require(type(rows) is list and len(rows) <= MAX_MEMBERS, "invalid artifact population")
    paths, total = set(), 0
    for row in rows:
        exact_fields(row, {"path", "bytes", "sha256"}, "artifact")
        parts = relative_parts(row["path"])
        require(parts[0] != "case.json" and row["path"] not in paths, "duplicate or reserved artifact path")
        paths.add(row["path"])
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_MEMBER_BYTES and
                type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]), "invalid artifact length or digest")
        total += row["bytes"]
        require(total <= MAX_CASE_BYTES, "case artifacts exceed their aggregate byte bound")
    if record["status"] == "passed":
        require(rows and total > 0, "passed case requires nonempty raw evidence")
        require(record["stage"] != "initializing", "passed case did not leave its initial stage")


def reconcile_case(path, expected):
    result = {"expected": expected, "recordStatus": "absent", "reconciliationStatus": "not-started",
              "record": None, "recordSha256": None, "verifiedArtifacts": [], "errors": []}
    try:
        with Directory(path / expected["caseId"]) as directory:
            result["recordStatus"] = None
            result["reconciliationStatus"] = "incomplete"
            census = directory.census()
            payload = directory.read("case.json", MAX_METADATA_BYTES, 1)
            result["recordSha256"] = hashlib.sha256(payload).hexdigest()
            record = parse_json(payload)
            if type(record) is dict and type(record.get("status")) is str and record["status"] in {"running", "passed", "failed"}:
                result["recordStatus"] = record["status"]
            validate_case(record, expected)
            # Invalid arbitrary JSON remains on disk with its raw digest; do not
            # duplicate unvalidated strings/structure into the bounded summary.
            result["record"] = record
            expected_names = {"case.json"}
            for row in record["artifacts"]:
                parts = relative_parts(row["path"])
                expected_names.update("/".join(parts[:end]) for end in range(1, len(parts) + 1))
                payload = directory.read(row["path"], MAX_MEMBER_BYTES)
                require(len(payload) == row["bytes"] and hashlib.sha256(payload).hexdigest() == row["sha256"],
                        "raw artifact length or digest differs")
                result["verifiedArtifacts"].append(row)
            require(set(census) == expected_names, "raw case file census differs from recorded artifacts")
            require(directory.census() == census, "case directory changed during reconciliation")
            result["_snapshot"] = (identity(os.fstat(directory.fd)), census)
            result["reconciliationStatus"] = {"running": "incomplete", "failed": "failed", "passed": "passed"}[record["status"]]
    except FileNotFoundError as failure:
        # Only a missing case directory is genuinely not started. A present case
        # with missing metadata/raw bytes remains incomplete and diagnostic.
        if result["recordStatus"] != "absent":
            result["errors"].append(bounded_failure(failure))
            if result["record"] is not None:
                result["reconciliationStatus"] = "invalid"
    except (ValueError, OSError) as failure:
        result["reconciliationStatus"] = "invalid"
        result["errors"].append(bounded_failure(failure))
    return result


def coverage_verifier():
    spec = importlib.util.spec_from_file_location("module_compilation_live_coverage",
                                                ROOT / "scripts/verify-module-compilation-live-tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_coverage(inventory_path, reports_path):
    """Use the unchanged gate, bracketed by stable reads of its exact inputs."""
    inventory_path, reports_path = build_path(inventory_path), build_path(reports_path)
    verifier = coverage_verifier()
    with Directory(inventory_path.parent) as inventory_directory, Directory(reports_path) as reports_directory:
        inventory_bytes = inventory_directory.read(inventory_path.name, verifier.MAX_INVENTORY_BYTES, 1)
        inventory, expected = verifier.load_inventory(inventory_bytes)
        require({(case["testClass"], case["testMethod"] + "()") for case in EXPECTED_CASES} <= set(expected),
                "compiled inventory omits a required hosted case method")
        filenames = {f"TEST-{name}.xml": name for name in inventory["classes"]}
        names = reports_directory.names(4096)
        require({name for name in names if name.startswith("TEST") and name.endswith(".xml")} == set(filenames),
                "report file membership differs")
        snapshots, total = {}, 0
        actual = Counter()
        for filename, class_name in sorted(filenames.items()):
            payload = reports_directory.read(filename, verifier.MAX_REPORT_BYTES, 1)
            total += len(payload)
            require(total <= verifier.MAX_TOTAL_REPORT_BYTES, "XML reports exceed their aggregate byte bound")
            actual.update(verifier.read_report(payload, class_name))
            snapshots[filename] = hashlib.sha256(payload).hexdigest()
        require(actual == expected, "live test membership differs from compiled inventory")
        verified = verifier.verify(inventory_path, reports_path)
        require(verified["inventorySha256"] == hashlib.sha256(inventory_bytes).hexdigest(), "inventory changed in XML gate")
        require(inventory_directory.read(inventory_path.name, verifier.MAX_INVENTORY_BYTES, 1) == inventory_bytes and
                reports_directory.names(4096) == names, "coverage input membership changed during verification")
        for filename, digest in snapshots.items():
            require(hashlib.sha256(reports_directory.read(filename, verifier.MAX_REPORT_BYTES, 1)).hexdigest() == digest,
                    "XML report changed during verification")
        return verified


def finalize(directory, inventory, reports, gradle_exit_code, phase):
    path = build_path(directory)
    require(gradle_exit_code is None or type(gradle_exit_code) is int and 0 <= gradle_exit_code <= 255,
            "invalid Gradle exit code")
    require(type(phase) is str and phase in PHASES, "unsupported finalization phase")
    summary = {"schemaVersion": 1, "provider": SUMMARY_PROVIDER, "status": "incomplete", "phase": phase,
               "gradleExitCode": gradle_exit_code, "run": None, "expectedIndexSha256": None,
               "source": None, "cases": [], "errors": [], "coverage": None}
    with Directory(path) as pinned:
        try:
            os.stat("case-summary.json", dir_fd=pinned.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("case summary must be fresh")
        initialized_payload = None
        try:
            payload = pinned.read("expected-case-index.json", MAX_METADATA_BYTES, 1)
            summary["expectedIndexSha256"] = hashlib.sha256(payload).hexdigest()
            index = parse_json(payload)
            exact_fields(index, {"schemaVersion", "provider", "run", "source", "cases"}, "expected index")
            require(type(index["schemaVersion"]) is int and index["schemaVersion"] == 1 and index["provider"] == INDEX_PROVIDER,
                    "unsupported expected index schema or provider")
            require(canonical(index["cases"]) == canonical(list(EXPECTED_CASES)), "authored expected case population changed")
            run = current_run()
            summary["run"] = run
            require(canonical(index["run"]) == canonical(run), "expected index belongs to a different Actions run or attempt")
            source = source_identity()
            summary["source"] = source
            require(canonical(index["source"]) == canonical(source), "expected index source checkpoint changed")
            require(canonical(index) == payload, "expected index bytes are not canonical initialization bytes")
            initialized_payload = payload
        except (ValueError, OSError, subprocess.SubprocessError) as failure:
            summary["errors"].append(bounded_failure(failure))
        for expected in EXPECTED_CASES:
            summary["cases"].append(reconcile_case(path, expected))
        try:
            allowed_names = {"expected-case-index.json"} | {case["caseId"] for case in EXPECTED_CASES}
            require(pinned.names(64) <= allowed_names, "unexpected case directory member")
        except (ValueError, OSError) as failure:
            summary["errors"].append(bounded_failure(failure))
        try:
            summary["coverage"] = verify_coverage(inventory, reports)
        except (ValueError, OSError) as failure:
            summary["errors"].append(bounded_failure(failure))
        for case in summary["cases"]:
            snapshot = case.pop("_snapshot", None)
            if snapshot is not None:
                try:
                    with Directory(path / case["expected"]["caseId"]) as directory:
                        require((identity(os.fstat(directory.fd)), directory.census()) == snapshot,
                                "case snapshot changed before final publication")
                except (ValueError, OSError) as failure:
                    case["reconciliationStatus"] = "invalid"
                    case["errors"].append(bounded_failure(failure))
        if initialized_payload is not None:
            try:
                require(pinned.read("expected-case-index.json", MAX_METADATA_BYTES, 1) == initialized_payload,
                        "expected index changed during finalization")
                require(source_identity() == summary["source"] and current_run() == summary["run"],
                        "source or run changed during finalization")
            except (ValueError, OSError, subprocess.SubprocessError) as failure:
                summary["errors"].append(bounded_failure(failure))
        if gradle_exit_code == 0 and not summary["errors"] and all(
                case["reconciliationStatus"] == "passed" for case in summary["cases"]):
            summary["status"] = "passed"
        pinned.publish("case-summary.json", summary, MAX_SUMMARY_BYTES)
    return summary


def exit_code(value):
    if value == "not-started":
        return None
    if re.fullmatch(r"0|[1-9][0-9]{0,2}", value) and int(value) <= 255:
        return int(value)
    raise argparse.ArgumentTypeError("Gradle exit code must be 0..255 or not-started")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initializer = commands.add_parser("initialize")
    initializer.add_argument("--directory", required=True, type=Path)
    initializer.add_argument("--run-id", required=True)
    initializer.add_argument("--run-attempt", required=True)
    finalizer = commands.add_parser("finalize")
    finalizer.add_argument("--directory", required=True, type=Path)
    finalizer.add_argument("--inventory", required=True, type=Path)
    finalizer.add_argument("--reports", required=True, type=Path)
    finalizer.add_argument("--gradle-exit-code", required=True, type=exit_code)
    finalizer.add_argument("--phase", required=True, choices=sorted(PHASES))
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "initialize":
            initialize(arguments.directory, arguments.run_id, arguments.run_attempt)
            return 0
        summary = finalize(arguments.directory, arguments.inventory, arguments.reports,
                           arguments.gradle_exit_code, arguments.phase)
        if summary["status"] == "passed":
            print("Reconciled all 13 hosted cases and exact compiled-test XML coverage")
            return 0
        print("Hosted case reconciliation is incomplete; retained case-summary.json", file=sys.stderr)
        return 1
    except (ValueError, OSError, subprocess.SubprocessError) as failure:
        print(f"Hosted case reconciliation refused: {bounded_failure(failure)['message']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
