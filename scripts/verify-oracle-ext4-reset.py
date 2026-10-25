#!/usr/bin/env python3
"""Gate the exact actual ext4 reset controls and their retained fixture evidence.

This verifies evidence consistency, not producer authenticity. The hosted workflow
must separately bind these bytes to its successful run, job, and source commit.
Pure mutation tests of this gate never count as actual kernel qualification.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET


CLASS = "decompengine.oracle.fulltree.FullTreeDiskScratchResetMountedTest"
PROFILE = "oracle-ext4-quarantine-reset-v1"
REQUIRED = (
    "K01 root private image and raw device deny oracle access",
    "K02 independent lease children contend and reset preserves live canary",
    "K03 killed lease child resets to a new admitted generation",
    "K04 sparse and deep residue resets with bounded work",
    "K05 byte exhaustion resets to fresh availability",
    "K06 inode exhaustion resets to fresh availability",
    "K07 live filesystem descriptors block unmount until holder reap",
    "K08 hidden mount namespace blocks exclusive format until holder reap",
    "K09 concurrent service request cannot overlap custodian",
    "K10 concurrent loop allocation preserves bound slot identity",
    "K11 killed controller leaves custodian custody intact",
    "K12 killed custodian leaves live utility fenced by service",
    "K13 killed formatter retains fence and same intent recovers",
    "K14 killed custodian after intent fsync reconciles safely",
    "K15 killed custodian after gate close reconciles safely",
    "K16 killed custodian after mount move reconciles safely",
    "K17 killed custodian after unmount reconciles safely",
    "K18 killed custodian after format started commit reconciles safely",
    "K19 killed custodian after format exit and flush reconciles safely",
    "K20 killed custodian after ready rename reconciles safely",
    "K21 killed broker before gate open publishes only candidate",
    "K22 mount replacement during recovery preserves alien canary",
    "K23 visible alias and nested mount preserve alien state",
    "K24 backing image replacement preserves both identities",
    "K25 state anchor and generation replacement preserve alien content",
    "K26 quarantined lease residue resets through independent controller",
    "K27 empty recorded filesystem resets and missing registration refuses",
    "K28 formatter trace proves exclusive open before device mutations",
    "K29 timeout retains fence until cgroup absence",
    "K30 teardown refuses alien replacement then removes only owned fixture",
    "K31 killed broker after gate open preserves admitted lease canary",
    "K32 killed custodian after candidate mount reconciles exact private target",
)
CASE_NAMES = {name[:3]: name for name in REQUIRED}
SOURCE_PATHS = (
    ".github/workflows/ci.yml",
    "scripts/ci-oracle-ext4-reset.py",
    "scripts/oracle-ext4-reset.py",
    "scripts/oracle-ext4-reset-install.py",
    "scripts/oracle-ext4-reset-fixture-mutations.py",
    "scripts/oracle-ext4-reset-profile.json",
    "scripts/oracle-ext4-reset-mke2fs.conf",
    "scripts/systemd/decomp-oracle-ext4-reset-ci.service",
    "scripts/systemd/decomp-oracle-ext4-reset-retain.target",
    "scripts/verify-oracle-ext4-reset.py",
    "src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt",
    "src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetMountedTest.kt",
    "src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetProbe.kt",
)
INSTALLED_TOOLS = {"mke2fs": "/usr/sbin/mke2fs", "mount": "/usr/bin/mount", "umount": "/usr/bin/umount", "systemctl": "/usr/bin/systemctl", "busctl": "/usr/bin/busctl", "strace": "/usr/bin/strace", "losetup": "/usr/sbin/losetup", "unshare": "/usr/bin/unshare", "setpriv": "/usr/bin/setpriv", "python": "/usr/bin/python3"}
MAX_XML = 1024 * 1024
MAX_JSON = 64 * 1024
MAX_ARTIFACT = 4 * 1024 * 1024
MAX_TOTAL_ARTIFACTS = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ARTIFACT_LIMITS = {"formatter.trace": 1024 * 1024, "events.json": MAX_JSON, "manifest.json": MAX_JSON, "service.properties": MAX_JSON}
IMAGE_BYTES = 67108864
INODES = 4096
SCRATCH = re.compile(r"/var/lib/decomp-oracle-ext4-reset-ci/public/g-[0-9a-f]{16}/scratch\Z")
LEASE_FIELDS = ("device", "evidenceSha256", "filesystemDevice", "filesystemType", "fragmentBytes", "initialAvailableBytes", "initialAvailableInodes", "leaseRecordSha256", "leaseRootDevice", "leaseRootInode", "maximumFilesystemBytes", "maximumFilesystemInodes", "mode", "mountFlags", "mountId", "mountPathSha256", "operationId", "ownerUid", "provider", "requestSha256", "requiredAvailableBytes", "requiredAvailableInodes", "rootInode", "schemaVersion", "scopeSha256", "shardId", "totalBytes", "totalInodes")
PHASES = {"REGISTERED", "INTENT", "FENCED", "UNMOUNTED", "FORMAT_STARTED", "FORMATTED", "MOUNT_INTENT", "READY_PRIVATE", "EXPOSURE_INTENT", "PUBLISHED"}
BARRIERS = {"INTENT_FSYNC", "GATE_CLOSED", "MOUNT_MOVED", "UNMOUNTED_BEFORE_COMMIT", "FORMAT_STARTED", "FORMAT_FLUSHED", "READY_RENAMED_BEFORE_FSYNC", "CANDIDATE_MOUNTED", "EXPOSURE_INTENT", "GATE_OPENED", "FORMAT_RUNNING", "SERVICE_RUNNING", "ACTION_TIMEOUT"}
EVENT_OPERATIONS = {"broker-request", "broker-resume", "broker-finalize", "broker-status", "mount", "umount", "loop-allocate", "namespace-holder", "file-holder", "fault-arm", "barrier-observe", "signal", "property-read", "fixture-restore", "fixture-teardown", "trace-read", "state-read"}
CANARY_LABELS = {"file-holder", "namespace-holder", "mount-replacement", "alias", "nested-mount", "image-replacement", "anchor-replacement", "state-anchor", "teardown-replacement", "candidate-lease"}
REQUIRED_DEATHS = {
    "K11": ("controller", "SERVICE_RUNNING"), "K12": ("custodian", "SERVICE_RUNNING"),
    "K13": ("utility", "FORMAT_RUNNING"), "K14": ("custodian", "INTENT_FSYNC"),
    "K15": ("custodian", "GATE_CLOSED"), "K16": ("custodian", "MOUNT_MOVED"),
    "K17": ("custodian", "UNMOUNTED_BEFORE_COMMIT"), "K18": ("custodian", "FORMAT_STARTED"),
    "K19": ("custodian", "FORMAT_FLUSHED"), "K20": ("custodian", "READY_RENAMED_BEFORE_FSYNC"),
    "K21": ("controller", "EXPOSURE_INTENT"), "K31": ("controller", "GATE_OPENED"),
    "K32": ("custodian", "CANDIDATE_MOUNTED"),
}
REQUIRED_CANARIES = {"K07": "file-holder", "K08": "namespace-holder", "K22": "mount-replacement", "K23": "alias", "K24": "image-replacement", "K25": "anchor-replacement", "K30": "teardown-replacement", "K31": "candidate-lease"}
EXPECTED_PROFILE = {
    "schemaVersion": 1, "profile": PROFILE, "kind": "production", "slotId": "slot0",
    "imageBytes": IMAGE_BYTES, "inodes": INODES, "blockBytes": 4096,
    "mountFlags": ["noatime", "nodev", "noexec", "nosuid", "rw"],
    "systemdMajor": 255, "machine": "x86_64",
    "formatterPackages": ["1.47.0-2.4~exp1ubuntu4", "1.47.0-2.4~exp1ubuntu4.1"],
    "metadataBytes": 1048576, "maximumEntries": 32, "maximumGenerationDirectories": 2,
    "recordBytes": 16384, "actionSeconds": 45, "unit": "decomp-oracle-ext4-reset-ci.service",
    "retentionUnit": "decomp-oracle-ext4-reset-retain.target",
    "startLimitIntervalSeconds": 10, "startLimitBurst": 5, "startLimitAction": "none",
}
START_SPACING_NS = 2100000000


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _keys(value, names, label):
    _require(type(value) is dict and set(value) == set(names), f"invalid {label} fields")


def _integer(value, low, high, label):
    _require(type(value) is int and low <= value <= high, f"invalid {label}")


def _decimal_property(value, low, high, label):
    _require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None, f"invalid {label}")
    number = int(value)
    _integer(number, low, high, label)
    return number


def _hash(value, label):
    _require(type(value) is str and SHA256.fullmatch(value) is not None, f"invalid {label}")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value, newline=True):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + ("\n" if newline else "")).encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(raw, label, newline=True):
    def reject_constant(value):
        raise ValueError(f"nonfinite JSON number: {value}")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=reject_constant, parse_float=reject_constant)
        def check_strings(node, depth=0):
            _require(depth <= 16, f"excessive {label} nesting")
            if type(node) is str:
                node.encode("utf-8")
            elif type(node) is dict:
                for key, item in node.items():
                    key.encode("utf-8")
                    check_strings(item, depth + 1)
            elif type(node) is list:
                for item in node:
                    check_strings(item, depth + 1)
        check_strings(value)
        _require(canonical(value, newline=newline) == raw, f"noncanonical {label}")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"invalid {label}: {error}") from error


def _open_directory(path):
    """Pin every component without following a symlink, including root ancestors."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _relative_parts(relative):
    _require(type(relative) is str and relative != "", "invalid evidence path")
    parts = relative.split("/")
    _require(all(part and part not in (".", "..") and "\\" not in part and "\0" not in part for part in parts), "invalid evidence path")
    return parts


def read_regular(root, relative, limit, allow_empty=False):
    """Open nonblocking before fstat so substituted FIFOs/devices cannot hang."""
    parts = _relative_parts(relative)
    directory = _open_directory(root)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"not a single-link ordinary file: {relative}")
        _require((0 if allow_empty else 1) <= before.st_size <= limit, f"empty or oversized file: {relative}")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        _require(len(raw) == before.st_size and len(raw) <= limit, f"changed or oversized file: {relative}")
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), f"file changed while reading: {relative}")
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def verify_junit(reports):
    raw = read_regular(reports, f"TEST-{CLASS}.xml", MAX_XML)
    try:
        document = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("JUnit must be UTF-8") from error
    _require("\0" not in document and re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", document, re.IGNORECASE) is None, "declarations or NUL bytes are not admitted in JUnit reports")
    suite = ET.fromstring(document)
    _require(suite.tag == "testsuite", "expected one JUnit testsuite")
    _require(suite.get("name") == CLASS, "unexpected JUnit suite class")
    _require(set(suite.attrib) <= {"name", "tests", "failures", "errors", "skipped", "timestamp", "hostname", "time"}, "unexpected JUnit suite attributes")
    for field, expected in (("tests", 32), ("failures", 0), ("errors", 0), ("skipped", 0)):
        _require(suite.get(field) == str(expected), f"invalid JUnit {field} count")
    observed = Counter()
    for child in suite:
        _require(child.tag in ("testcase", "system-out", "system-err", "properties"), "unexpected JUnit suite element")
        if child.tag != "testcase":
            if child.tag == "properties":
                _require(all(node.tag == "property" and not list(node) and set(node.attrib) == {"name", "value"} for node in child), "unexpected JUnit property element")
            else:
                _require(not list(child), "unexpected nested JUnit output element")
            continue
        _require(child.get("classname") == CLASS, "unexpected JUnit test class")
        _require(set(child.attrib) <= {"name", "classname", "time"}, "unexpected JUnit test attributes")
        name = child.get("name", "")
        if name.endswith("()"):
            name = name[:-2]
        _require(name in REQUIRED, f"unexpected reset control: {name}")
        _require(all(node.tag in ("system-out", "system-err") and not list(node) for node in child), f"reset control did not pass: {name}")
        observed[name] += 1
    _require(observed == Counter(REQUIRED), "report must execute each of the 32 named controls exactly once")
    return {"bytes": len(raw), "sha256": _digest(raw)}


def verify_sources(source_root, source_hashes):
    _keys(source_hashes, SOURCE_PATHS, "source hashes")
    for path in SOURCE_PATHS:
        _hash(source_hashes[path], f"source hash for {path}")
        _require(_digest(read_regular(source_root, path, MAX_ARTIFACT)) == source_hashes[path], f"source mismatch: {path}")


def _git_read(source_root, arguments):
    # These read-only commands emit at most one fixed HEAD or thirteen exact tree
    # entries, never file contents. Disable implicit fetches and optional writes.
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    try:
        result = subprocess.run(["git", "--no-pager", "-C", str(source_root), *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=10, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError("source commit verification timed out") from error
    _require(result.returncode == 0 and len(result.stdout) <= 16384 and len(result.stderr) <= 16384, "source commit metadata unavailable or oversized")
    return result.stdout


def verify_git_sources(source_root, source_commit, source_hashes):
    _require(_git_read(source_root, ["rev-parse", "--verify", "HEAD"]) == (source_commit + "\n").encode("ascii"), "source commit is not checked-out HEAD")
    raw_tree = _git_read(source_root, ["ls-tree", "-z", "--full-tree", source_commit, "--", *SOURCE_PATHS])
    entries = raw_tree.split(b"\0")
    _require(entries[-1] == b"", "truncated source tree observation")
    observed = {}
    for entry in entries[:-1]:
        match = re.fullmatch(rb"(100644|100755) blob ([0-9a-f]{40})\t([^\0\n]+)", entry)
        _require(match is not None, "source commit does not contain ordinary source blobs")
        path = match[3].decode("utf-8")
        _require(path in SOURCE_PATHS and path not in observed, "unknown or duplicate committed source path")
        observed[path] = match[2].decode("ascii")
    _require(set(observed) == set(SOURCE_PATHS), "source commit lacks the exact qualification source closure")
    for path in SOURCE_PATHS:
        raw = read_regular(source_root, path, MAX_ARTIFACT)
        _require(_digest(raw) == source_hashes[path], "source changed during verification")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        _require(blob == observed[path], f"qualified source differs from committed bytes: {path}")


def _inventory(root, expected):
    directory = _open_directory(root)
    try:
        _require(set(os.listdir(directory)) == set(expected), "unexpected or missing evidence entries")
    finally:
        os.close(directory)


def verify_artifacts(evidence, case_id, entries):
    _require(type(entries) is list and len(entries) == len(ARTIFACT_LIMITS), "invalid artifact count")
    artifacts = {}
    for entry in entries:
        _keys(entry, ("name", "path", "bytes", "sha256"), "artifact reference")
        name = entry["name"]
        _require(type(name) is str and name in ARTIFACT_LIMITS and name not in artifacts, "unknown or duplicate artifact")
        relative = f"raw/{case_id}/{name}"
        _require(entry["path"] == relative, "artifact belongs to another case or path")
        _integer(entry["bytes"], 0 if name == "formatter.trace" else 1, ARTIFACT_LIMITS[name], "artifact byte count")
        _hash(entry["sha256"], "artifact hash")
        raw = read_regular(evidence, relative, ARTIFACT_LIMITS[name], allow_empty=name == "formatter.trace")
        _require(len(raw) == entry["bytes"] and _digest(raw) == entry["sha256"], "artifact bytes differ from receipt")
        artifacts[name] = raw
    _inventory(Path(evidence) / "raw" / case_id, ARTIFACT_LIMITS)
    return artifacts


def _lease_evidence(value, event, snapshot):
    _keys(value, LEASE_FIELDS, "production lease evidence")
    expected = {
        "schemaVersion": 1, "provider": "dedicated-ext4-filesystem-v1",
        "operationId": _digest(f"{event['caseId']}:{event['sessionToken']}:{event['mode']}".encode()),
        "requestSha256": "2" * 64, "scopeSha256": "3" * 64, "shardId": "clang-lib-driver",
        "mountPathSha256": _digest(event["scratch"].encode()), "mountId": snapshot["mountId"],
        "filesystemDevice": f"{os.major(snapshot['loopRdev'])}:{os.minor(snapshot['loopRdev'])}",
        "filesystemType": "ext4", "fragmentBytes": 4096, "ownerUid": 65534, "mode": 0o700,
        "requiredAvailableBytes": 1, "maximumFilesystemBytes": IMAGE_BYTES,
        "requiredAvailableInodes": 4, "maximumFilesystemInodes": INODES,
    }
    for name, wanted in expected.items():
        _require(type(value[name]) is type(wanted) and value[name] == wanted, f"lease evidence {name} differs from actual case")
    for name in ("device", "leaseRootDevice"):
        _integer(value[name], 0, 2**64 - 1, f"lease {name}")
    for name in ("rootInode", "leaseRootInode"):
        _integer(value[name], 1, 2**64 - 1, f"lease {name}")
    _integer(value["totalBytes"], 1, IMAGE_BYTES, "lease total bytes")
    _integer(value["totalInodes"], 4, INODES, "lease total inodes")
    _integer(value["initialAvailableBytes"], 1, value["totalBytes"], "lease available bytes")
    _integer(value["initialAvailableInodes"], 4, value["totalInodes"], "lease available inodes")
    flags = value["mountFlags"]
    _require(type(flags) is list and all(type(flag) is str and re.fullmatch(r"[A-Za-z0-9._=+-]+", flag) for flag in flags) and flags == sorted(set(flags)) and {"rw", "nodev", "nosuid", "noexec", "noatime"} <= set(flags), "invalid lease mount flags")
    for name in ("leaseRecordSha256", "evidenceSha256"):
        _hash(value[name], f"lease {name}")
        _require(value[name] != "0" * 64, "unsealed lease evidence")
    unsigned = {key: item for key, item in value.items() if key != "evidenceSha256"}
    # This nested object is produced by OracleJson, whose self hash uses its
    # documented pretty canonical encoding, not the fixture envelope encoding.
    encoded = (json.dumps(unsigned, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    _require(_digest(encoded) == value["evidenceSha256"], "production lease evidence self hash differs")


def verify_probe(raw, receipt):
    probe = _json(raw, "probe receipt")
    _keys(probe, ("schemaVersion", "caseId", "sessionToken", "events", "kills"), "probe receipt")
    _integer(probe["schemaVersion"], 1, 1, "probe schema")
    case_id = receipt["caseId"]
    _require(probe["caseId"] == case_id and probe["sessionToken"] == receipt["sessionToken"], "probe case/session mismatch")
    _require(type(probe["events"]) is list and 0 <= len(probe["events"]) <= 16, "invalid probe events")
    _require(type(probe["kills"]) is list and len(probe["kills"]) <= 1, "invalid probe kills")
    common = {"schemaVersion", "caseId", "sessionToken", "mode", "event", "pid", "startTicks", "uid", "gid", "scratch"}
    held = {"leaseEvidence", "canarySha256", "runRootInode", "availableBytes", "availableInodes"}
    mode_facts = {
        "access": {"deniedObjects", "effectiveCapabilities", "noNewPrivileges", "accessResults", "rawDeviceRdev"},
        "expect-refusal": {"reason"}, "admit-clean": {"leaseEvidence"},
        "hold-canary": held, "active": held, "sparse-deep": held | {"sparseLogicalBytes", "directoryDepth"},
        "bytes-full": held | {"writtenBytes"}, "inodes-full": held | {"createdFiles"},
        "quarantine": {"leaseEvidence", "quarantineName", "recordSha256", "barrier"},
    }
    observed = []
    identities = {}
    for event in probe["events"]:
        _require(type(event) is dict and type(event.get("mode")) is str and event["mode"] in mode_facts, "unknown probe mode")
        mode = event["mode"]
        _keys(event, common | mode_facts[mode], "probe event")
        _integer(event["schemaVersion"], 1, 1, "probe event schema")
        _require(event["caseId"] == case_id and event["sessionToken"] == receipt["sessionToken"], "probe event case/session mismatch")
        for field in ("uid", "gid"):
            _integer(event[field], 65534, 65534, f"probe {field}")
        for field in ("pid", "startTicks"):
            _integer(event[field], 1, 2**63 - 1, f"probe {field}")
        identity = (event["pid"], event["startTicks"])
        _require(identity not in identities or identities[identity] == mode, "one process impersonates multiple probe modes")
        identities[identity] = mode
        wanted = "access-denied" if mode == "access" else "acquisition-refused" if mode == "expect-refusal" else "admitted-clean" if mode == "admit-clean" else None
        _require(event["event"] == wanted if wanted else event["event"] in ("ready", "checked", "clean-released") if mode == "hold-canary" else event["event"] == "ready", "unexpected probe event")
        snapshot = receipt["after"] if mode == "admit-clean" or case_id == "K31" else receipt["before"]
        _require(event["scratch"] == snapshot["scratch"] and SCRATCH.fullmatch(event["scratch"]) is not None, "probe scratch does not match measured generation")
        if "leaseEvidence" in event:
            _lease_evidence(event["leaseEvidence"], event, snapshot)
        if mode == "access":
            _integer(event["deniedObjects"], 7, 7, "denied object count")
            _require(event["effectiveCapabilities"] == "0" and event["noNewPrivileges"] is True, "probe privilege measurements differ")
            expected_access = [{"object": "private", "access": "list", "result": "AccessDeniedException"}] + [{"object": obj, "access": access, "result": "AccessDeniedException"} for obj in ("image", "state", "loop") for access in ("read", "write")]
            _require(event["accessResults"] == expected_access, "oracle read/write access was not independently denied")
            _integer(event["rawDeviceRdev"], snapshot["loopRdev"], snapshot["loopRdev"], "observed raw device identity")
        if mode == "expect-refusal":
            _require(event["reason"] == "already-leased", "probe refusal reason differs")
        if "canarySha256" in event:
            _require(event["canarySha256"] == _digest(f"reset-probe:{case_id}:{receipt['sessionToken']}\n".encode()), "probe canary bytes differ")
            _integer(event["runRootInode"], 1, 2**64 - 1, "probe run root inode")
            _integer(event["availableBytes"], 0, IMAGE_BYTES, "probe available bytes")
            _integer(event["availableInodes"], 0, INODES, "probe available inodes")
        if mode == "sparse-deep":
            _integer(event["sparseLogicalBytes"], 2**40, 2**40, "sparse logical bytes")
            _integer(event["directoryDepth"], 512, 512, "directory depth")
        if mode == "bytes-full":
            _integer(event["writtenBytes"], 1, IMAGE_BYTES, "written bytes")
            _require(event["availableBytes"] == 0, "byte exhaustion not observed")
        if mode == "inodes-full":
            _integer(event["createdFiles"], 1, INODES, "created files")
            _require(event["availableInodes"] == 0, "inode exhaustion not observed")
        if mode == "quarantine":
            _hash(event["recordSha256"], "quarantine record")
            _require(event["barrier"] == "release-after-quarantine-parent-sync", "wrong quarantine barrier")
            _require(type(event["quarantineName"]) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", event["quarantineName"]) is not None and ".." not in event["quarantineName"], "invalid quarantine component")
        observed.append((mode, event["event"]))
    expected = {
        "K01": [("access", "access-denied")],
        "K02": [("hold-canary", "ready"), ("expect-refusal", "acquisition-refused"), ("hold-canary", "checked"), ("hold-canary", "clean-released")],
        "K03": [("active", "ready")], "K04": [("sparse-deep", "ready")],
        "K05": [("bytes-full", "ready")], "K06": [("inodes-full", "ready")],
        "K26": [("quarantine", "ready")],
        "K31": [("hold-canary", "ready"), ("hold-canary", "checked"), ("hold-canary", "checked"), ("hold-canary", "clean-released")],
    }.get(case_id, [])
    if receipt["outcome"] == "reset":
        expected = expected + [("admit-clean", "admitted-clean")]
    _require(observed == expected, "probe lacks the exact required actual child event sequence")
    needs_kill = case_id in {"K03", "K04", "K05", "K06", "K26"}
    _require(len(probe["kills"]) == int(needs_kill), "probe lacks exact required kill/reap record")
    for kill in probe["kills"]:
        _keys(kill, ("pid", "startTicks", "signal", "exitCode"), "probe kill")
        for field in ("pid", "startTicks"):
            _integer(kill[field], 1, 2**63 - 1, f"probe kill {field}")
        _integer(kill["signal"], 9, 9, "probe kill signal")
        _integer(kill["exitCode"], 137, 137, "probe reaped exit code")
        _require((kill["pid"], kill["startTicks"]) == (probe["events"][0]["pid"], probe["events"][0]["startTicks"]), "probe kill/reap does not identify actual ready child")
    held_events = [event for event in probe["events"] if event["mode"] == "hold-canary"]
    if held_events:
        initial = held_events[0]
        for event in held_events[1:]:
            _require({key: value for key, value in event.items() if key != "event"} == {key: value for key, value in initial.items() if key != "event"}, "held child identity or canary changed across control")
    return {"bytes": len(raw), "sha256": _digest(raw)}


def _snapshot(value, teardown=False):
    _keys(value, ("generation", "filesystemUuid", "scratch", "phase", "gateMode", "mountId", "loopRdev", "imageDevice", "imageInode", "imageBytes", "availableBytes", "availableInodes"), "fixture snapshot")
    generation = value["generation"]
    _require(type(generation) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", generation) is not None and int(generation) <= 2**64 - 1, "invalid generation")
    _require(type(value["filesystemUuid"]) is str and str(uuid.UUID(value["filesystemUuid"])) == value["filesystemUuid"], "invalid filesystem UUID")
    _require(type(value["scratch"]) is str and SCRATCH.fullmatch(value["scratch"]) is not None, "invalid generation scratch path")
    _require(value["scratch"].split("/")[-2] == f"g-{int(generation):016x}", "generation path differs from generation number")
    _require(type(value["phase"]) is str and value["phase"] in (PHASES | {"RESERVED_UNMOUNTED"} if teardown else PHASES), "invalid snapshot phase")
    _integer(value["gateMode"], 0, 0o7777, "gate mode")
    _require(value["gateMode"] in (0, 0o711), "invalid physical gate mode")
    for field in ("loopRdev", "imageInode"):
        _integer(value[field], 1, 2**64 - 1, f"snapshot {field}")
    _integer(value["mountId"], 0 if teardown else 1, 2**64 - 1, "snapshot mountId")
    _integer(value["imageDevice"], 0, 2**64 - 1, "snapshot image device")
    _integer(value["imageBytes"], IMAGE_BYTES, IMAGE_BYTES, "reserved image bytes")
    _integer(value["availableBytes"], 0, IMAGE_BYTES, "snapshot available bytes")
    _integer(value["availableInodes"], 0, INODES, "snapshot available inodes")


def _invocation(value):
    _require(value is None or type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None, "invalid invocation identity")


def verify_events(raw, case_id):
    value = _json(raw, "raw events", newline=False)
    _keys(value, ("schemaVersion", "caseId", "events"), "raw events")
    _integer(value["schemaVersion"], 1, 1, "events schema")
    _require(value["caseId"] == case_id, "raw events case mismatch")
    _require(type(value["events"]) is list and 1 <= len(value["events"]) <= 256, "missing or excessive measured events")
    keys = {"reason", "phaseBefore", "phaseAfter", "pid", "startTicks", "signal", "barrier", "invocationId", "artifactSha256", "device", "imageInode"}
    if case_id == "K27":
        keys.add("missingRegistration")
    for event in value["events"]:
        _keys(event, ("operation", "startMonotonicNs", "endMonotonicNs", "exitCode", "details"), "measured event")
        _require(type(event["operation"]) is str and event["operation"] in EVENT_OPERATIONS, "unknown measured operation")
        _integer(event["startMonotonicNs"], 1, 2**63 - 1, "event start")
        _integer(event["endMonotonicNs"], event["startMonotonicNs"], 2**63 - 1, "event end")
        _integer(event["exitCode"], -128, 255, "event exit")
        details = event["details"]
        _require(type(details) is dict and set(details) <= keys, "unknown measured event details")
        for name, item in details.items():
            if name in {"phaseBefore", "phaseAfter"}:
                _require(type(item) is str and item in PHASES, "invalid event phase")
            elif name in {"pid", "startTicks", "imageInode"}:
                _integer(item, 1, 2**64 - 1, f"event {name}")
            elif name == "device":
                _integer(item, 0, 2**64 - 1, "event device")
            elif name == "signal":
                _integer(item, 9, 19, "event signal")
                _require(item == 9 or item == 19 and case_id == "K29" and event["operation"] == "signal" and details.get("barrier") == "ACTION_TIMEOUT", "signal is outside the closed case action")
            elif name == "barrier":
                _require(type(item) is str and item in BARRIERS, "invalid event barrier")
            elif name == "invocationId":
                _invocation(item)
            elif name == "artifactSha256":
                _hash(item, "event artifact hash")
            elif name == "missingRegistration":
                _require(item is True and event["operation"] == "broker-request" and event["exitCode"] == 1, "invalid missing-registration refusal event")
            else:
                _require(type(item) is str and 1 <= len(item) <= 1024 and "\0" not in item, "invalid measured reason")
    return value["events"]


def verify_observations(receipt, artifacts):
    case_id = receipt["caseId"]
    observations = receipt["observations"]
    _keys(observations, ("attempts", "deaths", "canaries", "holders", "trace", "facts"), "observations")
    for field in ("attempts", "deaths", "canaries", "holders"):
        _require(type(observations[field]) is list and len(observations[field]) <= 16, f"invalid {field} observations")
    attempts = observations["attempts"]
    if case_id not in {"K01", "K30"}:
        _require(attempts, "missing actual reset attempts")
    for attempt in attempts:
        _keys(attempt, ("action", "exitCode", "phaseBefore", "phaseAfter", "invocationId", "formatterCount"), "reset attempt")
        _require(type(attempt["action"]) is str and attempt["action"] in {"request", "resume", "finalize", "status"}, "unknown reset action")
        _integer(attempt["exitCode"], -128, 255, "reset exit code")
        _require(type(attempt["phaseBefore"]) is str and attempt["phaseBefore"] in PHASES and type(attempt["phaseAfter"]) is str and attempt["phaseAfter"] in PHASES, "invalid reset attempt phases")
        _invocation(attempt["invocationId"])
        _integer(attempt["formatterCount"], 0, 16, "formatter count")
    if receipt["outcome"] == "reset":
        _require(any(attempt["exitCode"] == 0 and attempt["phaseAfter"] == "PUBLISHED" for attempt in attempts), "no successful measured publication")
        _require(any(attempt["formatterCount"] > 0 and attempt["invocationId"] is not None for attempt in attempts), "no actual formatter invocation")
    if case_id in {"K02", "K07", "K08", "K09", "K11", "K12", "K22", "K23", "K24", "K25", "K27", "K29", "K30", "K32"}:
        _require(any(attempt["exitCode"] != 0 for attempt in attempts), "required actual refusal absent")
    deaths = set()
    for death in observations["deaths"]:
        _keys(death, ("role", "pid", "startTicks", "signal", "reaped", "barrier"), "process death")
        _require(type(death["role"]) is str and death["role"] in {"controller", "custodian", "utility"}, "unknown death role")
        _require(type(death["barrier"]) is str and death["barrier"] in BARRIERS, "unknown death barrier")
        for field in ("pid", "startTicks"):
            _integer(death[field], 1, 2**63 - 1, f"death {field}")
        _integer(death["signal"], 9, 9, "death signal")
        _require(death["reaped"] is True, "dead child has not been reaped")
        identity = (death["pid"], death["startTicks"])
        _require(identity not in deaths, "duplicate process death")
        deaths.add(identity)
    if case_id in REQUIRED_DEATHS:
        _require(any((death["role"], death["barrier"]) == REQUIRED_DEATHS[case_id] for death in observations["deaths"]), "required actual process death/barrier absent")
    if case_id == "K29":
        _require(any(death["barrier"] == "ACTION_TIMEOUT" and death["role"] in {"controller", "custodian"} for death in observations["deaths"]), "actual timeout death absent")
    labels = set()
    for canary in observations["canaries"]:
        _keys(canary, ("label", "beforeSha256", "afterSha256"), "canary")
        _require(type(canary["label"]) is str and canary["label"] in CANARY_LABELS and canary["label"] not in labels, "unknown or duplicate canary")
        labels.add(canary["label"])
        _hash(canary["beforeSha256"], "before canary")
        _hash(canary["afterSha256"], "after canary")
        _require(canary["beforeSha256"] == canary["afterSha256"], "canary changed during refused operation")
    if case_id in REQUIRED_CANARIES:
        _require(REQUIRED_CANARIES[case_id] in labels, "required actual canary observation absent")
    if case_id == "K23":
        _require({"alias", "nested-mount"} <= labels, "visible alias and nested mount both require preservation evidence")
    if case_id == "K25":
        _require({"anchor-replacement", "state-anchor"} <= labels, "generation and state anchors both require preservation evidence")
    for holder in observations["holders"]:
        _keys(holder, ("kind", "pid", "startTicks", "reaped", "refusalExitCode"), "holder")
        _require(type(holder["kind"]) is str and holder["kind"] in {"file", "namespace", "utility"}, "unknown holder kind")
        for field in ("pid", "startTicks"):
            _integer(holder[field], 1, 2**63 - 1, f"holder {field}")
        _require(holder["reaped"] is True, "held resource not released before successful final receipt")
        _integer(holder["refusalExitCode"], -128, 255, "holder refusal exit")
        _require(holder["refusalExitCode"] != 0, "holder did not cause measured refusal")
    for required_case, kind in (("K07", "file"), ("K08", "namespace"), ("K12", "utility")):
        if case_id == required_case:
            _require(any(holder["kind"] == kind for holder in observations["holders"]), "required actual holder absent")
    trace = observations["trace"]
    _keys(trace, ("artifact", "sha256", "exclusiveOpenFlags", "exclusiveOpenErrno", "deviceMutationCount", "mutationsBeforeExclusiveOpen", "truncated"), "formatter trace")
    _require(trace["artifact"] == f"raw/{case_id}/formatter.trace" and trace["sha256"] == _digest(artifacts["formatter.trace"]), "trace binding differs")
    _require(trace["exclusiveOpenFlags"] in ([], ["O_RDWR", "O_EXCL"], ["O_RDONLY", "O_EXCL"]), "unexpected exclusive open flags")
    _require(trace["exclusiveOpenErrno"] is None or trace["exclusiveOpenErrno"] == "EBUSY", "unexpected exclusive open result")
    _integer(trace["deviceMutationCount"], 0, 1000000, "device mutation count")
    _integer(trace["mutationsBeforeExclusiveOpen"], 0, 0, "mutations before exclusive open")
    _require(trace["truncated"] is False, "truncated formatter trace")
    derived_trace = decode_formatter_trace(artifacts["formatter.trace"], receipt["before"]["loopRdev"], receipt["after"]["filesystemUuid"])
    _require(all(trace[key] == value for key, value in derived_trace.items()), "formatter summary contradicts retained syscalls")
    if case_id == "K08":
        _require(artifacts["formatter.trace"] and trace["exclusiveOpenFlags"] and trace["exclusiveOpenErrno"] == "EBUSY" and trace["deviceMutationCount"] == 0, "hidden mount refusal not retained")
    elif receipt["outcome"] == "reset":
        _require(artifacts["formatter.trace"] and trace["exclusiveOpenFlags"] == ["O_RDWR", "O_EXCL"] and trace["exclusiveOpenErrno"] is None and trace["deviceMutationCount"] > 0, "successful format trace absent")
    else:
        _require(trace["deviceMutationCount"] == 0, "non-reset case mutated the device")
    facts = observations["facts"]
    fact_keys = {"allocatedLoopRdev", "oldTreeEntriesVisited", "oldContentBytesRead", "mutatorCount", "restored", "removedOwnedFixture", "retainedReservation"}
    if case_id == "K25":
        fact_keys |= {"stateAnchorReplacementRefused", "stateAnchorRestored"}
    if case_id == "K27":
        fact_keys |= {"missingRegistrationRefused", "registrationRestored", "registrationBeforeSha256", "registrationAfterSha256"}
    _require(type(facts) is dict and set(facts) <= fact_keys, "unknown fixture facts")
    for name in ("oldTreeEntriesVisited", "oldContentBytesRead"):
        _integer(facts.get(name), 0, 0, name)
    _integer(facts.get("mutatorCount"), 0, 64, "mutator count")
    for name in ("restored", "removedOwnedFixture", "retainedReservation"):
        if name in facts:
            _require(type(facts[name]) is bool, f"invalid {name} fact")
    if "allocatedLoopRdev" in facts:
        _integer(facts["allocatedLoopRdev"], 1, 2**64 - 1, "allocated loop device")
    if case_id == "K10":
        _require("allocatedLoopRdev" in facts and facts["allocatedLoopRdev"] != receipt["before"]["loopRdev"], "unrelated loop allocation not observed")
    if case_id in {"K22", "K23", "K24", "K25", "K30", "K32"}:
        _require(facts.get("restored") is True, "owned fixture not restored after alien refusal")
    if case_id == "K30":
        _require(facts.get("removedOwnedFixture") is True, "exact owned teardown not observed")
        _require(facts.get("retainedReservation") is True, "teardown lost the bound allocation reservation")
    if case_id == "K27":
        _require(facts.get("missingRegistrationRefused") is True and facts.get("registrationRestored") is True, "missing registration was not refused and restored")
        _hash(facts.get("registrationBeforeSha256"), "original registration hash")
        _hash(facts.get("registrationAfterSha256"), "restored registration hash")
        _require(facts["registrationBeforeSha256"] == facts["registrationAfterSha256"], "registration changed during missing-state refusal")
    if case_id == "K25":
        _require(facts.get("stateAnchorReplacementRefused") is True and facts.get("stateAnchorRestored") is True, "state-anchor replacement was not refused and exactly restored")
    events = verify_events(artifacts["events.json"], case_id)
    for attempt in attempts:
        _require(any(event["operation"] == "broker-" + attempt["action"] and event["exitCode"] == attempt["exitCode"] and event["details"].get("phaseBefore") == attempt["phaseBefore"] and event["details"].get("phaseAfter") == attempt["phaseAfter"] for event in events), "reset attempt not bound to raw measured event")
    for death in observations["deaths"]:
        _require(any(event["operation"] == "signal" and all(event["details"].get(key) == death[key] for key in ("pid", "startTicks", "signal", "barrier")) for event in events), "process death not bound to raw measured event")
    if case_id == "K27":
        _require(any(event["details"].get("missingRegistration") is True and event["details"].get("phaseBefore") == event["details"].get("phaseAfter") and any(attempt["action"] == "request" and attempt["exitCode"] == event["exitCode"] and attempt["phaseBefore"] == event["details"].get("phaseBefore") and attempt["phaseAfter"] == event["details"].get("phaseAfter") and attempt["formatterCount"] == 0 for attempt in attempts) for event in events), "missing-registration refusal lacks a matching non-mutating actual request")
    if case_id == "K29":
        _require(any(stop["operation"] == "signal" and stop["exitCode"] == 0 and stop["details"].get("signal") == 19 and stop["details"].get("barrier") == "ACTION_TIMEOUT" and any(death["role"] == "custodian" and all(stop["details"].get(key) == death[key] for key in ("pid", "startTicks", "barrier")) and any(kill["operation"] == "signal" and kill["exitCode"] == 0 and kill["details"].get("signal") == 9 and all(kill["details"].get(key) == death[key] for key in ("pid", "startTicks", "barrier")) and stop["endMonotonicNs"] <= kill["startMonotonicNs"] for kill in events) for death in observations["deaths"]) for stop in events), "timeout lacks the exact stopped and subsequently killed custodian")
    if case_id == "K25":
        _require(any(event["operation"] == "broker-request" and event["exitCode"] != 0 and event["details"].get("reason") == "state-anchor-replacement" and any(attempt["action"] == "request" and attempt["exitCode"] == event["exitCode"] and attempt["phaseBefore"] == event["details"].get("phaseBefore") and attempt["phaseAfter"] == event["details"].get("phaseAfter") for attempt in attempts) for event in events), "state-anchor preservation lacks its actual broker refusal")
    if case_id == "K30":
        teardowns = [event for event in events if event["operation"] == "fixture-teardown"]
        _require(len(teardowns) == 2 and teardowns[0]["exitCode"] == 1 and teardowns[0]["details"].get("reason") == "original filesystem mount differs" and teardowns[1]["exitCode"] == 0 and teardowns[1]["details"].get("reason") == "public mount removed; allocation reserved" and teardowns[0]["endMonotonicNs"] <= teardowns[1]["startMonotonicNs"], "teardown lacks ordered exact refusal and owned unmount observations")
    return events


def decode_formatter_trace(raw, loop_rdev, filesystem_uuid=None):
    """Independently derive the fence summary from the selected strace grammar.

    stat/newfstatat binds the /proc/self/fd pathname to the measured block rdev,
    including failed opens (which have no returned descriptor annotation).
    Writable claims are tracked until close for each traced process/descriptor.
    """
    _require(type(raw) is bytes and len(raw) <= ARTIFACT_LIMITS["formatter.trace"], "formatter trace exceeds its byte bound")
    _integer(loop_rdev, 1, 2**64 - 1, "formatter loop device")
    if filesystem_uuid is not None:
        _require(type(filesystem_uuid) is str and str(uuid.UUID(filesystem_uuid)) == filesystem_uuid, "invalid expected formatter UUID")
    result = {"exclusiveOpenFlags": [], "exclusiveOpenErrno": None, "deviceMutationCount": 0, "mutationsBeforeExclusiveOpen": 0, "truncated": False}
    if not raw:
        return result
    _require(os.major(loop_rdev) == 7, "formatter target is not a loop block device")
    try:
        document = raw.decode("ascii")
    except UnicodeError as error:
        raise ValueError("formatter trace is not ASCII") from error
    _require(document.endswith("\n") and "\0" not in document, "truncated formatter trace")
    loop_path = f"/dev/loop{os.minor(loop_rdev)}"
    target = re.escape(loop_path)
    paths = set()
    claimed = set()
    calls = {"execve", "openat", "openat2", "write", "pwrite64", "writev", "pwritev", "ioctl", "close", "stat", "newfstatat", "fstat"}
    exec_count = 0
    invocation_path = None
    write_calls = {"write", "pwrite64", "writev", "pwritev"}
    write_ioctls = {"BLKDISCARD", "BLKSECDISCARD", "BLKZEROOUT", "BLKFLSBUF"}
    read_ioctls = {"BLKGETSIZE64", "BLKGETSIZE", "BLKSSZGET", "BLKPBSZGET", "BLKBSZGET", "BLKROGET", "BLKALIGNOFF", "BLKIOMIN", "BLKIOOPT", "BLKDISCARDZEROES", "HDIO_GETGEO"}
    for line in document.splitlines():
        _require(0 < len(line) <= 4096 and "<unfinished ...>" not in line and "resumed>" not in line, "incomplete formatter syscall")
        line_match = re.fullmatch(r"(?:(?:\[pid\s+([0-9]+)\]|([0-9]+))\s+)?(.+)", line)
        _require(line_match is not None, "unknown formatter trace line")
        pid = line_match[1] or line_match[2] or "unprefixed"
        body = line_match[3]
        if body == "+++ exited with 0 +++":
            continue
        match = re.fullmatch(r"([a-z0-9_]+)\((.*)\)\s+=\s+(.+)", body)
        _require(match is not None and match[1] in calls, "unknown formatter syscall or abnormal exit")
        call, arguments, returned = match.groups()
        if call == "execve":
            _require(exec_count == 0 and returned == "0", "formatter exec was repeated or failed")
            try:
                invocation = json.loads("[" + arguments + "]")
            except (json.JSONDecodeError, UnicodeError) as error:
                raise ValueError("formatter exec argv/environment is truncated or not explicit") from error
            _require(type(invocation) is list and len(invocation) == 3, "invalid formatter exec shape")
            executable, argv, environment = invocation
            _require(type(executable) is str and re.fullmatch(r"/proc/self/fd/[0-9]+", executable) is not None, "formatter executable is not its pinned descriptor")
            _require(type(argv) is list and len(argv) == 21 and all(type(item) is str for item in argv), "invalid formatter argument vector")
            invocation_path = argv[-2]
            _require(re.fullmatch(r"/proc/self/fd/[0-9]+", invocation_path) is not None, "formatter target is not its pinned descriptor")
            observed_uuid = argv[14]
            _require(str(uuid.UUID(observed_uuid)) == observed_uuid and (filesystem_uuid is None or observed_uuid == filesystem_uuid), "formatter UUID differs from committed intent")
            expected = [executable, "-t", "ext4", "-q", "-F", "-b", "4096", "-I", "256", "-N", "4096", "-m", "0", "-U", observed_uuid, "-O", "none,has_journal,extent,filetype,sparse_super,large_file,dir_index,uninit_bg", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", invocation_path, "16384"]
            _require(argv == expected, "formatter argv differs from fixed profile")
            expected_environment = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "MKE2FS_CONFIG=/var/lib/decomp-oracle-ext4-reset-ci/private/mke2fs.conf", "E2FSPROGS_UNDO_DIR=none"}
            _require(type(environment) is list and len(environment) == 5 and all(type(item) is str for item in environment) and set(environment) == expected_environment, "formatter environment differs from fixed profile")
            exec_count += 1
        if call in {"openat", "openat2"}:
            reused = re.fullmatch(r"([0-9]+)(?:<[^>]+>)?", returned)
            if reused:
                paths.discard((pid, "/proc/self/fd/" + reused[1]))
                claimed.discard((pid, reused[1]))
        if call in {"stat", "newfstatat", "fstat"} and returned == "0" and "st_mode=S_IFBLK|" in arguments:
            rdev = re.search(r"\bst_rdev=makedev\((0x[0-9a-f]+|[0-9]+), (0x[0-9a-f]+|[0-9]+)\)", arguments)
            if rdev and (int(rdev[1], 0), int(rdev[2], 0)) == (os.major(loop_rdev), os.minor(loop_rdev)):
                path = re.search(r'"(/proc/self/fd/[0-9]+)"', arguments)
                if path:
                    paths.add((pid, path[1]))
                elif call == "fstat":
                    descriptor = re.match(r"([0-9]+)<" + target + r">,", arguments)
                    if descriptor:
                        paths.add((pid, "/proc/self/fd/" + descriptor[1]))
        if call in {"openat", "openat2"}:
            path = re.search(r'"(/proc/self/fd/[0-9]+)"', arguments)
            if path and "O_EXCL" in arguments:
                _require(path[1] == invocation_path, "exclusive open targets a different formatter descriptor")
                _require((pid, path[1]) in paths, "exclusive target lacks prior exact block-device stat")
                flags = ["O_RDWR" if "O_RDWR" in arguments else "O_RDONLY", "O_EXCL"]
                _require("O_RDWR" in arguments or "O_RDONLY" in arguments, "unknown exclusive access mode")
                result["exclusiveOpenFlags"] = flags
                if re.fullmatch(r"-1 EBUSY \([^\n]+\)", returned):
                    result["exclusiveOpenErrno"] = "EBUSY"
                else:
                    opened = re.fullmatch(r"([0-9]+)<" + target + r">", returned)
                    _require(opened is not None, "exclusive target open did not produce the exact loop")
                    if flags[0] == "O_RDWR":
                        claimed.add((pid, opened[1]))
        descriptor = re.match(r"([0-9]+)<" + target + r">(?:,|$)", arguments)
        if descriptor:
            mutates = call in write_calls
            if call == "ioctl":
                command = arguments.split(",", 2)[1].strip()
                _require(command in write_ioctls | read_ioctls, "unknown ioctl on formatter block device")
                mutates = command in write_ioctls
            if mutates:
                result["deviceMutationCount"] += 1
                if (pid, descriptor[1]) not in claimed:
                    result["mutationsBeforeExclusiveOpen"] += 1
        if call == "close" and returned == "0":
            closed = re.fullmatch(r"([0-9]+)(?:<[^>]+>)?", arguments)
            _require(closed is not None, "unknown closed descriptor")
            claimed.discard((pid, closed[1]))
            paths.discard((pid, "/proc/self/fd/" + closed[1]))
    _require(exec_count == 1 and paths and result["exclusiveOpenFlags"], "formatter trace lacks fixed exec, exact target, or exclusive attempt")
    return result


def qualification_profile_hash(source_root):
    profile = _json(read_regular(source_root, "scripts/oracle-ext4-reset-profile.json", 16384), "checked profile", newline=False)
    expected = EXPECTED_PROFILE
    _keys(profile, expected, "checked profile")
    _require(all(type(profile[key]) is type(item) and profile[key] == item for key, item in expected.items()), "checked profile differs from reviewed v1 boundary")
    profile["kind"] = "qualification"
    return _digest(canonical(profile, newline=False))


def verify_package_provenance(value):
    _keys(value, ("schemaVersion", "machine", "kernelRelease", "systemdVersion", "pythonVersion", "packages", "formatterSource", "aptAuthenticationBoundary"), "package provenance")
    _integer(value["schemaVersion"], 1, 1, "package provenance schema")
    _require(value["machine"] == "x86_64", "wrong hosted architecture")
    _require(type(value["kernelRelease"]) is str and 1 <= len(value["kernelRelease"]) <= 256 and re.fullmatch(r"[A-Za-z0-9._+-]+", value["kernelRelease"]) is not None, "invalid observed kernel version")
    _require(type(value["systemdVersion"]) is str and value["systemdVersion"].startswith("systemd 255 ") and len(value["systemdVersion"]) <= 4096, "wrong observed systemd version")
    _require(type(value["pythonVersion"]) is str and value["pythonVersion"].startswith("Python 3.") and len(value["pythonVersion"]) <= 256, "invalid observed Python version")
    _require(value["aptAuthenticationBoundary"] == "requires-successful-signature-enforced-workflow-apt-install", "missing explicit APT authentication boundary")
    source = value["formatterSource"]
    _keys(source, ("upstreamCommit", "originalArchiveSha256", "distributionPatchReview"), "formatter source binding")
    _require(source == {"upstreamCommit": "25ad8a431331b4d1d444a70b6079456cc612ac40", "originalArchiveSha256": "6667afde56eef0c6af26684974400e4d2288ea49e9441bf5e6229195d51a3578", "distributionPatchReview": "no-reviewed-formatter-files-modified"}, "formatter source differs from reviewed boundary")
    packages = value["packages"]
    _keys(packages, ("e2fsprogs", "libext2fs2t64", "systemd", "python3-minimal"), "observed packages")
    for name, package in packages.items():
        _keys(package, ("binaryPackage", "version", "sourcePackage", "sourceVersion", "architecture", "status", "verifyOutputSha256", "aptMetadata", "aptMetadataSha256", "aptPolicy", "aptPolicySha256", "aptArchiveSha256"), "observed package")
        _require(package["binaryPackage"] in (name, name + ":amd64") and package["architecture"] == "amd64" and package["status"] == "install ok installed", "package installation identity differs")
        for key in ("version", "sourcePackage", "sourceVersion"):
            _require(type(package[key]) is str and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", package[key]) is not None, "invalid observed package version")
        _require(package["verifyOutputSha256"] == _digest(b""), "installed package verification was not clean")
        for text_key, hash_key in (("aptMetadata", "aptMetadataSha256"), ("aptPolicy", "aptPolicySha256")):
            _require(type(package[text_key]) is str and 1 <= len(package[text_key]) <= 16384, "missing or oversized APT observation")
            _require(_digest(package[text_key].encode("utf-8")) == package[hash_key], "APT observation hash differs")
        _hash(package["aptArchiveSha256"], "APT archive hash")
        metadata = package["aptMetadata"].splitlines()
        for line in ("Package: " + name, "Version: " + package["version"], "SHA256: " + package["aptArchiveSha256"]):
            _require(metadata.count(line) == 1, "APT metadata does not bind installed package/archive")
        if name in {"e2fsprogs", "libext2fs2t64"}:
            _require(package["sourcePackage"] == "e2fsprogs" and package["sourceVersion"] in {"1.47.0-2.4~exp1ubuntu4", "1.47.0-2.4~exp1ubuntu4.1"}, "unreviewed formatter package source")


def verify_installed_manifest(raw, source_hashes, profile_hash):
    manifest = _json(raw, "installed manifest", newline=False)
    _keys(manifest, ("schemaVersion", "owner", "tools", "files", "packageProvenance"), "installed manifest")
    _integer(manifest["schemaVersion"], 1, 1, "installed manifest schema")
    _keys(manifest["owner"], ("uid", "gid", "groups"), "installed oracle identity")
    _integer(manifest["owner"]["uid"], 65534, 65534, "installed oracle uid")
    _integer(manifest["owner"]["gid"], 65534, 65534, "installed oracle gid")
    _require(manifest["owner"]["groups"] == [], "oracle has supplementary groups")
    tools = manifest["tools"]
    _require(type(tools) is dict and tools == INSTALLED_TOOLS, "installed tool roles or paths differ from the fixed installer")
    files = manifest["files"]
    _require(type(files) is dict and 6 <= len(files) <= 64, "invalid installed file inventory")
    for path, entry in files.items():
        _require(type(path) is str and path.startswith("/") and str(Path(path)) == path and not {".", ".."}.intersection(path.split("/")), "invalid installed file path")
        _keys(entry, ("resolved", "identity", "sha256"), "installed file")
        resolved = entry["resolved"]
        _require(type(resolved) is str and resolved.startswith("/") and str(Path(resolved)) == resolved and not {".", ".."}.intersection(resolved.split("/")), "invalid resolved installed path")
        _hash(entry["sha256"], "installed file hash")
        identity = entry["identity"]
        _keys(identity, ("device", "inode", "mountId", "uid", "gid", "mode", "kind", "links", "size", "rdev"), "installed file identity")
        _require(identity["kind"] == "file", "installed object is not an ordinary file")
        for name in ("device", "gid", "rdev"):
            _integer(identity[name], 0, 2**64 - 1, f"installed {name}")
        for name in ("inode", "mountId", "links", "size"):
            _integer(identity[name], 1, 2**64 - 1, f"installed {name}")
        _integer(identity["uid"], 0, 0, "installed owner")
        _integer(identity["mode"], 0, 0o7777, "installed mode")
        _require(identity["mode"] & 0o022 == 0, "installed object is writable by non-root")
    for role, path in tools.items():
        _require(type(role) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", role) is not None and type(path) is str and path in files, "installed tool not bound to measured file")
    private = "/var/lib/decomp-oracle-ext4-reset-ci/private/"
    installed_sources = {
        private + "oracle-ext4-reset.py": "scripts/oracle-ext4-reset.py",
        private + "oracle-ext4-reset-install.py": "scripts/oracle-ext4-reset-install.py",
        private + "oracle-ext4-reset-fixture-mutations.py": "scripts/oracle-ext4-reset-fixture-mutations.py",
        private + "ci-oracle-ext4-reset.py": "scripts/ci-oracle-ext4-reset.py",
        private + "verify-oracle-ext4-reset.py": "scripts/verify-oracle-ext4-reset.py",
        private + "mke2fs.conf": "scripts/oracle-ext4-reset-mke2fs.conf",
        "/etc/systemd/system/decomp-oracle-ext4-reset-ci.service": "scripts/systemd/decomp-oracle-ext4-reset-ci.service",
        "/etc/systemd/system/decomp-oracle-ext4-reset-retain.target": "scripts/systemd/decomp-oracle-ext4-reset-retain.target",
    }
    for installed, source in installed_sources.items():
        _require(installed in files and files[installed]["sha256"] == source_hashes[source], "installed source bytes differ from qualified checkout")
    _require(private + "profile.json" in files and files[private + "profile.json"]["sha256"] == profile_hash, "installed qualification profile differs")
    verify_package_provenance(manifest["packageProvenance"])
    return manifest


def verify_service(raw, outcome):
    service = _json(raw, "service observation", newline=False)
    _keys(service, ("schemaVersion", "unit", "properties", "cgroup", "bootId", "retentionTarget", "completedInvocationId", "startBudget"), "service observation")
    _integer(service["schemaVersion"], 1, 1, "service observation schema")
    unit = "decomp-oracle-ext4-reset-ci.service"
    group_path = "/system.slice/" + unit
    _require(service["unit"] == unit, "unexpected service unit")
    target = service["retentionTarget"]
    expected_target = {"LoadState": "loaded", "ActiveState": "active", "SubState": "active", "FragmentPath": "/etc/systemd/system/decomp-oracle-ext4-reset-retain.target", "DropInPaths": "", "DefaultDependencies": "no", "After": unit, "Wants": "", "Requires": ""}
    _keys(target, (*expected_target, "Job"), "retention target properties")
    _require(all(target[key] == value for key, value in expected_target.items()) and target["Job"] in ("", "0"), "retention target is inactive, modified, or activates service work")
    _require(type(service["bootId"]) is str and str(uuid.UUID(service["bootId"])) == service["bootId"], "invalid observed boot ID")
    properties = service["properties"]
    _keys(properties, ("ActiveState", "SubState", "ControlGroup", "MainPID", "InvocationID", "Result", "Job", "ExecMainPID", "ExecMainCode", "ExecMainStatus", "StartLimitIntervalUSec", "StartLimitBurst", "StartLimitAction"), "service properties")
    _require(all(type(item) is str and len(item) <= 256 for item in properties.values()), "invalid service property types")
    _require(properties["ActiveState"] in {"inactive", "failed"} and properties["SubState"] in {"dead", "failed"} and properties["MainPID"] == "0" and properties["Job"] in {"", "0"}, "service is active, queued, or ambiguous")
    _require(properties["ControlGroup"] in {"", group_path}, "unexpected service cgroup")
    _require(properties["InvocationID"] == "" or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is not None, "invalid service invocation")
    _require(type(service["completedInvocationId"]) is str and service["completedInvocationId"] == properties["InvocationID"], "completed invocation differs from retained manager identity")
    _require(properties["Result"] in {"success", "signal", "timeout", "exit-code"}, "unknown service result")
    exec_pid = _decimal_property(properties["ExecMainPID"], 0, 2**31 - 1, "retained ExecMainPID")
    exec_code = _decimal_property(properties["ExecMainCode"], 0, 6, "retained ExecMainCode")
    exec_status = _decimal_property(properties["ExecMainStatus"], 0, 255, "retained ExecMainStatus")
    if properties["InvocationID"] == "":
        _require((exec_pid, exec_code, exec_status) == (0, 0, 0), "unstarted unit carries a completed process")
    elif properties["Result"] == "success":
        _require(exec_pid > 1 and exec_code == 1 and exec_status == 0, "successful retained invocation lacks actual exited-zero main process")
    _require(properties["StartLimitIntervalUSec"] == "10s" and properties["StartLimitBurst"] == "5" and properties["StartLimitAction"] == "none", "effective start limit differs from finite fixed profile")
    if outcome == "reset":
        _require(properties["ActiveState"] == "inactive" and properties["SubState"] == "dead" and properties["Result"] == "success" and properties["InvocationID"] != "", "reset lacks successful completed service invocation")
    group = service["cgroup"]
    _keys(group, ("path", "exists", "pids", "children", "identity"), "service cgroup")
    _require(type(group["path"]) is str and group["path"] in {group_path, "/sys/fs/cgroup" + group_path}, "wrong observed cgroup path")
    _require(type(group["exists"]) is bool and group["pids"] == [] and group["children"] == [], "service cgroup absence was not established")
    if group["exists"]:
        identity = group["identity"]
        _keys(identity, ("device", "inode", "mountId", "uid", "gid", "mode", "kind"), "cgroup identity")
        for field in ("device", "gid"):
            _integer(identity[field], 0, 2**64 - 1, f"cgroup {field}")
        for field in ("inode", "mountId"):
            _integer(identity[field], 1, 2**64 - 1, f"cgroup {field}")
        _integer(identity["uid"], 0, 0, "cgroup owner")
        _integer(identity["mode"], 0, 0o7777, "cgroup mode")
        _require(identity["kind"] == "directory" and identity["mode"] & 0o022 == 0, "untrusted cgroup identity")
    else:
        _require(group["identity"] is None, "absent cgroup carries an identity")
    budget = service["startBudget"]
    _keys(budget, ("bootId", "sessionId", "timestampsMonotonicNs", "lastTerminalMonotonicNs"), "durable start budget")
    _require(budget["bootId"] == service["bootId"], "start budget belongs to another boot")
    _hash(budget["sessionId"], "start budget fixture session")
    timestamps = budget["timestampsMonotonicNs"]
    _require(type(timestamps) is list and len(timestamps) <= 64, "durable start budget exceeds its finite cap")
    for timestamp in timestamps:
        _integer(timestamp, 1, 2**63 - 1, "charged start timestamp")
    _require(all(later - earlier >= START_SPACING_NS for earlier, later in zip(timestamps, timestamps[1:])), "charged starts violate minimum spacing")
    terminal = budget["lastTerminalMonotonicNs"]
    _integer(terminal, 0, 2**63 - 1, "last terminal observation timestamp")
    if outcome == "reset":
        _require(timestamps and terminal >= timestamps[-1], "successful reset lacks a terminal observation after its last charged start")
    return service


def verify(reports, evidence, source_root, expected_source_commit):
    _require(type(expected_source_commit) is str and COMMIT.fullmatch(expected_source_commit) is not None, "invalid expected source commit")
    junit = verify_junit(reports)
    evidence = Path(evidence)
    _inventory(evidence / "cases", {f"{case}.json" for case in CASE_NAMES} | {f"{case}-probe.json" for case in CASE_NAMES})
    _inventory(evidence / "raw", CASE_NAMES)
    profile_hash = qualification_profile_hash(source_root)
    expected_sources = None
    installed_raw = None
    tokens = set()
    controls = []
    receipts = {}
    budgets = {}
    case_events = {}
    boot_id = None
    total_artifact_bytes = 0
    for case_id, name in CASE_NAMES.items():
        raw = read_regular(evidence, f"cases/{case_id}.json", MAX_JSON)
        receipt = _json(raw, "case receipt")
        _keys(receipt, ("schemaVersion", "caseId", "sessionToken", "outcome", "before", "after", "observations", "profileSha256", "sourceCommit", "sourceHashes", "installedManifestSha256", "artifacts"), "case receipt")
        _integer(receipt["schemaVersion"], 1, 1, "receipt schema")
        _require(receipt["caseId"] == case_id, "receipt case identity differs")
        _hash(receipt["sessionToken"], "case session token")
        _require(receipt["sessionToken"] not in tokens, "case session reused")
        tokens.add(receipt["sessionToken"])
        expected_outcome = "refused" if case_id == "K01" else "teardown" if case_id == "K30" else "reset"
        _require(receipt["outcome"] == expected_outcome, "case did not reach its required final outcome")
        _require(receipt["profileSha256"] == profile_hash, "receipt profile identity differs")
        _require(receipt["sourceCommit"] == expected_source_commit, "receipt source commit differs")
        if expected_sources is None:
            verify_sources(source_root, receipt["sourceHashes"])
            expected_sources = receipt["sourceHashes"]
        else:
            _require(receipt["sourceHashes"] == expected_sources, "cases bind different source bytes")
        _snapshot(receipt["before"])
        _snapshot(receipt["after"], teardown=case_id == "K30")
        for field in ("loopRdev", "imageDevice", "imageInode", "imageBytes"):
            _require(receipt["before"][field] == receipt["after"][field], "reset changed reserved loop/image identity")
        if expected_outcome == "reset":
            _require(int(receipt["after"]["generation"]) == int(receipt["before"]["generation"]) + 1 and receipt["after"]["filesystemUuid"] != receipt["before"]["filesystemUuid"] and receipt["after"]["scratch"] != receipt["before"]["scratch"], "reset did not publish exactly one new filesystem generation")
            _require(receipt["after"]["phase"] == "PUBLISHED" and receipt["after"]["gateMode"] == 0o711, "new generation not physically published")
            _require(receipt["after"]["availableBytes"] > 0 and receipt["after"]["availableInodes"] >= 4, "reset did not restore availability")
        elif expected_outcome == "refused":
            _require(receipt["before"] == receipt["after"], "refused access changed registered generation")
        else:
            _require(all(receipt["before"][field] == receipt["after"][field] for field in ("generation", "filesystemUuid", "scratch")), "teardown changed the reserved filesystem generation")
            _require(receipt["after"]["phase"] == "RESERVED_UNMOUNTED" and all(receipt["after"][field] == 0 for field in ("gateMode", "mountId", "availableBytes", "availableInodes")), "teardown did not retain a fenced unmounted reservation")
        artifacts = verify_artifacts(evidence, case_id, receipt["artifacts"])
        total_artifact_bytes += sum(map(len, artifacts.values()))
        _require(total_artifact_bytes <= MAX_TOTAL_ARTIFACTS, "aggregate artifact byte limit")
        _require(receipt["installedManifestSha256"] == _digest(artifacts["manifest.json"]), "installed manifest hash differs")
        if installed_raw is None:
            verify_installed_manifest(artifacts["manifest.json"], expected_sources, profile_hash)
            installed_raw = artifacts["manifest.json"]
        else:
            _require(artifacts["manifest.json"] == installed_raw, "installed profile/tools changed between cases")
        events = verify_observations(receipt, artifacts)
        case_events[case_id] = events
        service = verify_service(artifacts["service.properties"], receipt["outcome"])
        captures = [event for event in events if event["operation"] == "property-read"]
        _require(captures, "service properties lack a bounded actual capture event")
        final_capture = max(captures, key=lambda event: event["endMonotonicNs"])
        _require(final_capture["exitCode"] == 0, "final service property capture did not succeed")
        capture_end = final_capture["endMonotonicNs"]
        budget = service["startBudget"]
        _require(all(stamp <= capture_end for stamp in budget["timestampsMonotonicNs"]) and budget["lastTerminalMonotonicNs"] <= capture_end, "start budget timestamp exceeds actual property capture")
        if receipt["outcome"] == "reset":
            _require(any(attempt["action"] == "finalize" and attempt["exitCode"] == 0 and attempt["phaseAfter"] == "PUBLISHED" and attempt["invocationId"] == service["completedInvocationId"] for attempt in receipt["observations"]["attempts"]), "published reset does not bind the retained completed invocation")
            _require(any(event["exitCode"] == 0 and event["details"].get("reason") == "terminal-empty" and event["details"].get("invocationId") == service["completedInvocationId"] and event["startMonotonicNs"] <= budget["lastTerminalMonotonicNs"] <= event["endMonotonicNs"] for event in captures), "terminal timestamp lacks the matching empty-cgroup completed-invocation observation")
        budgets[case_id] = service["startBudget"]
        if boot_id is None:
            boot_id = service["bootId"]
        _require(service["bootId"] == boot_id, "same-boot reset evidence crosses a reboot")
        probe_raw = read_regular(evidence, f"cases/{case_id}-probe.json", MAX_JSON)
        probe_summary = verify_probe(probe_raw, receipt)
        controls.append({"id": case_id, "name": name, "receiptBytes": len(raw), "receiptSha256": _digest(raw), "probe": probe_summary, "artifacts": receipt["artifacts"]})
        receipts[case_id] = receipt
    _require(receipts["K04"]["observations"]["facts"]["mutatorCount"] == receipts["K03"]["observations"]["facts"]["mutatorCount"], "sparse/deep residue changed the fixed mutator count")
    ordered = [case_id for case_id in CASE_NAMES if case_id != "K30"] + ["K30"]
    continuity_fields = ("generation", "filesystemUuid", "scratch", "mountId", "loopRdev", "imageDevice", "imageInode", "imageBytes")
    for previous, current in zip(ordered, ordered[1:]):
        _require(all(receipts[previous]["after"][field] == receipts[current]["before"][field] for field in continuity_fields), "cases do not preserve one continuous reserved fixture")
    previous_timestamps = []
    previous_terminal = 0
    budget_session = budgets[ordered[0]]["sessionId"]
    for case_id in ordered:
        budget = budgets[case_id]
        timestamps = budget["timestampsMonotonicNs"]
        _require(budget["sessionId"] == budget_session, "start budget fixture session changed")
        _require(timestamps[:len(previous_timestamps)] == previous_timestamps, "durable start budget lost or rewrote prior charges")
        starts = sum(attempt["action"] in {"request", "resume"} for attempt in receipts[case_id]["observations"]["attempts"])
        _require(len(timestamps) - len(previous_timestamps) >= starts, "request or resume is missing its conservative durable charge")
        observed_starts = sorted((event for event in case_events[case_id] if event["operation"] in {"broker-request", "broker-resume"}), key=lambda event: event["startMonotonicNs"])
        new_charges = timestamps[len(previous_timestamps):]
        _require(len(new_charges) >= len(observed_starts) and all(charge <= event["startMonotonicNs"] for charge, event in zip(new_charges, observed_starts)), "actual request or resume precedes its distinct durable start charge")
        _require(budget["lastTerminalMonotonicNs"] >= previous_terminal, "terminal observation timestamp moved backwards")
        if len(timestamps) > len(previous_timestamps) and previous_terminal:
            _require(timestamps[len(previous_timestamps)] - previous_terminal >= START_SPACING_NS, "new start precedes minimum spacing after prior terminal observation")
        previous_timestamps = timestamps
        previous_terminal = budget["lastTerminalMonotonicNs"]
    verify_git_sources(source_root, expected_source_commit, expected_sources)
    return {"schemaVersion": 1, "status": "passed", "class": CLASS, "profile": PROFILE, "profileSha256": profile_hash,
            "sourceCommit": expected_source_commit, "sourceHashes": expected_sources, "installedManifestSha256": _digest(installed_raw), "bootId": boot_id,
            "passed": 32, "skipped": 0, "junit": junit, "controls": controls,
            "scope": "Actual named ext4 reset fixture evidence consistency. Hosted run/job and APT authentication provenance are separate required gates; this report is not reset or whole-run accounting authority."}


def _write_output(source_root, output, raw):
    source_root = Path(os.path.abspath(source_root))
    try:
        relative = Path(os.path.abspath(output)).relative_to(source_root)
    except ValueError as error:
        raise ValueError("gate output must stay under source root") from error
    parts = _relative_parts(relative.as_posix())
    directory = _open_directory(source_root)
    fd = None
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)
        identity = os.fstat(fd)
        _require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1, "gate output must be a single-link ordinary file")
        os.ftruncate(fd, 0)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            _require(written > 0, "short gate report write")
            view = view[written:]
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.reports, args.evidence, args.source_root, args.source_commit)
    except (OSError, ValueError, ET.ParseError) as error:
        result = {"schemaVersion": 1, "status": "failed", "reason": str(error)}
    try:
        _write_output(args.source_root, args.output, canonical(result))
    except (OSError, ValueError) as error:
        print(f"cannot write gate report: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "passed": result.get("passed", 0), "skipped": result.get("skipped", 0), "reason": result.get("reason")}, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
