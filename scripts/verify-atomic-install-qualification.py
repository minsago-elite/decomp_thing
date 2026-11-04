#!/usr/bin/env python3
"""Select and validate the latest producer-shaped atomic-install qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections import Counter
from contextlib import contextmanager

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "build/orchestration/atomic-install-remediation"
CI_EVIDENCE = ROOT / "build/orchestration/atomic-install-ci"
OWNED = (
    "build.gradle.kts",
    "scripts/test-atomic-install.py",
    "scripts/test-atomic-install-controls.py",
    "src/test/java/decompengine/install/AtomicInstallProbeAgent.java",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_POINTER = 64 * 1024
MAX_JSON = 8 * 1024 * 1024
MAX_LOG = 16 * 1024 * 1024
# Publisher: 512 MiB/file, 4 GiB protected runtime; bundled Ghidra: 2 GiB.
# 8 GiB/archive leaves room for both plus helpers/headers. Stream everything;
# 32 GiB total covers both archives and protected files without read-all buffers.
MAX_PROTECTED = 512 * 1024 * 1024
MAX_PROTECTED_RUNTIME = 4 * 1024**3
MAX_ARCHIVE = 8 * 1024**3
MAX_PRODUCTS = 32 * 1024**3
MAX_ENTRIES = 4096
REFERENCES = {"kotlin-boot-classpath-reference-v1.json", "gcc-bundled-ghidra-reference-v1.json",
              "llvm-behavior-hosted-worker-classpath-reference-v1.json"}
FINAL_TASKS = ["installDist", "distZip", "distTar", "verifyGhidraDistributionArchives",
               "verifyAnalysisIoHelperInstalled", "verifyAcpGateHelperDistribution",
               "verifyLlvmBehaviorHelperDistribution", "verifyKotlinBootClasspathDistribution"]
COMMAND_PHASES = ["agent build", "initial A and no-update", "initial A and no-update",
                  "failed-before-rename live A", "live transition A->B", "live transition A->B",
                  "live transition B->A", "live transition B->A", "retained gcc authority",
                  "retained gcc authority", "retained llvm authority", "retained llvm authority",
                  "archive/classpath/helper contracts"]
EXPECTED_RELEASE_SECONDS = 1200 + 120 + 120 + 60


class QualificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def no_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise QualificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


@contextmanager
def regular_stream(path: pathlib.Path, limit: int):
    # Check ancestors as well as the final component. O_NONBLOCK prevents a
    # replaced FIFO from blocking open; fstat rejects it before any read.
    child_path(path.parent, str(path), "read")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as failure:
        raise QualificationError(f"missing/nonregular evidence: {path}: {failure}") from failure
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), f"nonregular evidence: {path}")
        require(before.st_size <= limit, f"evidence exceeds {limit} bytes: {path}")
        yield stream, before
        after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(after) == identity(current), f"file changed during read: {path}")


def read_bytes(path: pathlib.Path, limit: int):
    with regular_stream(path, limit) as (stream, _):
        data = stream.read(limit + 1)
        require(len(data) <= limit, f"evidence grew beyond {limit} bytes: {path}")
    return data


def read_json(path: pathlib.Path, limit: int = MAX_JSON):
    data = read_bytes(path, limit)
    try:
        return json.loads(data, object_pairs_hook=no_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as failure:
        raise QualificationError(f"malformed/truncated JSON evidence: {path}: {failure}") from failure


def file_receipt(path: pathlib.Path, limit: int, budget=None):
    result = hashlib.sha256()
    with regular_stream(path, limit) as (stream, info):
        if budget is not None:
            require(info.st_size <= budget[0], "product aggregate exceeds byte bound")
        total = 0
        while block := stream.read(min(1024 * 1024, limit - total + 1)):
            total += len(block)
            require(total <= limit, f"digest input grew beyond byte bound: {path}")
            result.update(block)
        require(total == info.st_size, f"digest input size changed: {path}")
        if budget is not None:
            budget[0] -= total
    return {"sha256": result.hexdigest(), "mode": stat.S_IMODE(info.st_mode),
            "key": [info.st_dev, info.st_ino], "bytes": total}


def digest(path: pathlib.Path) -> str:
    return file_receipt(path, 128 * 1024 * 1024)["sha256"]


def child_path(base: pathlib.Path, value: str, label: str) -> pathlib.Path:
    require(isinstance(value, str) and value, f"missing {label} path")
    candidate = pathlib.Path(value)
    require(".." not in candidate.parts, f"{label} escapes expected root: {value}")
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = pathlib.Path(os.path.abspath(candidate))
    base_lexical = pathlib.Path(os.path.abspath(base))
    try:
        candidate.relative_to(base_lexical)
    except ValueError as failure:
        raise QualificationError(f"{label} escapes expected root: {value}") from failure
    cursor = candidate
    while cursor != cursor.parent:
        require(not cursor.is_symlink(), f"symlink in {label} path: {cursor}")
        cursor = cursor.parent
    return candidate


def git_source_names(repo: pathlib.Path):
    try:
        return subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=repo, timeout=30).decode().split("\0")
    except (OSError, subprocess.SubprocessError) as failure:
        raise QualificationError(f"cannot enumerate current sources: {failure}") from failure


def current_source_paths(repo: pathlib.Path):
    # Exact source_hashes() inclusion policy, including deleted tracked files and
    # symlink exclusion. Safe opening additionally rejects symlinked ancestors.
    names = set(git_source_names(repo)) | set(OWNED)
    return {name for name in names if name and
            (name.startswith(("src/", "scripts/", "frontend/", "ghidra-bridge/")) or
             name.endswith((".gradle.kts", ".properties"))) and
            (repo / name).is_file() and not (repo / name).is_symlink()}


def current_checkout_head(repo: pathlib.Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                                       stderr=subprocess.PIPE, timeout=10).strip()
    except (OSError, subprocess.SubprocessError) as failure:
        raise QualificationError(f"cannot identify current checkout HEAD: {failure}") from failure


def validate_sources(record: dict, repo: pathlib.Path, expected_head: str):
    require(record.get("sourceHead") == expected_head, "qualification sourceHead differs from expected checkout")
    initial = record.get("sourceHashes")
    final = record.get("finalSourceHashes")
    require(isinstance(initial, dict) and initial, "missing initial full sourceHashes")
    require(isinstance(final, dict) and final == initial, "initial/final full source hashes differ")
    require(set(initial) == current_source_paths(repo), "initial/final/current source path sets differ")
    for name, recorded in initial.items():
        require(isinstance(name, str) and not pathlib.PurePosixPath(name).is_absolute(), "invalid source path")
        require(".." not in pathlib.PurePosixPath(name).parts, f"source escapes checkout: {name}")
        require(isinstance(recorded, str) and SHA256.fullmatch(recorded), f"invalid source digest: {name}")
        path = child_path(repo, name, "source")
        require(digest(path) == recorded, f"current source differs from qualification: {name}")
    owned_initial = {name: initial.get(name) for name in OWNED}
    owned_final = record.get("finalOwnedSourceHashes")
    require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in owned_initial.values()),
            "full sourceHashes omit an owned source")
    require(isinstance(owned_final, dict), "missing finalOwnedSourceHashes")
    for name in OWNED:
        current = digest(child_path(repo, name, "owned source"))
        require(owned_initial[name] == current and owned_final.get(name) == current,
                f"owned source digest differs: {name}")
    return {"full": dict(initial), "owned": {name: digest(repo / name) for name in OWNED}}


def read_log(run_dir: pathlib.Path, command: dict) -> str:
    path = child_path(run_dir, command.get("log", ""), "command log")
    data = read_bytes(path, MAX_LOG)
    require(command.get("logSha256") == hashlib.sha256(data).hexdigest(), "retained command log digest differs")
    return data.decode("utf-8", errors="replace")


def command_args(command: dict) -> list[str]:
    args = command.get("args")
    require(isinstance(args, list) and all(isinstance(item, str) for item in args), "malformed command args")
    return args


def task_arguments(command: dict) -> set[str]:
    return set(command_args(command))


def validate_commands(record: dict, run_dir: pathlib.Path):
    commands = record.get("commands")
    require(isinstance(commands, list) and len(commands) == 13, "expected all 13 external Gradle invocations")
    logs, log_keys = set(), set()
    init_path = child_path(run_dir, "atomic-install.init.gradle", "init script")
    init_digest = file_receipt(init_path, MAX_JSON)["sha256"]
    for index, command in enumerate(commands):
        require(isinstance(command, dict), "malformed command entry")
        require(command.get("status") in {"passed", "failed"}, "incomplete/running Gradle command record")
        exit_code = command.get("exitCode")
        require(type(exit_code) is int and ((exit_code == 0) == (command["status"] == "passed")),
                "Gradle command status and exit code disagree")
        args = command_args(command)
        require(command.get("phase") == COMMAND_PHASES[index], "command phase differs from producer plan")
        # The producer appends exactly this task tail to its common Gradle prefix.
        tail = ["atomicInstallProbeAgentJar"] if index == 0 else ["-I", str(init_path), *(
            FINAL_TASKS if index == 12 else ["installDist"])]
        require(args[-len(tail):] == tail, "command task/init plan differs from producer")
        prefix = args[:-len(tail)]
        require(len(prefix) >= 2 and pathlib.Path(prefix[0]).name == "gradlew" and prefix[1] == "--no-daemon",
                "Gradle command omitted isolated no-daemon execution")
        remaining = prefix[2:]
        while remaining:
            option = remaining.pop(0)
            if option == "-g":
                require(bool(remaining) and bool(remaining.pop(0)), "missing Gradle user home")
            else:
                require(option.startswith(("-Dorg.gradle.jvmargs=", "-Dorg.gradle.java.installations.auto-download=",
                                           "-Dorg.gradle.java.installations.paths=")), "unexpected Gradle task/option")
        log = child_path(run_dir, command.get("log", ""), "command log")
        require(log.parent == run_dir, "command log is not directly under its run")
        read_log(run_dir, command)
        info = log.stat(follow_symlinks=False)
        key = (info.st_dev, info.st_ino)
        require(log not in logs and key not in log_keys, "duplicate command log")
        logs.add(log)
        log_keys.add(key)

    require("atomicInstallProbeAgentJar" in task_arguments(commands[0]) and commands[0].get("status") == "passed",
            "probe-agent build command did not pass")
    require(all(command.get("status") == "passed" for command in commands[1:3]), "initial/no-update install command failed")

    injected = commands[3]
    injected_log = read_log(run_dir, injected)
    require(injected.get("status") == "failed" and isinstance(injected.get("exitCode"), int) and
            injected["exitCode"] != 0 and "atomic-probe injected before first rename" in injected_log and
            "completed renames=0" in injected_log,
            "expected injected failed-before-rename command was not recorded")
    require("installDist" in task_arguments(injected), "pre-rename control did not invoke installDist")
    require(all(command.get("status") == "passed" for command in [*commands[4:9], commands[10]]),
            "A/B transition or retained-authority setup install failed")

    authorities = record.get("authorities")
    require(isinstance(authorities, list) and all(isinstance(item, dict) for item in authorities) and
            [item.get("authority") for item in authorities] == ["gcc", "llvm"],
            "missing exact GCC/LLVM authority records")
    for command_index, authority in ((9, authorities[0]), (11, authorities[1])):
        command = commands[command_index]
        require("installDist" in task_arguments(command), "retained-authority command omitted installDist")
        exit_code = command.get("exitCode")
        require(isinstance(exit_code, int) and exit_code == authority.get("installExit"),
                "authority command exit code differs from retained record")
        if exit_code == 0:
            require(command.get("status") == "passed" and authority.get("probe", {}).get("authorityOutcome") ==
                    "rejected-before-authorization", "successful replacement lacked real authority rejection")
        else:
            log = read_log(run_dir, command)
            require(command.get("status") == "failed" and authority.get("protectedUnchanged") is True and
                    re.search(r"(?i)(lease|resource temporarily unavailable|device or resource busy)", log) and
                    authority.get("probe", {}).get("authorityOutcome") == "unchanged-valid",
                    "nonzero authority install was not an explicit unchanged lease refusal")

    final = commands[12]
    required_tasks = {"installDist", "distZip", "distTar", "verifyGhidraDistributionArchives",
                      "verifyAnalysisIoHelperInstalled", "verifyAcpGateHelperDistribution",
                      "verifyLlvmBehaviorHelperDistribution", "verifyKotlinBootClasspathDistribution"}
    require(final.get("status") == "passed" and required_tasks <= task_arguments(final),
            "final distribution/archive/helper closure command incomplete")
    return {"finalInitSha256": init_digest,
            "limitation": "Final init is overwritten; no historical per-command generation/init identity is inferred."}


def directory_entries(base: pathlib.Path, relative: str):
    directory = child_path(base, relative, "product directory")
    require(directory.is_dir(), f"missing product directory: {directory}")
    result = []
    with os.scandir(directory) as entries:
        for entry in entries:
            require(len(result) < MAX_ENTRIES, "product directory exceeds entry bound")
            require(not entry.is_symlink(), f"symlink product entry: {entry.path}")
            result.append(pathlib.Path(entry.path))
    return result


def validate_products(record: dict, run_dir: pathlib.Path):
    budget = [MAX_PRODUCTS]
    archive_paths = directory_entries(run_dir, "root-build/distributions")
    require(len(archive_paths) == 2 and {p.suffix for p in archive_paths} == {".zip", ".tar"} and
            len({p.stem for p in archive_paths}) == 1 and
            all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,250}", p.stem) for p in archive_paths),
            "expected exactly the matching final ZIP/TAR archive set")
    archives = record.get("archiveHashes")
    require(isinstance(archives, dict) and set(archives) == {str(p) for p in archive_paths},
            "archive receipt path set differs from final ZIP/TAR set")
    verified_archives = {}
    for path in archive_paths:
        receipt = file_receipt(path, MAX_ARCHIVE, budget)
        require(receipt["bytes"] > 0 and archives[str(path)] == receipt["sha256"], "final archive digest differs")
        verified_archives[str(path.relative_to(run_dir))] = receipt

    install = "root-build/install/llm_bin_patch"
    lib = directory_entries(run_dir, install + "/lib")
    bin_files = directory_entries(run_dir, install + "/bin")
    require(not any(p.match(".install-*.tmp") for p in lib + bin_files), "installer left own temporary files")
    jars = [p for p in lib if p.suffix == ".jar"]
    require(jars and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.jar", p.name) for p in jars),
            "invalid or missing protected runtime JAR closure")
    references = [p for p in lib if p.name.endswith("reference-v1.json")]
    require({p.name for p in references} == REFERENCES, "protected reference set differs from production")
    expected = jars + references + [run_dir / install / "bin" / name for name in ("llm_bin_patch", "llm_bin_patch.bat")]
    protected = record.get("finalProtectedFiles")
    require(isinstance(protected, dict) and set(protected) == {str(p.relative_to(run_dir)) for p in expected},
            "protected receipt path set differs from final installation")
    verified_protected = {}
    runtime_bytes = 0
    for path in expected:
        name = str(path.relative_to(run_dir))
        claimed = protected[name]
        mode = 0o755 if path.name == "llm_bin_patch" else 0o644
        require(isinstance(claimed, dict) and type(claimed.get("mode")) is int and claimed["mode"] == mode and
                isinstance(claimed.get("key"), list) and len(claimed["key"]) == 2 and
                all(type(n) is int and n >= 0 for n in claimed["key"]), "malformed protected mode/file key")
        actual = file_receipt(path, MAX_PROTECTED, budget)
        if path.parent.name == "lib":
            runtime_bytes += actual["bytes"]
            require(runtime_bytes <= MAX_PROTECTED_RUNTIME, "protected runtime exceeds aggregate byte bound")
        require(actual["bytes"] > 0 and all(claimed.get(k) == actual[k] for k in ("sha256", "mode", "key")),
                f"final protected bytes/mode/file key differs: {name}")
        verified_protected[name] = actual
    return {"archives": verified_archives, "protected": verified_protected, "bytesVerified": MAX_PRODUCTS - budget[0]}


def validate_probe_files(record: dict, run_dir: pathlib.Path):
    probes = record.get("probes")
    require(isinstance(probes, list) and len(probes) == 8, "expected eight real installed READY probes")
    roots, logs, log_keys = set(), set(), set()
    for index, probe in enumerate(probes):
        require(isinstance(probe, dict) and probe.get("status") == "passed", "installed probe did not pass")
        require(type(probe.get("exitCode")) is int and probe["exitCode"] == 0, "passed probe has nonzero/missing exit")
        probe_root = child_path(run_dir / "barriers", probe.get("root", ""), "probe barrier")
        require(probe_root.is_dir() and not probe_root.is_symlink(), "missing/non-directory probe barrier")
        require(probe_root not in roots, "duplicate probe barrier root")
        roots.add(probe_root)
        log_path = child_path(probe_root, probe.get("log", ""), "probe log")
        require(log_path == probe_root / "launcher.log" and log_path not in logs, "duplicate/unexpected probe log")
        read_log(run_dir, probe)
        info = log_path.stat(follow_symlinks=False)
        key = (info.st_dev, info.st_ino)
        require(key not in log_keys, "duplicate probe log identity")
        logs.add(log_path)
        log_keys.add(key)
        expected_release = "unchanged" if index < 2 else "changed"
        if index >= 6 and record["authorities"][index - 6]["installExit"] != 0:
            expected_release = "lease-refused"
        require(read_bytes(probe_root / "RELEASE", MAX_POINTER) == (expected_release + "\n").encode(),
                "RELEASE differs from producer probe role")
        ready = read_json(probe_root / "READY", limit=64 * 1024)
        loaded = read_json(probe_root / "READY.loaded", limit=64 * 1024)
        require(not os.path.lexists(probe_root / "READY.failure"), "passing probe also has READY.failure")
        require(probe.get("ready") == ready and probe.get("loaded") == loaded,
                "embedded probe record differs from retained READY/loaded evidence")
        marker = probe.get("generation")
        require(ready.get("archiveMarker") == marker and ready.get("modelAbsentBeforeReady") == "true" and
                ready.get("resourceOpenedBeforeReady") == "true" and ready.get("authority") == probe.get("authority"),
                "READY does not prove the producer's installed pre-load barrier")
        require(ready.get("releaseTimeoutSeconds") == str(EXPECTED_RELEASE_SECONDS),
                "READY does not carry the driver's full bounded release budget")
        install_lib = run_dir / "root-build/install/llm_bin_patch/lib"
        cursor = install_lib
        while cursor != run_dir:
            require(not cursor.is_symlink(), f"symlink in installed classpath root: {cursor}")
            cursor = cursor.parent
        require(install_lib.is_dir(), "redirected installed lib directory is missing")
        expected_classpath = {path.resolve() for path in install_lib.glob("*.jar")
                              if path.is_file() and not path.is_symlink()}
        classpath = ready.get("classpath", "").split(os.pathsep)
        actual_classpath = set()
        for value in classpath:
            require(pathlib.Path(value).is_absolute(), "READY classpath path is not absolute")
            path = child_path(install_lib, value, "installed classpath")
            require(path.is_absolute() and path.suffix == ".jar" and not path.is_symlink() and path.is_file(),
                    "READY contains a nonregular installed classpath entry")
            try:
                path.resolve().relative_to(install_lib.resolve())
            except ValueError as failure:
                raise QualificationError("READY classpath escaped the redirected installation") from failure
            actual_classpath.add(path.resolve())
        require(expected_classpath and len(actual_classpath) == len(classpath) and actual_classpath == expected_classpath,
                "READY classpath differs from the exact installed JAR closure")
        require(child_path(install_lib, ready.get("mainOrigin", ""), "MainKt origin") in actual_classpath,
                "READY MainKt origin is outside the exact installed JAR classpath")
        require(loaded.get("lateResourceMarker") == marker and loaded.get("schemaVersion") == "4" and
                loaded.get("inputSha256") == "a" * 64 and loaded.get("modelLoader") == loaded.get("transformLoader") and
                loaded.get("modelOrigin") == loaded.get("transformOrigin"),
                "loaded evidence does not prove the producer's late schema-4 read")
        require(loaded.get("modelOrigin") == ready.get("mainOrigin"),
                "late model origin differs from the installed MainKt origin")
        require(ready.get("descriptorDigest") == loaded.get("descriptorDigest"), "retained descriptor changed in loaded evidence")
        if probe.get("authority") in {"gcc", "llvm"}:
            require(loaded.get("authorityOutcome") in {"unchanged-valid", "rejected-before-authorization"},
                    "retained-authority probe lacks explicit authority outcome")
    return probes


def validate_record(record: dict, run_dir: pathlib.Path, repo: pathlib.Path, expected_head: str):
    require(isinstance(record, dict), "qualification report is not a JSON object")
    require(record.get("status") == "passed" and record.get("phase") == "complete",
            "latest installed qualification did not finish passed/complete")
    require(not record.get("cleanupFailures"), "driver reported child cleanup failures")
    source_digests = validate_sources(record, repo, expected_head)
    agent = child_path(repo, "build/atomic-install/atomic-install-probe-agent.jar", "probe agent")
    require(record.get("agentSha256") == digest(agent), "retained probe-agent digest differs")
    command_receipt = validate_commands(record, run_dir)
    product_receipt = validate_products(record, run_dir)
    probes = validate_probe_files(record, run_dir)

    no_update = record.get("noUpdate")
    require(isinstance(no_update, dict) and no_update.get("status") == "passed" and
            no_update.get("protectedUnchanged") is True and
            no_update.get("probe") == probes[0].get("loaded"),
            "live no-update control missing or failed")
    failed = record.get("failedBeforeRename")
    require(isinstance(failed, dict) and failed.get("lateResourceMarker") == "A" and
            failed.get("schemaVersion") == "4" and
            failed == probes[1].get("loaded"),
            "live failed-before-rename control missing")
    transitions = record.get("transitions")
    require(isinstance(transitions, list) and all(isinstance(item, dict) for item in transitions) and
            [(item.get("from"), item.get("to")) for item in transitions] ==
            [("A", "B"), ("B", "A")], "expected exactly A→B and B→A transitions")
    for transition in transitions:
        require(transition.get("beforeFileKey") != transition.get("afterFileKey"), "transition did not atomically replace app inode")
        old = transition.get("oldParent", {})
        fresh = transition.get("newProcessByInstalledPath", {})
        require(any(old == probe.get("loaded") for probe in probes) and
                any(fresh == probe.get("loaded") for probe in probes),
                "transition observations are not backed by retained installed probes")
        require(old.get("lateResourceMarker") == transition.get("from") and
                old.get("descriptorDigest") != old.get("installedPathDigestAfterRelease") and
                fresh.get("descriptorDigest") == old.get("installedPathDigestAfterRelease"),
                "transition lacks old descriptor/new installed-path observations")
        require(fresh.get("lateResourceMarker") == transition.get("to"), "fresh installed-path probe read wrong generation")
    require(Counter((item.get("generation"), item.get("authority")) for item in probes) ==
            Counter({("A", "none"): 4, ("B", "none"): 2, ("A", "gcc"): 1, ("A", "llvm"): 1}),
            "installed probes do not match the exact no-update/failure/A-B/authority plan")
    require([(p.get("generation"), p.get("authority")) for p in probes] ==
            [("A", "none"), ("A", "none"), ("A", "none"), ("B", "none"),
             ("B", "none"), ("A", "none"), ("A", "gcc"), ("A", "llvm")],
            "installed probe ordering differs from producer roles")
    require(all(isinstance(item, dict) for item in record["authorities"]), "malformed authority record")
    for authority in record["authorities"]:
        require(any(authority.get("probe") == probe.get("loaded") and
                    probe.get("authority") == authority.get("authority") for probe in probes),
                "authority result is not backed by its retained installed probe")
    return source_digests, command_receipt, product_receipt


def validate_controls(repo: pathlib.Path):
    control_runs = sorted((EVIDENCE if repo == ROOT else repo / "build/orchestration/atomic-install-remediation").glob("driver-controls-*/controls.json"))
    require(len(control_runs) == 1, "expected exactly one retained combined driver control record")
    controls_path = child_path(repo, str(control_runs[0]), "combined controls")
    control_record = read_json(controls_path)
    require(isinstance(control_record, dict), "combined controls record is not an object")
    expected_controls = {"distinct-buildDir-production-service-contention/release/task-failure/process-cancel/reacquire",
                         "agent-clock-121-second-update/full-expiry/signed-wrap/backward-rejection",
                         "synthetic-agent-A-B-A-late-loader-origin-resource-descriptor-JSON/no-product-main"}
    require(control_record.get("status") == "passed" and expected_controls <= set(control_record.get("passed", [])),
            "combined Gradle writer/Java-agent controls are incomplete")
    expected_owned = {name: digest(child_path(repo, name, "control source")) for name in OWNED}
    require(control_record.get("sourceHashes") == expected_owned,
            "combined control source hashes do not match current owned sources")
    synthetic_results = read_json(child_path(repo, str(controls_path.parent / "java-fixture/synthetic-agent-results.json"),
                                             "synthetic agent controls"))
    require(isinstance(synthetic_results, list) and len(synthetic_results) == 2 and
            all(isinstance(item, dict) for item in synthetic_results) and
            [(item.get("from"), item.get("to")) for item in synthetic_results] == [("A", "B"), ("B", "A")],
            "synthetic agent A→B/B→A evidence is incomplete")

    publisher_base = repo / "build/atomic-install/publisher-controls"
    require(not publisher_base.is_symlink(), "publisher controls root is a symlink")
    publisher_runs = sorted(publisher_base.glob("run-*/passed.txt"))
    require(len(publisher_runs) == 1, "expected exactly one publisher controls result")
    publisher_result = child_path(repo, str(publisher_runs[0]), "publisher controls receipt")
    require(publisher_result.stat(follow_symlinks=False).st_size <= 64 * 1024,
            "publisher controls receipt is symlinked or exceeds its bound")
    publisher_passed = set(read_bytes(publisher_result, MAX_POINTER).decode("utf-8").splitlines())
    required_publisher = {"source-before-copy", "source-after-copy", "copy-failure", "file-force-failure",
                          "last-stage-file-force", "corrupt-copy", "unsupported-atomic-move",
                          "post-rename-directory-force", "stale-prune-failure", "stale-closure-mismatch",
                          "prune-directory-force", "first-install/replacement/no-update/order/closure/modes",
                          "writer-contention/release/cooperative-cancellation", "symlink-lock-rejection",
                          "pre-Sync-symlink/foreign-write/target-rejection"}
    require(required_publisher <= publisher_passed, "publisher controls result omits required production controls")
    return {"driverControls": str(controls_path.relative_to(repo)),
            "publisherControls": str(publisher_result.relative_to(repo))}


def select_and_verify(repo: pathlib.Path, expected_head: str):
    evidence = repo / "build/orchestration/atomic-install-remediation"
    marker_path = repo / "build/orchestration/atomic-install-ci/driver-started.json"
    marker = read_json(marker_path, MAX_POINTER)
    require(isinstance(marker, dict), "current CI driver-start marker is not an object")
    require(marker.get("sourceHead") == expected_head and isinstance(marker.get("startedAtUnixNs"), int),
            "current CI driver-start marker is missing or identifies another checkout")
    pointer_path = evidence / "latest-installed-run.json"
    pointer = read_json(pointer_path, MAX_POINTER)
    require(isinstance(pointer, dict), "latest installed-run pointer is not an object")
    record_path = child_path(evidence, pointer.get("record", ""), "latest installed run")
    run_dir = record_path.parent
    require(run_dir.name.startswith("installed-") and run_dir.parent == evidence.resolve(),
            "latest pointer does not name a unique installed-* run directly under expected root")
    installed_runs = [path for path in evidence.glob("installed-*") if path.is_dir()]
    require(len(installed_runs) == 1 and installed_runs[0].resolve() == run_dir,
            "latest pointer is stale, ambiguous, or masked by another installed run")
    require(run_dir.stat(follow_symlinks=False).st_ctime_ns >= marker["startedAtUnixNs"],
            "latest installed run predates this CI attempt")
    require(record_path.name == "qualification.json" and pointer.get("record") == str(record_path),
            "latest pointer does not reference qualification.json")
    record = read_json(record_path)
    require(record.get("runRoot") == str(run_dir), "qualification runRoot differs from latest pointer")
    actual_head = current_checkout_head(repo)
    require(actual_head == expected_head, "expected head differs from current checkout")
    source_digests, command_receipt, product_receipt = validate_record(record, run_dir, repo, expected_head)
    control_receipts = validate_controls(repo)
    return {"status": "passed", "sourceHead": actual_head, "record": str(record_path.relative_to(repo)),
            "recordSha256": digest(record_path), "pointerSha256": digest(pointer_path),
            "driverStartedSha256": digest(marker_path),
            "sourceDigests": source_digests, "controls": control_receipts,
            "commands": command_receipt, "verifiedProducts": product_receipt,
            "classification": "consistency/qualification selection; not authentication"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    try:
        result = select_and_verify(ROOT, args.expected_head)
        CI_EVIDENCE.mkdir(parents=True, exist_ok=True)
        receipt = child_path(ROOT, str(CI_EVIDENCE / "verification.json"), "verification output")
        receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        source_evidence = {"sourceHead": result["sourceHead"], "sourceDigests": result["sourceDigests"],
                           "qualificationRecordSha256": result["recordSha256"]}
        child_path(ROOT, str(CI_EVIDENCE / "source-digests.json"), "source output").write_text(
            json.dumps(source_evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0
    except (QualificationError, OSError, ValueError, TypeError) as failure:
        print(f"atomic-install qualification verification failed: {failure}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
