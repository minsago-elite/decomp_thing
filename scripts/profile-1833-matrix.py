#!/usr/bin/env python3
"""Collect bounded, replay-verified analysis timing observations for issue #1833.

This is an evidence-only profiler. It does not authorize reconstruction, mutate
accepted source, or claim source/interface/receipt/compiler-validation coverage.
Those cells require the normal reconstruction and compiler acceptance path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DRIVER_PROFILE = "oracle/gcc/analysis-timing-profile-v1.json"
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_RUN_DIRECTORY_BYTES = 256 * 1024 * 1024
MAX_INDIVIDUAL_FILE_BYTES = MAX_TOTAL_BYTES
MAX_PROGRESS_BYTES = 16 * 1024
SIDECAR_WAIT_SECONDS = 5.0
PROFILE_SWITCH_REFUSAL = "cannot reuse an implementation or different-purpose workspace for evidence-carrier generation"

SUMMARY_SPEC = importlib.util.spec_from_file_location(
    "analysis_timing_summary", ROOT / "scripts" / "summarize-analysis-timings.py"
)
if SUMMARY_SPEC is None or SUMMARY_SPEC.loader is None:
    raise RuntimeError("analysis timing summarizer is unavailable")
SUMMARY = importlib.util.module_from_spec(SUMMARY_SPEC)
SUMMARY_SPEC.loader.exec_module(SUMMARY)


class MatrixError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_repo_child(path: Path, label: str) -> Path:
    resolved = path.resolve()
    build_root = (ROOT / "build").resolve()
    if resolved == build_root or build_root not in resolved.parents:
        raise MatrixError(f"{label} must be a new directory beneath repository build/")
    lexical = Path(os.path.abspath(path))
    if lexical == ROOT or ROOT not in lexical.parents:
        raise MatrixError(f"{label} must be beneath the repository root")
    current = lexical
    while current != ROOT:
        if current.exists() and current.is_symlink():
            raise MatrixError(f"{label} cannot traverse a symbolic link")
        current = current.parent
    return resolved


def load_archival_fixture(fixture_id: str, binary_kind: str) -> dict[str, Any]:
    manifest_path = ROOT / "benchmarks/archival/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture = next((item for item in manifest["fixtures"] if item["id"] == fixture_id), None)
    if fixture is None:
        raise MatrixError(f"unknown archival fixture: {fixture_id}")
    binary = next((item for item in fixture["binaries"] if item["symbols"] == binary_kind), None)
    if binary is None:
        raise MatrixError(f"fixture {fixture_id} has no {binary_kind} binary")
    path = ROOT / "benchmarks/archival" / binary["path"]
    if path.is_symlink() or not path.is_file():
        raise MatrixError(f"pinned input is absent or not a regular file: {binary['path']}")
    actual = sha256_file(path)
    if actual != binary["sha256"]:
        raise MatrixError(f"fixture digest mismatch for {binary['path']}")
    return {"id": fixture_id, "path": path, "sha256": actual,
        "manifest": str(manifest_path.relative_to(ROOT)), "manifestSha256": sha256_file(manifest_path)}


def load_driver_fixture(root: Path = ROOT) -> dict[str, Any]:
    profile_relative = PurePosixPath(DRIVER_PROFILE)
    if profile_relative.is_absolute() or profile_relative.as_posix() != DRIVER_PROFILE or \
            any(part in {"", ".", ".."} for part in profile_relative.parts):
        raise MatrixError("pinned driver profile path is unsafe")
    profile_path = root.joinpath(*profile_relative.parts)
    current = root
    for index, part in enumerate(profile_relative.parts):
        current = current / part
        if current.is_symlink():
            raise MatrixError("pinned driver profile traverses a link")
        if index < len(profile_relative.parts) - 1 and not current.is_dir():
            raise MatrixError("pinned driver profile parent is not a directory")
    profile_root = profile_path.parent
    if not profile_path.is_file() or profile_path.stat().st_size > 16 * 1024:
        raise MatrixError("pinned driver profile is absent, linked, or oversized")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict) or set(profile) != {"schemaVersion", "driver"} or \
            type(profile.get("schemaVersion")) is not int or profile["schemaVersion"] != 1:
        raise MatrixError("unsupported pinned driver profile")
    driver = profile.get("driver")
    fields = {"id", "path", "sha256", "identityName", "identityManifest"}
    if not isinstance(driver, dict) or set(driver) != fields:
        raise MatrixError("pinned driver profile has unsupported fields")
    if not isinstance(driver["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", driver["id"]):
        raise MatrixError("pinned driver profile has invalid id")
    if not isinstance(driver["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", driver["sha256"]):
        raise MatrixError("pinned driver profile has invalid digest")
    if not isinstance(driver["identityName"], str) or not driver["identityName"]:
        raise MatrixError("pinned driver profile has invalid identity name")

    def relative_path(value: object, label: str) -> Path:
        if not isinstance(value, str) or not value or "\\" in value or any(ord(char) < 32 for char in value):
            raise MatrixError(f"pinned driver profile has invalid {label}")
        relative = PurePosixPath(value)
        if relative.is_absolute() or relative.as_posix() != value or any(part in {"", ".", ".."} for part in relative.parts):
            raise MatrixError(f"pinned driver profile has unsafe {label}")
        path = profile_root.joinpath(*relative.parts)
        current = profile_root
        for index, part in enumerate(relative.parts):
            current = current / part
            if current.is_symlink():
                raise MatrixError(f"pinned driver profile {label} traverses a link")
            if index < len(relative.parts) - 1 and not current.is_dir():
                raise MatrixError(f"pinned driver profile {label} has a non-directory parent")
        return path

    binary_path = relative_path(driver["path"], "binary path")
    catalog_path = relative_path(driver["identityManifest"], "identity manifest")
    if not binary_path.is_file() or binary_path.stat().st_size > MAX_INDIVIDUAL_FILE_BYTES:
        raise MatrixError("pinned driver binary is absent or not a regular file")
    if not catalog_path.is_file() or catalog_path.stat().st_size > 1024 * 1024:
        raise MatrixError("pinned driver identity manifest is absent, linked, or oversized")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or type(catalog.get("schemaVersion")) is not int or \
            catalog.get("schemaVersion") != 1 or not isinstance(catalog.get("identities"), list):
        raise MatrixError("unsupported pinned driver identity manifest")
    identities = [item for item in catalog["identities"]
        if isinstance(item, dict) and item.get("name") == driver["identityName"]]
    if len(identities) != 1 or identities[0].get("sha256") != driver["sha256"]:
        raise MatrixError("pinned driver identity does not match its identity manifest")
    actual = sha256_file(binary_path)
    if actual != driver["sha256"]:
        raise MatrixError("pinned driver binary digest differs from its identity manifest")
    return {
        "id": driver["id"],
        "path": binary_path,
        "sha256": actual,
        "manifest": str(profile_path.relative_to(root)),
        "manifestSha256": sha256_file(profile_path),
        "identityManifest": str(catalog_path.relative_to(root)),
        "identityManifestSha256": sha256_file(catalog_path),
        "identityName": driver["identityName"],
    }


def fixtures() -> dict[str, dict[str, Any]]:
    return {
        "large_project_mtu": load_archival_fixture("large_project_mtu", "stripped"),
        "large_project": load_archival_fixture("large_project", "stripped"),
        "gcc_driver": load_driver_fixture(),
    }


def safe_environment(home: Path, temporary: Path) -> dict[str, str]:
    """Run the agent-free CLI without inheriting provider credentials or GHIDRA_HOME."""
    resolved_home = home.resolve(strict=True)
    resolved_temporary = temporary.resolve(strict=True)
    for label, directory in (("home", resolved_home), ("temporary", resolved_temporary)):
        if directory == ROOT or ROOT not in directory.parents or not directory.is_dir():
            raise MatrixError(f"profiling JVM {label} directory must be a real repository-local directory")

    def java_path_option(name: str, value: Path) -> str:
        rendered = str(value)
        if '"' in rendered or "\\" in rendered or any(ord(char) < 0x20 for char in rendered):
            raise MatrixError("profiling JVM directory path has characters unsafe for its option parser")
        return f'-D{name}="{rendered}"'

    java_tool_options = " ".join((
        java_path_option("user.home", resolved_home),
        java_path_option("java.io.tmpdir", resolved_temporary),
        java_path_option("jna.tmpdir", resolved_temporary),
        "-XX:-UsePerfData",
    ))
    env = {key: value for key, value in os.environ.items() if key in {
        "PATH", "JAVA_HOME", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "WINDIR"
    }}
    env["HOME"] = str(resolved_home)
    env["TMPDIR"] = str(resolved_temporary)
    env["TMP"] = str(resolved_temporary)
    env["TEMP"] = str(resolved_temporary)
    env["JAVA_TOOL_OPTIONS"] = java_tool_options
    return env


def history_ids(output: Path) -> set[str]:
    root = output / "run-history"
    if not root.exists():
        return set()
    if root.is_symlink() or not root.is_dir():
        raise MatrixError("run-history is not a real directory")
    found = set()
    for entry in root.iterdir():
        if RUN_ID.fullmatch(entry.name) and not entry.is_symlink() and entry.is_dir():
            found.add(entry.name)
    return found


def history_ids_started_during(output: Path, started_at: datetime, completed_at: datetime) -> list[str]:
    """Identify this CLI invocation even when input switching restores old run-history directories."""
    root = output / "run-history"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise MatrixError("run-history is not a real directory")
    matches = []
    for run_id in sorted(history_ids(output)):
        directory = root / run_id
        metadata_path = directory / "run.json"
        if metadata_path.is_symlink() or not metadata_path.is_file() or metadata_path.stat().st_size > 16 * 1024:
            raise MatrixError("run history metadata is absent, linked, or oversized")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            started_value = metadata.get("startedAt")
            if not isinstance(started_value, str):
                raise MatrixError("run history metadata has no valid invocation timestamp")
            run_started = datetime.fromisoformat(started_value.replace("Z", "+00:00"))
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as problem:
            raise MatrixError("run history metadata has no valid invocation timestamp") from problem
        if metadata.get("runId") != run_id or run_started.tzinfo is None:
            raise MatrixError("run history identity or timestamp is invalid")
        if started_at <= run_started <= completed_at:
            matches.append(run_id)
    return matches


def profile_output_hashes(output: Path) -> dict[str, str]:
    """Bind the generated result around a refused evidence-carrier profile switch."""
    paths = (
        "source-tree.zip",
        "reconstruction.json",
        "analysis/reports/program_model.json",
        "analysis/reports/program_model.json.progress.json",
    )
    result: dict[str, str] = {}
    for relative in paths:
        path = output / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INDIVIDUAL_FILE_BYTES:
            raise MatrixError(f"profile-switch output is absent, linked, or oversized: {relative}")
        result[relative] = sha256_file(path)
    return result


def classify_profile_switch_refusal(return_code: int, stderr: str,
                                    before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    if return_code == 0:
        raise MatrixError("evidence-carrier profile switch unexpectedly succeeded")
    if PROFILE_SWITCH_REFUSAL not in stderr:
        raise MatrixError("profile switch failed without the expected evidence-carrier refusal")
    if before != after:
        raise MatrixError("refused evidence-carrier profile switch changed generated output")
    return {"status": "refused", "reason": "evidence-carrier profile identity is fixed for an output",
        "diagnostic": PROFILE_SWITCH_REFUSAL, "generatedOutputUnchanged": True}


def capture_profile_switch_refusal(cli: Path, output: Path, fixture: dict[str, Any], label: str,
                                   evidence: Path, budget: list[int]) -> dict[str, Any]:
    attempt_dir = evidence / "observations" / label
    home = attempt_dir / "home"
    temporary = attempt_dir / "tmp"
    home.mkdir(parents=True, exist_ok=False)
    temporary.mkdir(parents=True, exist_ok=False)
    before = profile_output_hashes(output)
    command = [str(cli), "reconstruct", str(fixture["path"]), "--output", str(output),
        "--profile", "generated-c-ninja-v1", "--evidence-only"]
    host_before = host_sample()
    invocation_started = datetime.now(timezone.utc)
    result = run_logged(command, ROOT, safe_environment(home, temporary), attempt_dir / "cli")
    invocation_completed = datetime.now(timezone.utc)
    host_after = host_sample()
    stderr_path = ROOT / result["stderrPath"]
    if stderr_path.stat().st_size > 64 * 1024:
        raise MatrixError("profile-switch refusal diagnostic exceeded its 64 KiB bound")
    refusal = classify_profile_switch_refusal(result["returnCode"],
        stderr_path.read_text(encoding="utf-8", errors="replace"), before, profile_output_hashes(output))
    run_ids = history_ids_started_during(output, invocation_started, invocation_completed)
    if len(run_ids) != 1:
        raise MatrixError(f"{label}: expected one journal for the refused invocation, found {len(run_ids)}")
    run_id = run_ids[0]
    run_directory = output / "run-history" / run_id
    metadata_path = run_directory / "run.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("state") != "closed" or metadata.get("complete") is not True or \
            metadata.get("lastPhase") != "failed" or metadata.get("runId") != run_id:
        raise MatrixError(f"{label}: refused profile invocation has no complete failed run record")
    list_log = run_logged([str(cli), "runs", "list", str(output)], ROOT,
        safe_environment(home, temporary), attempt_dir / "list")
    replay_log = run_logged([str(cli), "runs", "replay", str(output), run_id], ROOT,
        safe_environment(home, temporary), attempt_dir / "replay")
    if list_log["returnCode"] != 0 or replay_log["returnCode"] != 0:
        raise MatrixError(f"{label}: refused profile run history does not list/replay")
    retained_history = attempt_dir / "evidence" / "run-history" / run_id
    copy_bounded(run_directory, retained_history, budget)
    timing_dir = output / "analysis/reports/analysis-timings"
    retained_timing = None
    timing_digest = None
    try:
        sidecar = wait_for_sidecar(timing_dir, run_id)
    except MatrixError as missing_sidecar:
        if str(missing_sidecar) != "no timing sidecar correlated to the completed workflow run":
            raise
    else:
        retained_timing = attempt_dir / "evidence" / "analysis-timing.json"
        copy_bounded(sidecar, retained_timing, budget)
        timing_digest = sha256_file(retained_timing)
    observation: dict[str, Any] = {
        "label": label,
        "input": {"path": str(fixture["path"].relative_to(ROOT)), "sha256": fixture["sha256"]},
        "profile": "generated-c-ninja-v1",
        "cli": result,
        "hostBefore": host_before,
        "hostAfter": host_after,
        "invocationStartedAt": invocation_started.isoformat(),
        "invocationCompletedAt": invocation_completed.isoformat(),
        "runId": run_id,
        "runHistoryMetadata": metadata,
        "runHistoryPath": str(retained_history.relative_to(ROOT)),
        "timingSidecar": str(retained_timing.relative_to(ROOT)) if retained_timing else None,
        "timingSidecarSha256": timing_digest,
        "timingCoverage": "present" if retained_timing else "no sidecar matched the refused invocation; no phase timing claimed",
        "runsListReturnCode": list_log["returnCode"],
        "runsReplayReturnCode": replay_log["returnCode"],
        "beforeOutputSha256": before,
        "afterOutputSha256": profile_output_hashes(output),
        **refusal,
    }
    if directory_bytes(evidence) > MAX_TOTAL_BYTES:
        raise MatrixError("matrix workspace and retained evidence exceed the 4 GiB total byte limit")
    return observation


def copy_bounded(source: Path, destination: Path, budget: list[int]) -> None:
    if source.is_symlink():
        raise MatrixError(f"refusing to retain linked evidence entry: {source}")
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=False)
        for child in sorted(source.iterdir()):
            copy_bounded(child, destination / child.name, budget)
        return
    if not source.is_file():
        raise MatrixError(f"refusing to retain special evidence entry: {source}")
    size = source.stat().st_size
    budget[0] += size
    if budget[0] > MAX_TOTAL_BYTES:
        raise MatrixError("retained matrix evidence exceeds the 4 GiB total byte limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def directory_bytes(path: Path) -> int:
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        base = Path(root)
        for name in directories + files:
            entry = base / name
            if entry.is_symlink():
                raise MatrixError(f"matrix workspace contains a link: {entry}")
            if entry.is_file():
                total += entry.stat().st_size
    return total


def run_logged(command: list[str], cwd: Path, env: dict[str, str], log_dir: Path) -> dict[str, Any]:
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / "stdout.log"
    stderr_path = log_dir / "stderr.log"
    started = time.monotonic_ns()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        completed = subprocess.run(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
            check=False, preexec_fn=limit_child_files)
    duration = max(0, time.monotonic_ns() - started)
    return {
        "command": command,
        "returnCode": completed.returncode,
        "durationNanos": duration,
        "stdoutPath": str(stdout_path.relative_to(ROOT)),
        "stderrPath": str(stderr_path.relative_to(ROOT)),
        "stdoutSha256": sha256_file(stdout_path),
        "stderrSha256": sha256_file(stderr_path),
    }


def limit_child_files() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_INDIVIDUAL_FILE_BYTES, MAX_INDIVIDUAL_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def read_context(run_directory: Path) -> dict[str, Any]:
    path = run_directory / "events.jsonl"
    contexts: list[dict[str, Any]] = []
    event_kinds: dict[str, int] = {}
    if path.is_symlink() or not path.is_file():
        raise MatrixError("run history has no regular events.jsonl")
    with path.open("rb") as stream:
        for raw in stream:
            if len(raw) > 64 * 1024 + 1:
                raise MatrixError("run history contains an oversized event")
            envelope = json.loads(raw)
            event = envelope.get("event")
            if isinstance(event, dict):
                kind = event.get("kind")
                if isinstance(kind, str):
                    event_kinds[kind] = event_kinds.get(kind, 0) + 1
                    if kind == "run_context":
                        contexts.append(event)
    if len(contexts) != 1:
        raise MatrixError("successful run history must contain exactly one run_context event")
    context = contexts[0]
    for key in ("inputSha256", "profileSha256"):
        if not isinstance(context.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", context[key]):
            raise MatrixError(f"run_context has no valid {key}")
    return {
        "inputSha256": context["inputSha256"],
        "profileSha256": context["profileSha256"],
        "agentTasks": event_kinds.get("task_started", 0),
        "reusedModuleCheckpoints": event_kinds.get("module_checkpoint_reused", 0),
        "eventKinds": event_kinds,
    }


def wait_for_sidecar(timing_dir: Path, run_id: str) -> Path:
    deadline = time.monotonic() + SIDECAR_WAIT_SECONDS
    while time.monotonic() <= deadline:
        if timing_dir.exists():
            matches = []
            for path in timing_dir.glob("*.json"):
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > 1024 * 1024:
                    continue
                try:
                    if json.loads(path.read_text(encoding="utf-8")).get("workflowRunId") == run_id:
                        matches.append(path)
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise MatrixError("multiple timing sidecars claim one workflow run")
        time.sleep(0.05)
    raise MatrixError("no timing sidecar correlated to the completed workflow run")


def read_exporter_progress(output: Path) -> tuple[dict[str, Any], Path]:
    path = output / "analysis/reports/program_model.json.progress.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_PROGRESS_BYTES:
        raise MatrixError("bounded exporter progress record is absent, linked, or oversized")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise MatrixError("unsupported exporter progress record")
    if value.get("phase") != "complete":
        raise MatrixError("exporter did not publish a terminal progress phase")
    for key in ("completed", "total", "recovered", "partial", "failed", "reused"):
        if not isinstance(value.get(key), int) or isinstance(value[key], bool) or value[key] < 0:
            raise MatrixError(f"exporter progress has invalid {key}")
    if value["completed"] > value["total"] or value["reused"] > value["completed"]:
        raise MatrixError("exporter progress counters are inconsistent")
    return value, path


def capture_run(cli: Path, output: Path, fixture: dict[str, Any], profile: str,
                label: str, evidence: Path, budget: list[int]) -> dict[str, Any]:
    attempt_dir = evidence / "observations" / label
    home = attempt_dir / "home"
    temporary = attempt_dir / "tmp"
    home.mkdir(parents=True, exist_ok=False)
    temporary.mkdir(parents=True, exist_ok=False)
    command = [str(cli), "reconstruct", str(fixture["path"]), "--output", str(output),
        "--profile", profile, "--evidence-only"]
    host_before = host_sample()
    invocation_started = datetime.now(timezone.utc)
    result = run_logged(command, ROOT, safe_environment(home, temporary), attempt_dir / "cli")
    invocation_completed = datetime.now(timezone.utc)
    host_after = host_sample()
    new_ids = history_ids_started_during(output, invocation_started, invocation_completed)
    input_binding: dict[str, Any] = {
        "path": str(fixture["path"].relative_to(ROOT)),
        "sha256": fixture["sha256"],
    }
    for key in ("manifest", "manifestSha256", "identityManifest", "identityManifestSha256", "identityName"):
        if key in fixture:
            input_binding[key] = fixture[key]
    observation: dict[str, Any] = {
        "label": label,
        "input": input_binding,
        "profile": profile,
        "cli": result,
        "hostBefore": host_before,
        "hostAfter": host_after,
        "invocationStartedAt": invocation_started.isoformat(),
        "invocationCompletedAt": invocation_completed.isoformat(),
        "newRunIds": new_ids,
        "replayReturnCodes": {},
        "status": "failed",
    }
    if directory_bytes(evidence) > MAX_TOTAL_BYTES:
        raise MatrixError("matrix workspace and evidence exceeded the 4 GiB total byte limit")
    if result["returnCode"] != 0:
        return observation
    if len(new_ids) != 1:
        raise MatrixError(f"{label}: expected one new run id, found {len(new_ids)}")
    run_id = new_ids[0]
    run_directory = output / "run-history" / run_id
    if directory_bytes(run_directory) > MAX_RUN_DIRECTORY_BYTES:
        raise MatrixError(f"{label}: run history exceeds its 256 MiB per-run bound")
    metadata_path = run_directory / "run.json"
    if metadata_path.is_symlink() or not metadata_path.is_file() or metadata_path.stat().st_size > 16 * 1024:
        raise MatrixError(f"{label}: run history metadata is absent, linked, or oversized")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("state") != "closed" or metadata.get("complete") is not True:
        raise MatrixError(f"{label}: run history is not durably complete")
    context = read_context(run_directory)
    if context["inputSha256"] != fixture["sha256"]:
        raise MatrixError(f"{label}: run history input binding differs from the pinned binary")
    if metadata.get("runId") != run_id:
        raise MatrixError(f"{label}: run history metadata is bound to a different run")

    list_log = run_logged([str(cli), "runs", "list", str(output)], ROOT,
        safe_environment(home, temporary), attempt_dir / "list")
    replay_log = run_logged([str(cli), "runs", "replay", str(output), run_id], ROOT,
        safe_environment(home, temporary), attempt_dir / "replay")
    observation["replayReturnCodes"]["list"] = list_log["returnCode"]
    observation["replayReturnCodes"]["replay"] = replay_log["returnCode"]
    if list_log["returnCode"] != 0 or replay_log["returnCode"] != 0:
        raise MatrixError(f"{label}: run history list/replay failed")
    listed_stdout = ROOT / list_log["stdoutPath"]
    if listed_stdout.stat().st_size > 1024 * 1024:
        raise MatrixError(f"{label}: run history listing output exceeded its 1 MiB limit")
    listed_ids = {
        fields[0]
        for line in listed_stdout.read_text(encoding="utf-8").splitlines()
        if (fields := line.split(maxsplit=1))
    }
    if run_id not in listed_ids:
        raise MatrixError(f"{label}: the completed run does not appear in runs list")

    timing_dir = output / "analysis/reports/analysis-timings"
    sidecar = wait_for_sidecar(timing_dir, run_id)
    if sidecar.stat().st_size > 1024 * 1024:
        raise MatrixError(f"{label}: timing sidecar exceeded its 1 MiB limit")
    timing_record = SUMMARY.load_record(sidecar)
    if timing_record.get("workflowRunId") != run_id:
        raise MatrixError(f"{label}: timing sidecar workflowRunId mismatch")
    if timing_record.get("inputSha256") != fixture["sha256"]:
        raise MatrixError(f"{label}: timing sidecar input binding differs from the pinned binary")
    if timing_record.get("profileSha256") != context["profileSha256"]:
        raise MatrixError(f"{label}: timing sidecar profile binding differs from run history")
    exporter_progress, exporter_progress_path = read_exporter_progress(output)

    retained_history = attempt_dir / "evidence" / "run-history" / run_id
    copy_bounded(run_directory, retained_history, budget)
    retained_timing = attempt_dir / "evidence" / "analysis-timing.json"
    copy_bounded(sidecar, retained_timing, budget)
    retained_progress = attempt_dir / "evidence" / "exporter-progress.json"
    copy_bounded(exporter_progress_path, retained_progress, budget)
    archive = output / "source-tree.zip"
    archive_hash = sha256_file(archive) if archive.is_file() and not archive.is_symlink() else None
    observation.update({
        "runId": run_id,
        "context": context,
        "timingSidecar": str(retained_timing.relative_to(ROOT)),
        "timingSidecarSha256": sha256_file(retained_timing),
        "exporterProgress": exporter_progress,
        "exporterProgressPath": str(retained_progress.relative_to(ROOT)),
        "exporterProgressSha256": sha256_file(retained_progress),
        "runHistoryPath": str(retained_history.relative_to(ROOT)),
        "runHistoryMetadata": metadata,
        "archiveSha256": archive_hash,
        "reconstructionManifestSha256": sha256_file(output / "reconstruction.json")
            if (output / "reconstruction.json").is_file() and not (output / "reconstruction.json").is_symlink()
            else None,
        "status": "passed",
    })
    if directory_bytes(evidence) > MAX_TOTAL_BYTES:
        raise MatrixError("matrix workspace and retained evidence exceed the 4 GiB total byte limit")
    return observation


def host_pins(cli: Path) -> dict[str, Any]:
    java_home = os.environ.get("JAVA_HOME")
    java_candidate = Path(java_home) / "bin/java" if java_home else None
    java = str(java_candidate) if java_candidate is not None and java_candidate.is_file() else shutil.which("java")
    if java is None:
        raise MatrixError("java is not available for runtime identity capture")
    java_version = None
    java_sha256 = None
    java_path = Path(java).resolve()
    if not java_path.is_file():
        raise MatrixError("resolved java executable is not a regular file")
    java_sha256 = sha256_file(java_path)
    java_environment = {key: value for key, value in os.environ.items()
        if key in {"PATH", "JAVA_HOME", "LANG", "LC_ALL", "TZ"}}
    result = subprocess.run([java, "-version"], cwd=ROOT, env=java_environment,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=10)
    if result.returncode != 0:
        raise MatrixError("java -version failed during runtime identity capture")
    java_version = result.stdout.decode("utf-8", errors="replace")[:4096]
    cpu_model = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[-1].strip()
                break
    install_root = cli.parent.parent
    bundle_manifest = install_root / "lib/gcc-bundled-ghidra-reference-v1.json"
    app_jars = sorted((path.relative_to(install_root).as_posix(), sha256_file(path))
        for path in (install_root / "lib").glob("*.jar") if path.is_file() and not path.is_symlink())
    if not bundle_manifest.is_file() or bundle_manifest.is_symlink():
        raise MatrixError("installed bundled-Ghidra identity manifest is missing")
    if not app_jars:
        raise MatrixError("installed application JAR inventory is empty")
    return {
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.strip(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "cpuCount": os.cpu_count(),
        "cpuModel": cpu_model,
        "hostSample": host_sample(),
        "javaVersion": java_version,
        "javaPath": str(java_path),
        "javaSha256": java_sha256,
        "ghidraBundleManifestSha256": sha256_file(bundle_manifest),
        "applicationJars": [{"path": path, "sha256": digest} for path, digest in app_jars],
        "cliSha256": sha256_file(cli),
    }


def host_sample() -> dict[str, Any]:
    memory_total = None
    memory_available = None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                fields = line.split()
                if len(fields) >= 2 and fields[1].isdigit():
                    memory_total = int(fields[1]) * 1024
            elif line.startswith("MemAvailable:"):
                fields = line.split()
                if len(fields) >= 2 and fields[1].isdigit():
                    memory_available = int(fields[1]) * 1024
    return {
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "loadAverage": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "memoryTotalBytes": memory_total,
        "memoryAvailableBytes": memory_available,
    }


def run_matrix(cli_arg: Path, evidence_arg: Path, repetitions: int) -> dict[str, Any]:
    if not cli_arg.is_absolute():
        cli_arg = ROOT / cli_arg
    if not evidence_arg.is_absolute():
        evidence_arg = ROOT / evidence_arg
    cli_lexical = Path(os.path.abspath(cli_arg))
    if cli_lexical.is_symlink():
        raise MatrixError("--cli cannot name a symbolic link")
    cli = cli_arg.resolve(strict=True)
    if cli.is_symlink() or not cli.is_file() or not os.access(cli, os.X_OK):
        raise MatrixError("--cli must name a regular executable file")
    evidence = require_repo_child(evidence_arg, "evidence directory")
    if evidence.exists():
        raise MatrixError("evidence directory already exists; refusing to overwrite retained data")
    workspace = evidence / "workspace"
    workspace.mkdir(parents=True)
    budget = [0]
    available = fixtures()
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "issue": 1833,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "scope": "agent-free evidence-only analysis; no reconstruction acceptance authority",
        "hostPins": host_pins(cli),
        "repetitions": repetitions,
        "fixtures": {},
        "unrunCells": {
            "partial-resume": "No deterministic checkpoint interruption control is provided by this harness.",
            "exporter-invalidation": "Requires a controlled exporter replacement and verified recapture.",
            "analysis-tool-invalidation": "Requires a separate authenticated bundled-tool replacement.",
            "profile-invalidation": "Evidence-carrier output is bound to one exact profile. The matrix records the refusal and runs Ninja independently; accepted implementation-profile invalidation requires the full reconstruction/compiler path.",
            "source-invalidation": "Requires the full reconstruction/compiler acceptance path.",
            "interface-invalidation": "Requires the full reconstruction/compiler acceptance path.",
            "receipt-invalidation": "Requires the full reconstruction/compiler acceptance path.",
            "compiler-validation-invalidation": "Requires configured compiler acceptance.",
            "binary_01": "The retained canonical binary pin is not available in the repository manifest.",
            "compiler-identity": "No compiler is executed by the evidence-only profiling path.",
        },
        "evidenceBytesCopied": 0,
    }
    report_path = evidence / "matrix.json"

    def persist() -> None:
        report["evidenceBytesCopied"] = budget[0]
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(report_path)

    def observe(collection: dict[str, Any], output: Path, fixture: dict[str, Any], profile: str,
                label: str) -> dict[str, Any]:
        row: dict[str, Any] = {"label": label, "status": "running"}
        collection["observations"].append(row)
        persist()
        try:
            result = capture_run(cli, output, fixture, profile, label, evidence, budget)
        except Exception as failure:
            row.update({"status": "failed", "failureType": type(failure).__name__,
                "failure": str(failure)[:512]})
            persist()
            raise
        row.clear()
        row.update(result)
        persist()
        if row["status"] != "passed":
            raise MatrixError(f"{label}: CLI returned failure; stdout/stderr remain retained")
        return row

    try:
        for fixture_id in ("large_project_mtu", "gcc_driver"):
            fixture = available[fixture_id]
            fixture_dir = workspace / fixture_id
            fixture_dir.mkdir()
            fixture_record = report["fixtures"].setdefault(fixture_id, {
                "input": {"path": str(fixture["path"].relative_to(ROOT)), "sha256": fixture["sha256"],
                    "manifest": fixture["manifest"], "manifestSha256": fixture["manifestSha256"],
                    **({"identityManifest": fixture["identityManifest"],
                        "identityManifestSha256": fixture["identityManifestSha256"],
                        "identityName": fixture["identityName"]} if "identityManifest" in fixture else {})},
                "observations": [],
            })
            for repetition in range(1, repetitions + 1):
                output = fixture_dir / f"baseline-{repetition:02d}"
                output.mkdir()
                observe(fixture_record, output, fixture, "generated-c-make-v1",
                    f"{fixture_id}-fresh-{repetition:02d}")
                for resume_index in range(1, repetitions + 1):
                    observe(fixture_record, output, fixture, "generated-c-make-v1",
                        f"{fixture_id}-complete-resume-{repetition:02d}-{resume_index:02d}")

        switch_fixture = available["large_project_mtu"]
        other_input = available["large_project"]
        switch_output = workspace / "shared-input-switch"
        switch_output.mkdir()
        switch_records = report["fixtures"].setdefault("shared-input-switch", {"observations": []})
        for index, fixture in enumerate((switch_fixture, other_input, switch_fixture), start=1):
            observe(switch_records, switch_output, fixture, "generated-c-make-v1", f"input-switch-{index}")

        profile_output = workspace / "profile-switch"
        profile_output.mkdir()
        profile_records = report["fixtures"].setdefault("profile-switch", {"observations": []})
        observe(profile_records, profile_output, switch_fixture, "generated-c-make-v1", "profile-switch-make-before")
        refusal = capture_profile_switch_refusal(cli, profile_output, switch_fixture,
            "profile-switch-ninja-refused", evidence, budget)
        profile_records["observations"].append(refusal)
        persist()
        observe(profile_records, profile_output, switch_fixture, "generated-c-make-v1", "profile-switch-make-after")

        independent_ninja_output = workspace / "profile-ninja-independent"
        independent_ninja_output.mkdir()
        observe(profile_records, independent_ninja_output, switch_fixture,
            "generated-c-ninja-v1", "ninja-independent-fresh")
        observe(profile_records, independent_ninja_output, switch_fixture,
            "generated-c-ninja-v1", "ninja-independent-complete-resume")

        sidecars = sorted(evidence.glob("observations/*/evidence/analysis-timing.json"))
        summary = SUMMARY.summarize(sidecars)
        summary_path = evidence / "timing-summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report["timingSummaryPath"] = str(summary_path.relative_to(ROOT))
        report["timingSummarySha256"] = sha256_file(summary_path)
        report["status"] = "partial-evidence-collected"
    except BaseException as failure:
        report["status"] = "failed"
        report["failure"] = f"{type(failure).__name__}: {str(failure)[:512]}"
        persist()
        raise
    finally:
        report["completedAt"] = datetime.now(timezone.utc).isoformat()
        persist()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True, help="installed llm_bin_patch executable")
    parser.add_argument("--evidence-dir", type=Path, required=True, help="new directory under repository build/")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args(argv)
    if args.repetitions not in range(2, 6):
        parser.error("--repetitions must be between 2 and 5")
    try:
        report = run_matrix(args.cli, args.evidence_dir, args.repetitions)
    except (MatrixError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as failure:
        print(f"#1833 matrix stopped with retained failure evidence: {type(failure).__name__}", file=sys.stderr)
        return 1
    print(f"#1833 partial evidence: {report['status']} ({report['evidenceBytesCopied']} retained bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
