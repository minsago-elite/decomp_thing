#!/usr/bin/env python3
"""Summarize complete, invocation-bound analysis timing sidecars."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BINDINGS = (
    "inputSha256",
    "exporterSha256",
    "analysisToolSha256",
    "profileSha256",
    "configurationSha256",
)


class TimingEvidenceError(ValueError):
    pass


def load_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TimingEvidenceError(f"{path}: cannot read timing JSON: {error}") from error
    if not isinstance(value, dict) or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise TimingEvidenceError(f"{path}: unsupported timing record schema")
    invocation = value.get("analysisInvocationId")
    if not isinstance(invocation, str) or not UUID.fullmatch(invocation):
        raise TimingEvidenceError(f"{path}: missing analysisInvocationId")
    workflow_run = value.get("workflowRunId")
    if workflow_run is not None and (not isinstance(workflow_run, str) or not UUID.fullmatch(workflow_run)):
        raise TimingEvidenceError(f"{path}: malformed workflowRunId")
    if value.get("terminalStatus") != "succeeded" or value.get("workerTerminalStatus") != "succeeded":
        raise TimingEvidenceError(f"{path}: timing sample is not a successful parent and worker invocation")
    coverage = value.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("complete") is not True:
        raise TimingEvidenceError(f"{path}: timing coverage is incomplete")
    if coverage.get("truncated") is not False or coverage.get("missingPhases") != []:
        raise TimingEvidenceError(f"{path}: timing coverage is truncated or has missing phases")
    for field in BINDINGS:
        digest = value.get(field)
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise TimingEvidenceError(f"{path}: missing or malformed {field}")
    if not isinstance(value.get("recoveryMode"), str) or not value["recoveryMode"]:
        raise TimingEvidenceError(f"{path}: missing recoveryMode")
    instrumentation_version = value.get("instrumentationVersion", "analysis-timing-v1")
    if not isinstance(instrumentation_version, str) or instrumentation_version not in {
        "analysis-timing-v1",
        "analysis-timing-pre-analysis-boundary-v2",
    }:
        raise TimingEvidenceError(f"{path}: unsupported instrumentationVersion")

    parent_total = value.get("parentTotalElapsedNanos")
    worker_total = value.get("workerTerminalElapsedNanos")
    if not isinstance(parent_total, int) or isinstance(parent_total, bool) or parent_total < 0:
        raise TimingEvidenceError(f"{path}: invalid parentTotalElapsedNanos")
    if not isinstance(worker_total, int) or isinstance(worker_total, bool) or worker_total < 0:
        raise TimingEvidenceError(f"{path}: invalid workerTerminalElapsedNanos")

    phases: dict[str, set[str]] = {}
    for list_name, expected_domain in (("spans", "parent-monotonic"), ("workerSpans", "worker-monotonic")):
        spans = value.get(list_name)
        if not isinstance(spans, list) or not spans:
            raise TimingEvidenceError(f"{path}: missing {list_name}")
        seen: set[str] = set()
        for span in spans:
            if not isinstance(span, dict):
                raise TimingEvidenceError(f"{path}: malformed span in {list_name}")
            phase = span.get("phase")
            duration = span.get("durationNanos")
            if not isinstance(phase, str) or not phase or phase in seen:
                raise TimingEvidenceError(f"{path}: missing or duplicate phase in {list_name}")
            if span.get("clockDomain") != expected_domain:
                raise TimingEvidenceError(f"{path}: unexpected clock domain for {phase}")
            expected_status = "succeeded" if expected_domain == "parent-monotonic" else "completed"
            if span.get("status") != expected_status:
                raise TimingEvidenceError(f"{path}: unsuccessful span status for {phase}")
            offset = span.get("startOffsetNanos")
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                raise TimingEvidenceError(f"{path}: invalid start offset for {phase}")
            if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
                raise TimingEvidenceError(f"{path}: invalid duration for {phase}")
            total = parent_total if expected_domain == "parent-monotonic" else worker_total
            if offset + duration > total:
                raise TimingEvidenceError(f"{path}: {phase} extends past its clock-domain terminal time")
            seen.add(phase)
        phases[expected_domain] = seen

    required_parent = {"analysis-invocation", "process-launch-request-to-worker-entry-frame"}
    required_worker = {
        "worker-entry-to-parent-permit",
        "application-initialization",
    }
    if instrumentation_version == "analysis-timing-v1":
        required_worker.add("project-import-analysis-pre-script")
    else:
        required_worker.update({"project-open-import-pre-analysis", "auto-analysis"})
    if not required_parent <= phases["parent-monotonic"]:
        raise TimingEvidenceError(f"{path}: required parent analysis or worker-entry span is missing")
    if not required_worker <= phases["worker-monotonic"]:
        raise TimingEvidenceError(f"{path}: required worker phase span is missing")
    if not any(phase.startswith("exporter:") for phase in phases["worker-monotonic"]):
        raise TimingEvidenceError(f"{path}: inclusive exporter span is missing")
    return value


def summarize(paths: list[Path]) -> dict[str, Any]:
    if not paths:
        raise TimingEvidenceError("at least one timing sidecar is required")
    records = [load_record(path) for path in paths]
    ids = [record["analysisInvocationId"] for record in records]
    if len(set(ids)) != len(ids):
        raise TimingEvidenceError("duplicate analysisInvocationId; each invocation may appear only once")

    groups: dict[tuple[Any, ...], dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for record in records:
        bindings = {field: record[field] for field in BINDINGS}
        for list_name, domain in (("spans", "parent-monotonic"), ("workerSpans", "worker-monotonic")):
            for span in record[list_name]:
                key = (
                    tuple(bindings.items()),
                    record["recoveryMode"],
                    record["terminalStatus"],
                    record["workerTerminalStatus"],
                    record.get("instrumentationVersion", "analysis-timing-v1"),
                    domain,
                )
                groups[key][span["phase"]].append(span["durationNanos"])

    summaries = []
    for key, phases in sorted(groups.items(), key=lambda item: item[0]):
        bindings_tuple, recovery_mode, parent_status, worker_status, instrumentation_version, domain = key
        phase_summaries = {
            phase: {
                "samples": len(values),
                "minNanos": min(values),
                "medianNanos": statistics.median(values),
                "maxNanos": max(values),
            }
            for phase, values in sorted(phases.items())
        }
        summaries.append({
            "bindings": dict(bindings_tuple),
            "recoveryMode": recovery_mode,
            "terminalStatus": parent_status,
            "workerTerminalStatus": worker_status,
            "instrumentationVersion": instrumentation_version,
            "clockDomain": domain,
            "invocations": len({record["analysisInvocationId"] for record in records
                                 if all(record[field] == dict(bindings_tuple)[field] for field in BINDINGS)
                                 and record["recoveryMode"] == recovery_mode
                                 and record["terminalStatus"] == parent_status
                                 and record["workerTerminalStatus"] == worker_status
                                 and record.get("instrumentationVersion", "analysis-timing-v1") == instrumentation_version}),
            "phases": phase_summaries,
        })
    return {"schemaVersion": 1, "sidecars": len(paths), "summaries": summaries}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sidecars", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, help="write JSON to this path instead of stdout")
    args = parser.parse_args(argv)
    try:
        result = summarize(args.sidecars)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        else:
            sys.stdout.write(encoded)
    except (TimingEvidenceError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
