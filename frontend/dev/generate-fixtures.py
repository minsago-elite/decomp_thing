#!/usr/bin/env python3
"""Create deterministic development records under the shared v1 schema.

The result is read by the Vite development process, never by a production build.
fastjsonschema is the existing pinned Python contract-validation dependency.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

import fastjsonschema

CONTRACT = Path(__file__).resolve().parents[2] / "contracts/web/v1"
sys.path.insert(0, str(CONTRACT))
from verify import check_semantics  # noqa: E402


def source(name: str) -> dict:
    return json.loads((CONTRACT / "fixtures" / f"{name}.json").read_text())


def generate(base_path: str, schema_path: Path) -> dict:
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*", base_path):
        raise ValueError("Development base path must be normalized ASCII path segments")
    schema_bytes = schema_path.read_bytes()
    validate = fastjsonschema.compile(json.loads(schema_bytes))
    routes: dict[str, dict] = {}
    scenarios = []
    jobs = []
    api = base_path + "api/v1"

    def record(path: str, document: dict) -> None:
        validate(document)
        check_semantics(document)
        routes[path] = document

    bootstrap = source("bootstrap")
    bootstrap["data"]["basePath"] = base_path
    bootstrap["data"]["applicationBuildId"] = "SIMULATED_DEVELOPMENT_DATA"
    bootstrap["data"]["uiBuildId"] = "SIMULATED_DEVELOPMENT_DATA"
    record(api + "/bootstrap", bootstrap)
    for name, state, description in [
        ("running", "running", "Simulated active attempt; no native process is running."),
        ("failed", "failed", "Simulated terminal failure; no accepted revision."),
        ("interrupted", "interrupted", "Simulated interrupted attempt; recovery has not started."),
        ("unsupported", "completed", "Simulated completed attempt with an unsupported report adapter; acceptance remains unknown."),
        ("partial", "running", "Simulated partially populated report; usage and revision are unavailable."),
    ]:
        job = source("job-lossless")
        job_id, run_id = f"fixture_job_{name}", f"fixture_run_{name}"
        job["data"].update(jobId=job_id, displayFilename=f"SIMULATED-{name}.elf", status=state,
                           latestRunId=run_id, acceptedRevisionId=None)
        run = source("run-queued")
        run["data"].update(jobId=job_id, runId=run_id, state=state,
                           startedAt="2026-09-05T00:00:01Z")
        if state in ("failed", "interrupted", "completed"):
            run["data"]["endedAt"] = "2026-09-05T00:00:02Z"
            run["data"]["terminalReason"] = {
                "failed": "FAILED", "interrupted": "PROCESS_INTERRUPTED", "completed": "COMPLETED"
            }[state]
        job_path = api + "/jobs/" + job_id
        run_path = job_path + "/runs/" + run_id
        record(job_path, job)
        record(run_path, run)
        jobs.append(deepcopy(job["data"]))
        events = source("events-poll")
        event = events["data"]["items"][0]
        event.update(jobId=job_id, runId=run_id, cursor=f"fixture_cursor_{name}")
        event["payload"].update(state=state, version=run["data"]["version"])
        events["data"]["nextCursor"] = event["cursor"]
        validate(event)
        check_semantics(event)
        record(run_path + "/events", events)
        snapshot = source("snapshot")
        snapshot["data"].update(run=deepcopy(run["data"]), throughCursor=event["cursor"],
                                  throughSequence=event["sequence"], oldestCursor=event["cursor"])
        record(run_path + "/snapshot", snapshot)
        report = source("report-unsupported" if name == "unsupported" else "report-partial" if name == "partial" else "report-missing")
        report["data"]["binding"].update(jobId=job_id, runId=run_id, revisionId=None)
        report["data"]["sourceArtifact"] = None
        report_path = run_path + "/reports/" + report["data"]["reportId"]
        record(report_path, report)
        scenarios.append({"name": name, "description": description, "jobPath": job_path,
                          "runPath": run_path, "reportPath": report_path})

    page = source("jobs-page")
    page["data"]["items"] = jobs
    record(api + "/jobs", page)
    download = "SIMULATED_DEVELOPMENT_DATA\nThis synthetic attachment is not execution evidence.\n"
    artifact = source("artifact")
    artifact["data"].update(artifactId="fixture_attachment", displayName="SIMULATED-evidence.txt",
                              mediaType="text/plain", sizeBytes=str(len(download.encode())),
                              sha256=hashlib.sha256(download.encode()).hexdigest())
    artifact["data"]["binding"].update(jobId="fixture_job_partial", runId="fixture_run_partial", revisionId=None)
    artifact_path = api + "/jobs/fixture_job_partial/artifacts/fixture_attachment"
    artifact["data"]["contentHref"] = artifact_path + "/content"
    record(artifact_path, artifact)
    errors = {}
    for code, message in [
        ("NOT_FOUND", "No simulated record exists for this route."),
        ("METHOD_NOT_ALLOWED", "Simulated development data is read-only; no action was performed."),
        ("VALIDATION_FAILED", "This deterministic fixture does not support those query parameters."),
    ]:
        error = source("error-validation")
        error["error"].update(code=code, message=message, details=[])
        validate(error)
        check_semantics(error)
        errors[code] = error
    return {"label": "SIMULATED_DEVELOPMENT_DATA", "schemaSha256": hashlib.sha256(schema_bytes).hexdigest(),
            "routes": routes, "scenarios": scenarios, "errors": errors,
            "download": {"path": artifact_path + "/content", "body": download,
                         "sha256": artifact["data"]["sha256"]}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--schema", type=Path, default=CONTRACT / "contract.schema.json")
    args = parser.parse_args()
    print(json.dumps(generate(args.base_path, args.schema), sort_keys=True, separators=(",", ":")))
