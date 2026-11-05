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

# Named bounded responsive (#619) fixtures. Synthetic text only: no native input, secrets or host paths.
RESPONSIVE_LONG_NAME = ("SIMULATED-\u05e7\u05d5\u05d1\u05e5-\u0645\u0644\u0641-\u00e9\u0301\u4e2d\u6587-"
                        "\U0001f600-" + "unbroken_identifier_" * 8 + ".elf")
RESPONSIVE_LABEL = "\u05ea\u05d5\u05d5\u05d9\u05ea \u0628\u0627\u0644\u0639\u0631\u0628\u064a\u0629 mixed RTL label " + "x" * 40
RESPONSIVE_SOURCE_LINE = "static const char simulated_unbroken_line[] = \"" + "A0b1C2d3" * 64 + "\";"
RESPONSIVE_PREVIEW_TEXT = "\u05e9\u05dc\u05d5\u05dd" + ("unbroken" * 16)[:120]  # exactly 128 UTF-8 bytes
RESPONSIVE_HEX = "".join(("" if i == 0 else "\n" if i % 16 == 0 else " ") + f"{b:02x}"
                         for i, b in enumerate(RESPONSIVE_PREVIEW_TEXT.encode()))


def _responsive_input(source: str, arg: str) -> dict:
    return {"id": "case-" + "\u05d0\u0628" + "x" * 40, "source": source,
            "args": [arg, RESPONSIVE_LONG_NAME, "<img src=x>"], "stdinHex": RESPONSIVE_PREVIEW_TEXT.encode().hex()[:256]}


def _responsive_observation(exit_code: int) -> dict:
    out = RESPONSIVE_PREVIEW_TEXT.encode().hex()[:256]
    return {"candidateId": "case-" + "\u05d0\u0628" + "x" * 40, "exitCode": exit_code, "stdoutHex": out,
            "stderrHex": "1b", "signature": f"{exit_code}:{out}:1b", "networkIsolated": True}


# Exploration partial-case artifacts (producer schema 1), rendered by ExplorationCases' two progress tables.
RESPONSIVE_PARTIAL_CASES = {
    "schema": "decomp-exploration-failure", "schemaVersion": 1, "state": "partial", "coverage": None, "confidence": None,
    "failure": {"phase": "expanded", "candidateIndex": 1, "kind": "timeout", "code": "behavior-deadline-exceeded"},
    "samples": {"baselineInputs": 2, "expandedInputs": 3, "baselineObserved": 2, "expandedObserved": 1},
    "details": {"baselineInputs": [_responsive_input("SEED", RESPONSIVE_SOURCE_LINE[:200]), _responsive_input("SEED", "second")],
                "expandedInputs": [_responsive_input("MUTATION", "a"), _responsive_input("MUTATION", "failed"),
                                   _responsive_input("MUTATION", "unobserved")],
                "baselineObservations": [_responsive_observation(124), _responsive_observation(0)],
                "expandedObservations": [_responsive_observation(124)]},
    "detailsOmitted": None}
RESPONSIVE_PREPARATION_CASES = {
    "schema": "decomp-exploration-preparation-failure", "schemaVersion": 1, "state": "partial",
    "observationState": "not-started",
    "failure": {"stage": "static-hints", "kind": "generation-failure", "code": "candidate-generation-failed"},
    "availableInputs": {"seeds": 1, "angr": 1, "staticHints": None, "expanded": None},
    "details": {"seeds": [_responsive_input("SEED", RESPONSIVE_SOURCE_LINE[:200])],
                "angr": [_responsive_input("ANGR", "angr")], "staticHints": None},
    "detailsOmitted": None, "coverage": None, "confidence": None}


def responsive_exploration(job_path: str, job_id: str, base_run: dict, kind: str, cases: dict, record, artifacts) -> dict:
    """One completed attempt whose partial exploration report binds an exact raw-evidence JSON artifact."""
    run_id = f"fixture_run_responsive_{kind}"
    run = deepcopy(base_run)
    run["data"].update(runId=run_id)
    run_path = job_path + "/runs/" + run_id
    record(run_path, run)
    events = source("events-poll")
    event = events["data"]["items"][0]
    event.update(jobId=job_id, runId=run_id, cursor=f"fixture_cursor_responsive_{kind}")
    event["payload"].update(state="completed", version=run["data"]["version"])
    events["data"]["nextCursor"] = event["cursor"]
    record(run_path + "/events", events)
    snapshot = source("snapshot")
    snapshot["data"].update(run=deepcopy(run["data"]), throughCursor=event["cursor"],
                            throughSequence=event["sequence"], oldestCursor=event["cursor"])
    record(run_path + "/snapshot", snapshot)
    controls = source("attempt-controls-retry")
    controls["data"].update(jobId=job_id, runId=run_id, runVersion=run["data"]["version"], state="completed",
                            inputRevisionId=None, resumeRestores=None, successorRunId=None,
                            cancel={"available": False, "reason": "ATTEMPT_TERMINAL"},
                            retry={"available": False, "reason": "ATTEMPT_COMPLETED"},
                            resume={"available": False, "reason": "ATTEMPT_COMPLETED"})
    record(run_path + "/controls", controls)
    body = json.dumps(cases, ensure_ascii=False, separators=(",", ":"))
    data = body.encode()
    artifact_id = f"fixture_exploration_{kind}"
    content = job_path + "/artifacts/" + artifact_id + "/content"
    report = source("report-exploration")
    report["data"].update(state="partial", summary=None, producerSchemaVersion=1)
    report["data"]["binding"].update(jobId=job_id, runId=run_id, revisionId=None)
    report["data"]["sourceArtifact"].update(artifactId=artifact_id, displayName="exploration.json",
                                            sizeBytes=str(len(data)), sha256=hashlib.sha256(data).hexdigest(),
                                            contentHref=content)
    report["data"]["sourceArtifact"]["binding"].update(jobId=job_id, runId=run_id, revisionId=None)
    record(run_path + "/reports/exploration", report)
    artifacts[content] = {"body": body, "sha256": report["data"]["sourceArtifact"]["sha256"]}
    return {"kind": kind, "runPath": run_path, "contentPath": content}


def responsive_fixtures(api: str, record, artifact: dict) -> dict:
    """Long Unicode/RTL names, dense tables, a long unbroken source line and long hex previews."""
    job_id, run_id, revision_id = "f619f619f619f619f619f619f619f619", "fixture_run_responsive", "fixture_revision_responsive"
    job = source("job-lossless")
    job["data"].update(jobId=job_id, displayFilename=RESPONSIVE_LONG_NAME, status="completed",
                       latestRunId=run_id, acceptedRevisionId=None)
    if "label" in job["data"]:
        job["data"]["label"] = RESPONSIVE_LABEL
    run = source("run-queued")
    run["data"].update(jobId=job_id, runId=run_id, state="completed", startedAt="2026-09-05T00:00:01Z",
                       endedAt="2026-09-05T00:00:02Z", terminalReason="COMPLETED")
    job_path = api + "/jobs/" + job_id
    run_path = job_path + "/runs/" + run_id
    record(job_path, job)
    record(run_path, run)
    events = source("events-poll")
    event = events["data"]["items"][0]
    event.update(jobId=job_id, runId=run_id, cursor="fixture_cursor_responsive")
    event["payload"].update(state="completed", version=run["data"]["version"])
    events["data"]["nextCursor"] = event["cursor"]
    record(run_path + "/events", events)
    snapshot = source("snapshot")
    snapshot["data"].update(run=deepcopy(run["data"]), throughCursor=event["cursor"],
                            throughSequence=event["sequence"], oldestCursor=event["cursor"])
    record(run_path + "/snapshot", snapshot)
    controls = source("attempt-controls-retry")
    controls["data"].update(jobId=job_id, runId=run_id, runVersion=run["data"]["version"], state="completed",
                            inputRevisionId=None, resumeRestores=None, successorRunId=None,
                            cancel={"available": False, "reason": "ATTEMPT_TERMINAL"},
                            retry={"available": False, "reason": "ATTEMPT_COMPLETED"},
                            resume={"available": False, "reason": "ATTEMPT_COMPLETED"})
    record(run_path + "/controls", controls)
    report = source("report-missing")
    report["data"]["binding"].update(jobId=job_id, runId=run_id, revisionId=None)
    report["data"]["sourceArtifact"] = None
    report_path = run_path + "/reports/" + report["data"]["reportId"]
    record(report_path, report)

    # Recorded validation: one baseline owner whose previews carry the 128-byte hex/text maximum.
    history = source("validation-history")
    history["data"]["binding"].update(jobId=job_id, runId=run_id)
    history["data"]["items"] = history["data"]["items"][:1]
    owner = history["data"]["items"][0]
    record(run_path + "/validation-history", history)
    cases = source("report-normal-cases")
    cases["data"]["binding"].update(jobId=job_id, runId=run_id, revisionId=owner["candidateId"])
    vc = cases["data"]["validationCases"]
    vc.update(graphSha256=history["data"]["graphSha256"], ownerKind=owner["ownerKind"], ownerId=owner["ownerId"],
              sourceSha256=owner["sourceSha256"], corpusSha256=owner["corpusSha256"])
    cases["data"]["summary"]["sourceSha256"] = owner["sourceSha256"]
    preview = {"totalBytes": "4096", "prefixBytes": 128, "hex": RESPONSIVE_HEX, "text": RESPONSIVE_PREVIEW_TEXT,
               "textBytes": 128, "truncated": True}
    item = vc["items"][0]
    item.update(originalStdoutBytes="4096", rebuiltStdoutBytes="4096",
                originalStdoutPreview=deepcopy(preview), rebuiltStdoutPreview=deepcopy(preview))
    owner_key = {"attempt": "historyEvidence", "run-failure": "historyFailureRun"}.get(owner["ownerKind"], "historyRunEvidence")
    record(f"{run_path}/reports/revision-validation?historyGraph={history['data']['graphSha256']}"
           f"&historyPage={history['data']['page']}&{owner_key}={owner['ownerId']}&historyValidationPage=1", cases)
    responsive_sources(run_path, {"jobId": job_id, "runId": run_id, "revisionId": revision_id}, record)
    exploration = [responsive_exploration(job_path, job_id, run, kind, body, record, artifact)
                   for kind, body in (("partial", RESPONSIVE_PARTIAL_CASES), ("preparation", RESPONSIVE_PREPARATION_CASES))]
    return {"name": "responsive", "description": "Named #619 reflow fixtures: long Unicode/RTL identifiers, "
            "long hex byte previews, dense tables and a long unbroken source line. Synthetic only.",
            "jobPath": job_path, "runPath": run_path, "reportPath": report_path, "job": deepcopy(job["data"]),
            "explorationRunPaths": {value["kind"]: value["runPath"] for value in exploration}}


def responsive_sources(run_path: str, binding: dict, record) -> None:
    """Source directory/file/chunk/search records for one long unbroken line and one long hex chunk."""
    revision = run_path + "/revisions/" + binding["revisionId"]
    source_sha, metadata = "6" * 64, "7" * 64
    text = RESPONSIVE_SOURCE_LINE + "\n" + "int simulated_short_line = 0;\n"
    hex_bytes = bytes((i * 37 + 0x80) % 256 for i in range(512))
    files = [
        ("file_0_" + "1" * 64, "SIMULATED-\u05de\u05e7\u05d5\u05e8-" + "unbroken_source_name_" * 4 + ".c", text.encode(), "utf8"),
        ("file_1_" + "2" * 64, "SIMULATED-binary-preview.bin", hex_bytes, "hex"),
    ]
    directory = source("revision-directory-root")
    directory["data"].update(binding=deepcopy(binding), sourceSha256=source_sha, metadataVersion=metadata,
                             sourceFileCount=len(files), totalChildren=len(files))
    directory["data"]["page"]["snapshotVersion"] = metadata
    directory["data"]["items"] = []
    for file_id, name, content, representation in sorted(files, key=lambda value: value[1]):
        digest = hashlib.sha256(content).hexdigest()
        directory["data"]["items"].append({"fileId": file_id, "displayName": name, "sizeBytes": str(len(content)), "sha256": digest,
                                           "declaredUtf8Text": representation == "utf8", "declaredViewable": True, "kind": "file"})
        meta = source("revision-file-root")
        meta["data"].update(binding=deepcopy(binding), sourceSha256=source_sha, metadataVersion=metadata)
        meta["data"]["item"].update(fileId=file_id, displayName=name, sizeBytes=str(len(content)), sha256=digest,
                                    declaredUtf8Text=representation == "utf8")
        record(f"{revision}/source-files/{file_id}", meta)
        chunk = source("source-chunk-hex" if representation == "hex" else "source-chunk-complete-BOM-CRLF")
        chunk["data"].update(binding=deepcopy(binding), fileId=file_id, sourceSha256=source_sha, metadataVersion=metadata,
                             sha256=digest, sizeBytes=str(len(content)), offsetBytes="0", lengthBytes=str(len(content)),
                             nextOffsetBytes=None, completeFile=True,
                             text=content.hex() if representation == "hex" else content.decode())
        if representation == "hex":
            chunk["data"]["fallbackReason"] = "declared-binary"
        record(f"{revision}/source-files/{file_id}/chunk?offset=0&maxBytes=65536&metadataVersion={metadata}", chunk)
    record(f"{revision}/source-directories/root?limit=50", directory)
    search = source("source-search-complete")
    needle = "A0b1C2d3"
    column = RESPONSIVE_SOURCE_LINE.index(needle)
    search["data"].update(binding=deepcopy(binding), sourceSha256=source_sha, metadataVersion=metadata)
    search["data"]["query"]["text"] = needle
    search["data"]["page"]["snapshotVersion"] = metadata
    search["data"]["scope"].update(filesInScope=2, searchableFiles=1, declaredBinary=1)
    search["data"]["progress"].update(scannedFiles=1, scannedBytes=str(len(text.encode())))
    item = deepcopy(search["data"]["items"][0])
    item.update(fileId=files[0][0], displayName=files[0][1], sha256=hashlib.sha256(files[0][2]).hexdigest(), line="1",
                column=str(column + 1), offsetBytes=str(column), lineOffsetBytes="0", before=RESPONSIVE_SOURCE_LINE[:column],
                match=needle, after=RESPONSIVE_SOURCE_LINE[column + len(needle):column + len(needle) + 80],
                truncatedBefore=False, truncatedAfter=True)
    search["data"]["items"] = [item]
    record(f"{revision}/source-search?q={needle}&limit=50", search)


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
    bootstrap["data"]["serverInstanceId"] = "SIMULATED_DEVELOPMENT_INSTANCE"
    # A fixed past expiry made every fixture session read as expired once that date passed.
    bootstrap["data"]["sessionExpiresAt"] = "2099-12-31T23:59:59Z"
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
        # Read-only simulated eligibility: the fixture server registers no workflow and owns no worker.
        controls = source("attempt-controls-retry")
        terminal = run["data"]["state"] in ("failed", "interrupted", "completed", "cancelled")
        recovery_reason = ("ATTEMPT_COMPLETED" if run["data"]["state"] == "completed"
                           else "WORKFLOW_UNAVAILABLE" if terminal else "ATTEMPT_ACTIVE")
        controls["data"].update(jobId=job_id, runId=run_id, runVersion=run["data"]["version"], state=run["data"]["state"],
                                inputRevisionId=None, resumeRestores=None, successorRunId=None,
                                cancel={"available": False, "reason": "ATTEMPT_TERMINAL" if terminal else "NO_OWNED_WORKER"},
                                retry={"available": False, "reason": recovery_reason},
                                resume={"available": False, "reason": recovery_reason})
        validate(controls)
        check_semantics(controls)
        record(run_path + "/controls", controls)
        report = source("report-unsupported" if name == "unsupported" else "report-partial" if name == "partial" else "report-missing")
        report["data"]["binding"].update(jobId=job_id, runId=run_id, revisionId=None)
        report["data"]["sourceArtifact"] = None
        report_path = run_path + "/reports/" + report["data"]["reportId"]
        record(report_path, report)
        scenarios.append({"name": name, "description": description, "jobPath": job_path,
                          "runPath": run_path, "reportPath": report_path})

    artifact_contents: dict[str, dict] = {}
    responsive = responsive_fixtures(api, record, artifact_contents)
    jobs.append(responsive.pop("job"))
    scenarios.append(responsive)

    page = source("jobs-page")
    page["data"]["items"] = jobs
    record(api + "/jobs", page)
    record(api + "/recovery", source("recovery-empty"))
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
        # #1894: rendered availability-notice fixture; served only when a browser harness substitutes /bootstrap.
        ("SESSION_REQUIRED", "Simulated development session is not connected."),
        # #628: exact generated read-failure bodies; no backend outage is simulated outside the harness.
        ("SERVICE_UNAVAILABLE", "Simulated service is temporarily unavailable."),
        ("INTERNAL_ERROR", "Simulated server could not complete this read."),
    ]:
        error = source("error-validation")
        error["error"].update(code=code, message=message, details=[])
        if code in ("SERVICE_UNAVAILABLE", "INTERNAL_ERROR"):
            error["error"]["retryable"] = code == "SERVICE_UNAVAILABLE"
            error["requestId"] = ("62800000-0000-4000-8000-000000000503" if code == "SERVICE_UNAVAILABLE"
                                  else "62800000-0000-4000-8000-000000000500")
        validate(error)
        check_semantics(error)
        errors[code] = error
    return {"label": "SIMULATED_DEVELOPMENT_DATA", "schemaSha256": hashlib.sha256(schema_bytes).hexdigest(),
            "routes": routes, "scenarios": scenarios, "errors": errors, "artifactContents": artifact_contents,
            "download": {"path": artifact_path + "/content", "body": download,
                         "sha256": artifact["data"]["sha256"]}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--schema", type=Path, default=CONTRACT / "contract.schema.json")
    args = parser.parse_args()
    print(json.dumps(generate(args.base_path, args.schema), sort_keys=True, separators=(",", ":")))
