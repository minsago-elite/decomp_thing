#!/usr/bin/env python3
"""Validate D0 v1 design fixtures, including cross-record presentation invariants.

Requires the existing development tool fastjsonschema, pinned in
requirements/oracle-generation.txt. This is not an HTTP or runtime conformance test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import sys

import fastjsonschema


ROOT = Path(__file__).resolve().parent

# #604's outcome index is deliberately narrower than the full fixture manifest.
# These expectations cannot be changed merely by relabeling a fixture in JSON.
OUTCOME_EXPECTATIONS = {
    "successful": ("report", {"/data/state": "available", "/data/acceptance": "accepted"}),
    "empty": ("jobs", {"/data/items": [], "/data/page/nextCursor": None}),
    "partial": ("report", {"/data/state": "partial", "/data/acceptance": "unknown"}),
    "interrupted": ("run", {"/data/state": "interrupted", "/data/terminalReason": "PROCESS_INTERRUPTED"}),
    "failed": ("run", {"/data/state": "failed", "/data/terminalReason": "FAILED"}),
    "denied": ("error", {"/error/code": "ORIGIN_DENIED", "/error/retryable": False}),
    "unsupported": ("report", {"/data/state": "unsupported", "/data/acceptance": "unknown"}),
}


def check_outcomes(manifest: dict, validate) -> None:
    """Require one safe, schema-valid wire document for each named web outcome."""
    index = json.loads((ROOT / "outcomes.json").read_text())
    if index.get("version") != 1 or not isinstance(index.get("cases"), list):
        raise ValueError("outcome index must use version 1 and a cases array")
    cases = index["cases"]
    if len(cases) != len(OUTCOME_EXPECTATIONS) or {case.get("outcome") for case in cases} != set(OUTCOME_EXPECTATIONS):
        raise ValueError("outcome index must cover each required outcome exactly once")
    valid_files = {record["file"] for record in manifest["fixtures"] if record["valid"]}
    for case in cases:
        outcome = case["outcome"]
        filename = case.get("fixture")
        if set(case) != {"outcome", "fixture"} or not isinstance(filename, str) or not re.fullmatch(r"fixtures/[a-z0-9-]+\.json", filename):
            raise ValueError(f"{outcome}: invalid outcome fixture reference")
        if filename not in valid_files:
            raise ValueError(f"{outcome}: outcome fixture must be in the positive manifest")
        document = json.loads((ROOT / filename).read_text())
        validate(document)
        check_semantics(document)
        kind, expectations = OUTCOME_EXPECTATIONS[outcome]
        if document["kind"] != kind:
            raise ValueError(f"{outcome}: expected {kind} document")
        for pointer, expected in expectations.items():
            value = document
            for segment in pointer.split("/")[1:]:
                value = value[segment]
            if value != expected:
                raise ValueError(f"{outcome}: {pointer} must be {expected!r}")
        # These fixtures are wire metadata, never host-specific test inputs or
        # bearer material. Runtime auth and actual binary payloads are out of scope.
        serialized = json.dumps(document, ensure_ascii=False)
        if re.search(r'"(?:csrfToken|password|secret|privatePath|binaryBytes|authorization)"\s*:', serialized, re.I):
            raise ValueError(f"{outcome}: outcome fixture contains credential or binary fields")
        if re.search(r"/home/|/Users/|[A-Za-z]:\\\\Users\\\\|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}", serialized):
            raise ValueError(f"{outcome}: outcome fixture contains a private path or credential")


def check_semantics(document: dict) -> None:
    """Check relationships JSON Schema cannot express with portable draft-07."""
    kind = document["kind"]
    data = document.get("data", {})
    if kind == "error":
        error = document["error"]
        recovery = error.get("recovery")
        if (error["code"] == "EVENT_GAP") != (recovery is not None):
            raise ValueError("event gap recovery must accompany only EVENT_GAP")
        if recovery is not None:
            if error["retryable"] or error["retryAfterMs"] is not None:
                raise ValueError("event gaps require reconciliation, not blind retry")
            if recovery["oldestCursor"] is not None and recovery["latestCursor"] is None:
                raise ValueError("event gap boundary is incomplete")
            suffix = "/api/v1/jobs/" + recovery["jobId"] + "/runs/" + recovery["runId"] + "/snapshot"
            if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*" + re.escape(suffix), recovery["snapshotHref"]):
                raise ValueError("event gap snapshot belongs to another resource")
    elif kind == "uploadProgress":
        if int(data["receivedBytes"]) > 33554433 or (data["totalBytes"] is not None and int(data["totalBytes"]) > 33554432):
            raise ValueError("upload progress exceeds the request ceiling")
        if (data["state"] == "published") != (data["jobId"] is not None):
            raise ValueError("upload publication identity is inconsistent")
    elif kind == "runs":
        items = data["items"]
        if len(items) > data["page"]["limit"] or len({item["runId"] for item in items}) != len(items):
            raise ValueError("invalid attempt page bounds or duplicate identity")
        if any(item["jobId"] != data["jobId"] for item in items):
            raise ValueError("attempt belongs to a different job")
    elif kind == "jobs":
        if len(data["items"]) > data["page"]["limit"]:
            raise ValueError("page exceeds its declared record limit")
        identities = [item["jobId"] for item in data["items"]]
        if len(identities) != len(set(identities)):
            raise ValueError("a job appears more than once in a page")
    elif kind == "bootstrap":
        retention = data["runtime"].get("progressRetention")
        if retention is not None:
            if int(retention["expired"]) > int(retention["examined"]) or ((int(retention["failures"]) == 0) != (retention["lastFailureCode"] is None)):
                raise ValueError("retention counters are inconsistent")
        scheduler = data["runtime"].get("scheduler")
        if scheduler is not None and scheduler["state"] == "available":
            if int(scheduler["activeWorkers"]) > int(scheduler["workerLimit"]) or int(scheduler["queuedTasks"]) > int(scheduler["queueCapacity"]):
                raise ValueError("scheduler sample exceeds configured capacity")
        limits = data["limits"]
        if limits["defaultPageLimit"] > limits["maxPageLimit"]:
            raise ValueError("default page size exceeds configured maximum")
        capabilities = [item["id"] for item in data["capabilities"]]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("duplicate capability identity")
    elif kind == "report":
        artifact = data["sourceArtifact"]
        if artifact is not None and artifact["binding"] != data["binding"]:
            raise ValueError("report and source artifact have different evidence bindings")
        summary = data["summary"]
        if summary is not None:
            if data["reportType"] == "exploration" and "confidence" not in summary:
                raise ValueError("exploration adapter has a foreign summary schema")
            if data["reportType"] == "revision-validation" and "result" not in summary:
                raise ValueError("validation adapter has a foreign summary schema")
        if data["acceptance"] == "accepted":
            if summary is None or summary.get("result") != "passed":
                raise ValueError("accepted report requires a passed validation summary")
    elif kind == "snapshot":
        if (data["throughCursor"] is None) != (data["throughSequence"] is None):
            raise ValueError("snapshot cursor and sequence must describe the same watermark")
        if "progress" in data:
            progress = data["progress"]
            count, next_sequence = int(progress["retainedEventCount"]), int(progress["nextSequence"])
            if count > 1024 or count + int(progress["queueDropped"]) + int(progress["historyDropped"]) > next_sequence:
                raise ValueError("snapshot progress counters exceed the boundary")
            if (count == 0) != (data["oldestCursor"] is None) or (next_sequence == 0) != (data["throughSequence"] is None):
                raise ValueError("snapshot retained records and cursors disagree")
            if data["throughSequence"] is not None and int(data["throughSequence"]) + 1 != next_sequence:
                raise ValueError("snapshot progress boundary disagrees with next sequence")
    elif kind == "events":
        seen = set()
        previous = -1
        binding = None
        for event in data["items"]:
            if event["type"] == "retention.gap":
                raise ValueError("transport gaps are not persisted poll-page entries")
            current_binding = (event["jobId"], event["runId"])
            if binding is not None and binding != current_binding:
                raise ValueError("poll page mixes attempts")
            binding = current_binding
            sequence = int(event["sequence"])
            if event["cursor"] in seen or sequence <= previous:
                raise ValueError("persisted poll page must be unique and ordered")
            seen.add(event["cursor"])
            previous = sequence
        if data["items"] and data["nextCursor"] != data["items"][-1]["cursor"]:
            raise ValueError("poll continuation must follow the last returned event")
    elif kind == "gitWorkspace":
        length = {"sha1": 40, "sha256": 64}.get(data["objectFormat"])
        object_ids = [data["headObjectId"]]
        object_ids.extend(item["objectId"] for item in data["refs"])
        mapping = data["mapping"]
        if mapping is not None:
            object_ids.append(mapping["objectId"])
            if mapping["repositoryId"] != data["repositoryId"]:
                raise ValueError("Git provenance mapping belongs to another repository")
            if mapping["objectId"] != data["headObjectId"]:
                raise ValueError("workspace mapping must describe the observed HEAD")
            if mapping["acceptance"] == "accepted" and mapping["acceptanceArtifactId"] is None:
                raise ValueError("Git mapping cannot invent acceptance without evidence")
        if length is not None and any(len(oid) != length for oid in object_ids if oid is not None):
            raise ValueError("Git object ID is not full length for its repository format")


def main() -> int:
    manifest = json.loads((ROOT / "fixtures.json").read_text())
    schema = json.loads((ROOT / manifest["schema"]).read_text())
    validate = fastjsonschema.compile(schema)
    records = manifest["fixtures"]
    declared = [record["file"] for record in records]
    actual = {str(path.relative_to(ROOT)) for path in (ROOT / "fixtures").glob("*.json")}
    if len(declared) != len(set(declared)) or set(declared) != actual:
        raise ValueError("fixture manifest must cover each fixture exactly once")

    failures = []
    accepted = rejected = 0
    for record in records:
        value = json.loads((ROOT / record["file"]).read_text())
        try:
            validate(value)
            check_semantics(value)
        except (fastjsonschema.JsonSchemaException, ValueError) as error:
            if record["valid"]:
                failures.append(f"{record['file']}: unexpected rejection: {error}")
            else:
                rejected += 1
        else:
            if record["valid"]:
                accepted += 1
            else:
                failures.append(f"{record['file']}: invalid fixture was accepted")
    try:
        check_outcomes(manifest, validate)
    except (fastjsonschema.JsonSchemaException, KeyError, TypeError, ValueError) as error:
        failures.append(f"outcomes.json: {error}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"v1 design contracts: {accepted} valid fixtures accepted; {rejected} invalid fixtures rejected; {len(OUTCOME_EXPECTATIONS)} web outcomes verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
