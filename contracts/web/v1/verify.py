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


def check_run(run: dict) -> None:
    """Match durable lifecycle metadata without inferring execution or acceptance."""
    reasons = {
        "queued": (None,), "running": (None,), "cancelling": (None,),
        "completed": ("COMPLETED", "NO_CHANGES"),
        "failed": ("FAILED", "REFUSED", "LIMIT_EXHAUSTED"),
        "cancelled": ("CANCELLED",), "interrupted": ("PROCESS_INTERRUPTED",),
    }
    if run["terminalReason"] not in reasons[run["state"]]:
        raise ValueError("attempt state and terminal reason disagree")
    if run["state"] == "queued" and run["startedAt"] is not None:
        raise ValueError("queued attempt has already started")
    if run["state"] in ("running", "completed") and run["startedAt"] is None:
        raise ValueError("running or completed attempt has no start timestamp")


def check_source_page(data: dict, version: str) -> None:
    items, page = data["items"], data["page"]
    if page["snapshotVersion"] != version or len(items) > min(page["limit"], data["totalFiles"]):
        raise ValueError("source page does not match its captured metadata")
    if len({item["fileId"] for item in items}) != len(items) or (page["nextCursor"] is not None and not 0 < len(items) < data["totalFiles"]):
        raise ValueError("source page has duplicate identities or an impossible continuation")
    if any(not part.strip() or part in (".", "..") or len(part.encode("utf-16-le")) // 2 > 255
           for item in items for part in item["displayName"].split("/")):
        raise ValueError("source display label is not a portable relative name")


def check_directory(data: dict) -> None:
    def label_ok(label):
        # Match Kotlin Char.isWhitespace; Python strip additionally removes U+0085.
        return label is not None and re.search(r"[^\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]", label) is not None and label not in (".", "..")

    items, page, total = data["items"], data["page"], data["totalChildren"]
    count = data["sourceFileCount"]
    if page["snapshotVersion"] != data["metadataVersion"] or len(items) > page["limit"] or not len(items) <= total <= count:
        raise ValueError("directory page identity or bounds are inconsistent")
    if page["nextCursor"] is not None and len(items) >= total:
        raise ValueError("a complete directory page cannot continue")
    identities = [item["fileId"] if item["kind"] == "file" else item["directoryId"] for item in items]
    if len(set(identities)) != len(items) or len({item["displayName"] for item in items}) != len(items):
        raise ValueError("directory children must have unique identities and names")
    crumbs, depth = data["breadcrumbs"], data["depth"]
    child_count = 0
    for index, item in enumerate(items):
        label = item["displayName"]
        if not label_ok(label):
            raise ValueError("invalid directory child label")
        child_count += 1 if item["kind"] == "file" else item["sourceFileCount"]
        if item["kind"] == "directory" and any(crumb["directoryId"] == item["directoryId"] for crumb in crumbs):
            raise ValueError("directory child cannot be an ancestor")
        if index:
            previous = items[index - 1]
            # Kotlin and JavaScript compare UTF-16 code units, including astral labels.
            if not ((previous["kind"] == "directory" and item["kind"] == "file") or
                    (previous["kind"] == item["kind"] and previous["displayName"].encode("utf-16-be", "surrogatepass") < label.encode("utf-16-be", "surrogatepass"))):
                raise ValueError("directory children are out of order")
    if child_count > count or (len(items) == total and child_count != count):
        raise ValueError("directory descendant commitments are inconsistent")
    if len(crumbs) != 1 + min(depth, 31) or data["omittedAncestors"] != max(0, depth - 31):
        raise ValueError("directory breadcrumb bounds are inconsistent")
    if crumbs[0] != {"directoryId": "root", "displayName": None} or len({c["directoryId"] for c in crumbs}) != len(crumbs):
        raise ValueError("directory breadcrumb root or identity is inconsistent")
    if crumbs[-1] != {"directoryId": data["directoryId"], "displayName": data["displayName"]}:
        raise ValueError("directory breadcrumb does not identify this directory")
    if any(not label_ok(c["displayName"]) for c in crumbs[1:]):
        raise ValueError("invalid directory breadcrumb label")
    if depth == 0:
        if data["directoryId"] != "root" or data["parentDirectoryId"] is not None or data["displayName"] is not None:
            raise ValueError("directory root identity is inconsistent")
    elif data["directoryId"] == "root" or data["displayName"] is None or data["parentDirectoryId"] != crumbs[-2]["directoryId"]:
        raise ValueError("directory parent identity is inconsistent")


def check_source_chunk(data: dict) -> None:
    size, offset, length = int(data["sizeBytes"]), int(data["offsetBytes"]), int(data["lengthBytes"])
    end = offset + length
    if size > 8388608 or length > 131072 or end > size or not ((offset == 0 and length == 0) if size == 0 else (offset < size and length > 0)):
        raise ValueError("source chunk byte range exceeds its limits")
    if data["completeFile"] != (offset == 0 and end == size):
        raise ValueError("source chunk completeness is inconsistent")
    if not ((data["nextOffsetBytes"] is not None and int(data["nextOffsetBytes"]) == end) if end < size else data["nextOffsetBytes"] is None):
        raise ValueError("source chunk continuation is inconsistent")
    if data["representation"] == "hex":
        if data["fallbackReason"] is None or any(data[key] is not None for key in ("firstLine", "startsMidLine", "endsMidLine")):
            raise ValueError("hex fallback must not invent text line positions")
        if re.fullmatch(r"[0-9a-f]*", data["text"]) is None or len(data["text"]) != 2 * length:
            raise ValueError("hex fallback byte length is inconsistent")
    else:
        if len(data["text"].encode("utf-8")) != length or data["fallbackReason"] is not None or any(data[key] is None for key in ("firstLine", "startsMidLine", "endsMidLine")):
            raise ValueError("UTF-8 source byte length or line metadata is inconsistent")
        first = int(data["firstLine"])
        if first < 1 or first > offset + 1 or (offset == 0 and (first != 1 or data["startsMidLine"])) or (offset > 0 and first == 1 and not data["startsMidLine"]):
            raise ValueError("UTF-8 source start line is inconsistent")
        if data["endsMidLine"] != (end < size and not data["text"].endswith("\n")):
            raise ValueError("UTF-8 source end line is inconsistent")


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
    elif kind == "sourceCatalog":
        check_source_page(data, data["manifestSha256"])
    elif kind == "revisionSources":
        check_source_page(data, data["metadataVersion"])
    elif kind == "revisionDirectory":
        check_directory(data)
    elif kind == "sourceChunk":
        check_source_chunk(data)
    elif kind == "revisionFile":
        path = data["item"]["displayName"]
        for part in path.split("/"):
            if part in (".", "..") or len(part.encode("utf-16-le", "surrogatepass")) // 2 > 255 or re.search(r"[^\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]", part) is None:
                raise ValueError("invalid recorded source path component")
        if (data["parentDirectoryId"] == "root") != ("/" not in path):
            raise ValueError("recorded source parent is inconsistent")
    elif kind == "recovery":
        candidates = data["retainedUploadStages"] + data["retainedMetadataFiles"]
        if candidates > 128 or candidates > data["scannedEntries"] or int(data["observedBytes"]) > 67108864:
            raise ValueError("recovery inventory exceeds its bounded inspection")
    elif kind == "run":
        check_run(data)
    elif kind == "runs":
        items = data["items"]
        if len(items) > data["page"]["limit"] or len({item["runId"] for item in items}) != len(items):
            raise ValueError("invalid attempt page bounds or duplicate identity")
        if any(item["jobId"] != data["jobId"] for item in items):
            raise ValueError("attempt belongs to a different job")
        for item in items:
            check_run(item)
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
        check_run(data["run"])
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


def check_run_lifecycle_controls(validate) -> int:
    """Exercise every state/reason pair and start alternative in each Run position."""
    single = json.loads((ROOT / "fixtures/run-completed-unaccepted.json").read_text())
    page = json.loads((ROOT / "fixtures/runs-page.json").read_text())
    snapshot = json.loads((ROOT / "fixtures/snapshot.json").read_text())
    expected = {
        "queued": {None}, "running": {None}, "cancelling": {None},
        "completed": {"COMPLETED", "NO_CHANGES"},
        "failed": {"FAILED", "REFUSED", "LIMIT_EXHAUSTED"},
        "cancelled": {"CANCELLED"}, "interrupted": {"PROCESS_INTERRUPTED"},
    }
    all_reasons = [None, "COMPLETED", "NO_CHANGES", "REFUSED", "CANCELLED",
                   "LIMIT_EXHAUSTED", "FAILED", "PROCESS_INTERRUPTED"]
    checked = 0

    def check(run, valid):
        nonlocal checked
        documents = [
            {**single, "data": run},
            {**page, "data": {**page["data"], "items": [run]}},
            {**snapshot, "data": {**snapshot["data"], "run": run}},
        ]
        for document in documents:
            try:
                validate(document)
                check_semantics(document)
            except (fastjsonschema.JsonSchemaException, ValueError):
                if valid:
                    raise ValueError("valid lifecycle metadata was rejected")
            else:
                if not valid:
                    raise ValueError("contradictory lifecycle metadata was accepted")
            checked += 1

    for state, valid_reasons in expected.items():
        run = {**single["data"], "state": state, "resultRevisionId": None, "usage": None,
               "startedAt": None if state == "queued" else single["data"]["startedAt"],
               "endedAt": single["data"]["endedAt"] if state in ("completed", "failed", "cancelled", "interrupted") else None}
        for reason in all_reasons:
            check({**run, "terminalReason": reason}, reason in valid_reasons)
        for started in (None, single["data"]["startedAt"]):
            valid = (started is None) if state == "queued" else (started is not None) if state in ("running", "completed") else True
            check({**run, "terminalReason": next(reason for reason in all_reasons if reason in valid_reasons), "startedAt": started}, valid)
    return checked


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
    try:
        lifecycle_controls = check_run_lifecycle_controls(validate)
    except (fastjsonschema.JsonSchemaException, KeyError, TypeError, ValueError) as error:
        failures.append(f"run lifecycle controls: {error}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"v1 design contracts: {accepted} valid fixtures accepted; {rejected} invalid fixtures rejected; {len(OUTCOME_EXPECTATIONS)} web outcomes verified")
    print(f"run lifecycle metadata: {lifecycle_controls} envelope controls verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
