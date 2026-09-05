# Persisted progress adapter boundary

D4.1 (#174) consumes the display journal owned by #69. This document records the
adapter boundary; GitHub issues remain the source of implementation status.

`AgentProgressJournal.read(Path)` now delegates validation to
`AgentProgressJournal.decode(ByteArray)`. File callers retain the existing
no-follow regular-file check and bounded read. The decoder accepts at most 2 MiB,
uses strict JSON limits (including duplicate rejection), permits at most 1,024
retained events, and preserves signed-64-bit sequence values without a floating
point conversion. Ordering, next-sequence and nonnegative omission counters use
the same checks as the existing reader. Decoding retained bytes never reopens a
path. It is a display-journal decoder, not a full event-payload schema validator,
redaction proof, workflow-state authority or guarantee of complete history.

The versioned web adapter must obtain bytes through `WebJobService.readArtifact`
for the selected job/attempt's fixed `reports/runs/<attempt>/agent-progress.json`
path. It must not call the path reader on a browser-supplied path or downgrade a
failed storage read to an empty history. Existing artifact limits, root ownership
and authenticated attempt selection remain the storage/access authority.

The upstream journal and web event schema are not interchangeable. The journal
has writer-restart `runId`, optional durable `workflowRunId` correlation, task and
request commitments, observation kinds, numeric sequence/drop counters and
bounded redacted previews. Before the observation variant below, the web schema defined only agent
messages, run state, evidence availability and retention gaps. Journal observations cannot
be relabeled as authoritative run-state transitions or acceptance evidence to
fit that schema. A versioned observation representation and exact decimal-text
sequence projection are required before exposing those records to the typed UI.

Replay also needs an explicit retention boundary. The existing 256-event default
journal can omit queued/history records; a returned list is not evidence that
all intervening sequences exist. The adapter must preserve omission information,
bind cursors to the exact job/attempt, distinguish reset from continuation, and
return an explicit gap when it cannot serve the requested history. A missing or
invalid journal cannot establish that no events occurred. Snapshot/run-state
cutover, polling/SSE resources and correlation must be qualified against the
owning #174 acceptance criteria before any live-stream capability is advertised.

Verification for the decoder extraction exercises persisted bytes after the
source file is removed, exact large sequences, explicit omission counters,
oversized input, malformed/duplicate JSON, duplicate/out-of-range sequences,
invalid display metadata and excessive event count. The extraction does not
add a versioned HTTP route or change the existing legacy event endpoint.

The selected journal/decoder and JVM web suites passed 148 tests with zero
failures/errors. Frontend tests and packaged browser qualification were not
rerun because this extraction changes neither UI nor HTTP behavior. The broader
#174 stream/replay criteria remain unverified and open.

## Versioned observation event

The shared v1 contract now defines `workflow.observation`. Its ordinary event
binding carries the selected web job/attempt, cursor and decimal-text sequence.
`agentSequence` may carry an exact producer sequence; `agentInvocationId` is
null because a journal request commitment is not an invocation identity. The
payload has fixed `authority: observations`, the separate writer ID, workflow,
observation kind, bounded known fields and an exact omitted-field count.

Known fields preserve available task/turn/workflow-run/session/tool/permission
and revision commitments, bounded redacted display strings, boolean omission
flags, exact usage/count strings and at most eight bounded plan entries. A
producer's reported accepted phase or source commitment remains a display
observation; it cannot acquire the `run.state` acceptance semantics. Fields not
represented by this contract must be counted as omitted by the adapter. That
count concerns payload fields, not dropped events; journal queue/history gaps
still require the separate replay/retention protocol.

Shared fixtures cover observation/poll envelopes, large exact counts, separate
writer/attempt identities, reported acceptance without authority, bounded plans
and explicit omissions. Negative fixtures reject alternate authority, numeric
counts, absent omission accounting, untyped text objects and excess plan items.
The typed client generation includes the new branch. Existing clients that do
not know this branch retain their explicit unsupported-contract behavior.

The mapper below implements the producer projection for this schema. The
authenticated HTTP endpoint, cursor cutover/gap handling and UI activity view
remain to be connected and qualified; no streaming capability is enabled here.

Contract verification passed 36 valid and 26 invalid fixtures. All 210 frontend
tests, lint, generated-type drift checks and the typechecked bundle passed.
JVM and browser tests were not rerun for this schema-only checkpoint; those are
required when the producer and HTTP/UI adapters land.

## Journal-to-observation mapping

`webProgressObservation` now maps one decoded journal record to the shared
`workflow.observation` shape. The caller supplies the authenticated job/attempt
and replay cursor; those are never taken from the writer's `runId`. Writer,
workflow and kind are validated independently. Sequence and usage values are
canonical unsigned decimal strings, preserving exact integers without floating
point conversion. Timestamp text is normalized to a supported UTC instant.

The mapper copies only known typed fields and bounded plan entries. Unknown
root fields contribute to `omittedFieldCount`; neither their names nor values
are copied. Invalid known fields fail rather than being silently coerced or
counted as omitted. It bounds source field count and serialized output to 64 KiB.
That is a per-event ceiling; the future page adapter still needs its own total
response-byte budget. It does not mint replay cursors or establish storage/session
authority by itself.

Integration with the actual writer exposed an initial schema bound mismatch:
`ProgressRedactor` appends a 21-character marker after taking a 512-character
preview (160 for plan text). The corresponding contract and mapper bounds are
now 533 and 181, preserving the original producer text and marker. A shared
fixture and actual persisted journal test cover this case.

Tests compare exact output with the shared observation and truncated-plan
fixtures, reject invalid known field types/counts/commitments, count unknown
fields without leaking their content, and map actual persisted writer records
while retaining distinct attempt/writer identities. This completes the producer
projection function; authenticated reads, replay/cutover/gaps and HTTP/UI
integration remain required under #174.

Final verification passed 153 journal/web JVM tests, 211 frontend tests,
37 valid and 26 invalid contract fixtures, lint and the typechecked bundle.
Browser qualification was not rerun because this mapper is not yet attached to
an HTTP route or UI view.

## Bounded replay core

`WebProgressPages` now provides bounded polling and snapshot-boundary calculation
from checked journal bytes. It retains only a process-local signing key/epoch,
not per-client queues or event caches. A page decodes at most 2 MiB / 1,024 source
records and returns at most 200 observations, splitting below the one-MiB
response ceiling. Byte-driven splits retain the exact last returned cursor.

Opaque cursors bind session/job/attempt, process epoch, an exact retained record
fingerprint and position. An ordinary cursor resumes after that record; the
oldest boundary permits explicit selection before the first retained record.
A fresh snapshot cutover cursor additionally acknowledges the journal's observed
next-sequence boundary, including trailing omissions. This avoids repeatedly
resetting at a terminal queue drop while preserving the omission counters for
the snapshot response. It does not certify that omitted events were delivered.

Missing/changed anchors, sequence holes, trailing omissions and process restart
return `410 PROGRESS_GAP`; malformed/tampered/cross-binding cursors return
`400 INVALID_CURSOR`. Invalid journals return a bounded `503 PROGRESS_UNAVAILABLE`
message. A gap discards the prospective page rather than returning silently
partial history. Snapshot-boundary results retain next-sequence and queue/history
omission counters for the forthcoming HTTP snapshot adapter. A journal with no
retained records has no anchor cursor; its counters must still be shown, and no
resume proof may be invented for that empty retained history.

Tests cover append/replay/idle polls, cross-binding/tamper/restart rejection,
missing/changed/interior/trailing gaps, explicit oldest-history selection,
snapshot cutover across trailing omissions, near-maximum sequence cursor length,
byte-limited page reachability and malformed inputs. This core does not perform
HTTP authorization, read storage paths, connect workflow snapshots atomically,
or provide SSE. Those integration boundaries remain open under #174.

Verification passed 160 journal/web JVM tests with zero failures/errors and
`git diff --check`. Frontend/browser suites were not rerun because the new replay
core has no HTTP/UI connection yet. The existing typed frontend build and asset
checks ran as part of the JVM build dependency chain.
