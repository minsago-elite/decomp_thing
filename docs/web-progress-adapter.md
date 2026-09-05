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
bounded redacted previews. The web schema currently defines agent messages,
run state, evidence availability and retention gaps. Journal observations cannot
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
