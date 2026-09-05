# Persisted agent workflow progress

CLI and browser source reconstruction use `AgentWorkflowProgress` to project task events and
workflow validation phases into `reports/agent-progress.json`. This is a bounded operator view;
the invocation receipts, accepted checkpoints and archive verifiers remain the acceptance authority.

Each execution has a new run UUID and each task has a new turn UUID, even when the exact request
is retried. Events bind the immutable request digest, task identity digest and monotonic display
sequence. The terminal task record maps that turn to the session digest and final stop reason or
failure classification. It explicitly records that validation is still pending. A workflow-owned
accepted phase may subsequently reference an accepted source digest.

`workflowRunId` and its digest correlate task events and `workflow_run_state` observations with a
durable workflow run. They are separate from the journal writer's `runId`, which changes on restart.
Run-state observations can name the provisional or canonical revision independently of a task;
revision IDs use the same redacted-preview and digest convention. Explicit provisional, compile-valid,
rejected, exhausted, resource-exhausted, cancelled and interrupted phases do not carry an accepted
source commitment. An accepted run-state observation requires that commitment. These shape checks
keep display meanings distinct; they do not validate a graph or confer acceptance authority.

One journal writer owns a filesystem lock. Producers normalize and enqueue without disk I/O;
the writer forces a temporary file, atomically replaces the snapshot, and forces its directory.
Defaults bound the queue to 128 events, retained history to 256 events and the snapshot to 512 KiB.
Overflow is explicit through sequence gaps, queue/history omission counts and `truncated`. Readers
accept at most 2 MiB and 1,024 ordered records. Closing drains the bounded queue and waits at most
five seconds; persistence or cleanup failure is reported instead of claiming a complete projection.
A new writer retains the prior snapshot and continues its sequence while starting a distinct run.

Raw protocol frames and arbitrary exception messages do not enter this view. Message chunks retain
content/identity commitments and counts. Up to 16 messages of 8,192 characters each can be accumulated
for a completed-message preview; oversized messages omit the entire preview. Whole-message redaction
prevents a configured secret split across chunks from leaking through separate previews. Configured
environment values and common credential formats are redacted before previews are bounded. Tool,
plan and permission previews are also bounded. Opaque session/message/tool IDs remain digests.
Redaction is a display precaution, not a claim that arbitrary unconfigured secrets can be identified.

The browser reads the same persisted snapshot at `GET /api/jobs/<job-id>/events`, updates at bounded
polling intervals, and uses text nodes for peer-authored previews. Refresh renders the retained history
from disk. CLI progress phases go to stderr; source/archive result paths remain on stdout.

Repair runs now own a journal for their reports directory. Captured task events and final agent
receipts carry the durable repair run ID; policy checking precedes candidate validation. Provisional,
rollback and accepted observations are emitted after graph transitions, and the final observation
projects the persisted terminal outcome. An accepted source commitment comes from the fully accepted
graph head. The build phase encloses the provider call; the behavior phase marks checking its returned
report, not live per-case provider telemetry. A busy or failed journal is disabled with one fixed
diagnostic and cannot change acceptance, consume another repair attempt or replace durable failure.
Close retains the bounded journal drain and preserves thread interruption while releasing its lock.

The repair CLI consumes the whole-run outcome, prints at most 20 typed iteration dispositions, and
returns a nonzero exit for unsuccessful or incomplete validation. It omits peer summaries, prompts
and diagnostic streams from those result lines; configuration/failure diagnostics and harness
provenance use the bounded redactor on stderr. The shared browser progress renderer includes durable
run and revision IDs on refresh and incremental updates, with accepted source commitments shown
separately. Neither console output nor the browser view certifies a release.

The current browser job execution wiring covers reconstruction, while repair core writes the same
persisted view. Issue #69 still owns repair job execution/live CLI delivery, patch live integration,
thought and terminal updates, complete usage projection, explicit process-crash delivery/recovery
proof and correlation with the durable session store in #68. The display ring can omit old records;
its `displayOnly` flag and counters must never substitute for complete required release evidence in
#72. The existing job restart state is still owned by `JobStore` and does not restore an ACP session.

Focused verification:

```sh
./gradlew test --tests decompengine.jobs.AgentProgressJournalTest \
  --tests decompengine.web.UploadServerTest \
  --tests decompengine.web.SourceTreeJobReconstructorTest
```
