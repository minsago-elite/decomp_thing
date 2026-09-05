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

During repair, the CLI observes new project journal records every 250 milliseconds on one daemon
thread. It prints only recognized workflow phases and a durable-run digest prefix, never peer text
or raw identifiers. It skips preexisting history, reports sequence gaps, and emits at most 32 phase
updates per poll with an omission marker when needed. Snapshot reads bound bytes, JSON depth, nodes
and strings. Console backpressure affects only that observer; the journal producer and repair loop
continue independently. Observer close waits at most 200 milliseconds. A console write that ignores
interruption may retain the single daemon until the consumer drains or the CLI process exits. The
final typed command result remains separate from this optional live display.

The current browser job execution wiring covers reconstruction, while repair core writes the same
persisted view. Issue #69 still owns repair job execution, public-path live CLI qualification, patch live integration,
thought and terminal updates, complete usage projection, explicit process-crash delivery/recovery
proof and correlation with the durable session store in #68. The display ring can omit old records;
its `displayOnly` flag and counters must never substitute for complete required release evidence in
#72. The existing job restart state is still owned by `JobStore` and does not restore an ACP session.

Focused verification:

At prompt end the ACP adapter completes up to 16 tracked role/message identities, including earlier
interleaved IDs rather than only the last ID per role. An ID change alone does not complete a message.
The bounded drain is idempotent; identities beyond its capacity retain the journal's explicit omission
behavior. This closes displayed messages at prompt completion, not at guessed intermediate boundaries.

Final receipt observations preserve every available `AgentUsage` field: input, output and cached
input tokens, tool calls and wall-clock duration. Missing fields remain absent rather than becoming
zero. Durations use ISO-8601 text, preserving subsecond precision without overflowing a millisecond
conversion. Browser rows label these observations on refresh and incremental updates. They remain
invocation observations, not aggregate budget accounting, provider billing or validation evidence.
Live ACP context occupancy and optional peer-reported cost use separate `context_usage` records.
Context counts use decimal text to preserve 64-bit values in browser JSON consumers; currency text
is bounded and redacted. Receipt records retain a currency commitment, and the archive gate checks
the closed event shape, nonnegative counts, finite nonnegative cost and paired cost/currency fields.
No live observation substitutes for final prompt token usage, enforced ceilings or provider billing.

ACP `agent_thought_chunk` updates use message events with the distinct `thought` role. They share
the bounded whole-message redaction and omission rules, but do not contribute to the assistant
result summary. Buffer identity includes both role and peer message ID, so reused IDs cannot mix
thought and assistant content. Browser rows display the role on refresh and incremental updates.
This projects only thought content the peer explicitly sends; it does not infer hidden reasoning.

Message previews track at most 16 concurrent message IDs per task. Once a new ID exceeds that bound,
new IDs are omitted for the rest of that task, even if an earlier message completes and frees space.
This prevents a continuation whose prefix was lost from being redacted as though it were a whole
message. Already tracked messages can finish, later tasks start with fresh capacity, and
`messageTrackingExhausted` explicitly marks the omission mode in subsequent message records.
A source event sequence gap also clears all partial message content and disables new previews for
that task: missing chunks may contain the rest of a credential, even for an already tracked ID.

Web background failures are redacted before job status is persisted, so job JSON, API responses and
refreshed pages consume the same sanitized diagnostic. HTTP exception responses also use the bounded
redactor. The default sensitive values are the server environment; callers that supply credentials
outside that environment must provide them through `UploadServer.sensitiveValues`. Oversized messages
are omitted before taking a preview, and HTML escaping still applies after redaction. This does not
retroactively scrub historical job records or arbitrary downloadable artifacts.

Reconstruction CLI and browser jobs own their journal through a best-effort adapter. A busy
writer, persistence failure, or phase-observer exception disables that display and emits a fixed
diagnostic without replacing the workflow result or original exception. Closing still attempts to
release the writer after a display failure and preserves the calling thread's interruption state.

```sh
./gradlew test --tests decompengine.jobs.AgentProgressJournalTest \
  --tests decompengine.jobs.BestEffortProgressJournalTest \
  --tests decompengine.web.UploadServerTest \
  --tests decompengine.web.SourceTreeJobReconstructorTest
```

Persisted display snapshots must account for every allocated sequence through retained events or
queue/history omission counts. Reads and writer restart reject inconsistent counts or truncation
markers with bounded diagnostics; counter validation avoids arithmetic overflow. Rejected history
is retained unchanged and writer ownership is released. These consistency checks do not authenticate
history or prove that events pending at a process crash were durable.

The browser labels its latest-30-row window separately from journal retention loss. Refresh and
polling report unavailable progress history instead of implying an empty complete stream; polling
continues after an HTTP failure. These display warnings do not alter job status or acceptance.
