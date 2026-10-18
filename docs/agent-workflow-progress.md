# Persisted agent workflow progress

CLI and browser source reconstruction use `AgentWorkflowProgress` to project task events and
workflow validation phases into `reports/agent-progress.json`. This is a bounded operator view;
the invocation receipts, accepted checkpoints and archive verifiers remain the acceptance authority.

Each execution has a new run UUID and each task has a new turn UUID, even when the exact request
is retried. Events bind the immutable request digest, task identity digest and monotonic display
sequence. The terminal task record maps that turn to the session digest and final stop reason or
failure classification. It explicitly records that validation is still pending. A workflow-owned
accepted phase may subsequently reference an accepted source digest.
Display identity/content hashing classifies the complete text before encoding. Valid strings stream
through chunks of at most 4,096 UTF-16 units without splitting a surrogate pair; malformed strings
stream the receipt domain marker and every raw UTF-16BE unit through an 8,192-byte buffer. This
preserves the complete commitment while bounding temporary encoding buffers. Raw input length,
whole hashing time and request-binding admission still need their separate operation budgets.
Task identity digests and workflow-run display values are prepared once before queue admission.
Later task records reuse those immutable values instead of rehashing raw task/run IDs or
redacting the same run preview inside the producer monitor for every callback. Raw event and
request admission and total callback cost still need their separate whole-operation bounds.

`workflowRunId` and its digest correlate task events and `workflow_run_state` observations with a
durable workflow run. They are separate from the journal writer's `runId`, which changes on restart.
Run-state observations can name the provisional or canonical revision independently of a task;
revision IDs use the same redacted-preview and digest convention. Explicit provisional, compile-valid,
rejected, exhausted, resource-exhausted, cancelled and interrupted phases do not carry an accepted
source commitment. An accepted run-state observation requires that commitment. These shape checks
keep display meanings distinct; they do not validate a graph or confer acceptance authority.

One journal writer owns a filesystem lock. Producers normalize and enqueue without disk I/O;
the writer forces a temporary file, atomically replaces the snapshot, and forces its directory.
Defaults bound the ordinary queue to 128 events with one reserved overflow terminal record,
retained history to 256 events and the snapshot to 512 KiB. Superseding a pending overflow terminal
counts the earlier terminal as queue loss; both ordinary and reserved records drain in order.
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
Display identity/content commitments use the receipt text encoding: valid text keeps exact UTF-8;
malformed JVM strings use a `0xff` marker followed by raw UTF-16BE units. Distinct malformed IDs
therefore cannot collapse through replacement encoding and merge separate message buffers.
Configured literals reuse immutable prefix indexes for exact UTF-16 matching. Literal searches and
non-overlapping replacements use prefix fallback instead of repeatedly retrying long shared prefixes.
The same index checks final formatted hints and omission markers. The existing ordering, eight-pass
policy and 16,384-character replacement limit stay in force; the replacement builder also stays
within that limit. Index arrays require at most four bytes per admitted normalized code unit, plus
per-literal object/array overhead. Overall callback deadlines, raw event/request admission and total
shared-consumer resource qualification remain separate unfinished work.

The browser reads the same persisted snapshot at `GET /api/jobs/<job-id>/events`, updates at bounded
polling intervals, and uses text nodes for peer-authored previews. Refresh renders the retained history
from disk. CLI progress phases go to stderr; source/archive result paths remain on stdout.

Reconstruction CLI phase callbacks from the owned journal adapter enter a separate 32-phase
mailbox. The console worker reads only fixed phase enums from that mailbox; it does not read a
snapshot during construction, observation or close. Slow retained-file reads therefore cannot
suppress terminal console phases. The journal remains the browser/replay history, with its own
full-event loss counts. Mailbox omissions count console phase updates only. Callback capture and
run binding do not copy peer text or borrow another writer's observations. Close first attempts
the owned journal flush, then drains the mailbox with the existing 200-millisecond observer join.
A blocked console can still retain the one daemon or omit pending console lines on process exit;
console display is optional and never replaces the separate typed workflow result.

Repair runs now own a journal for their reports directory. Captured task events and final agent
receipts carry the durable repair run ID; policy checking precedes candidate validation. Provisional,
rollback and accepted observations are emitted after graph transitions, and the final observation
projects the persisted terminal outcome. An accepted source commitment comes from the fully accepted
graph head. The build phase encloses the provider call; the behavior phase marks checking its returned
report, not live per-case provider telemetry. A busy or failed journal is disabled with one fixed
diagnostic and cannot change acceptance, consume another repair attempt or replace durable failure.
Close retains the bounded journal drain and preserves thread interruption while releasing its lock.
Ordinary exceptions from the fixed repair warning sink are contained; warning interruption is
restored without replacing the original workflow failure or changing another journal owner's lease.
The default web/journal and repair warnings publish only a fixed kind to one process-wide daemon.
Its mailbox coalesces at most two pending kinds, retains no task/run values or exception, and never
holds its monitor during output. A blocked stderr sink therefore does not hold a workflow caller
or its journal lease. Warnings may be delayed or coalesced. The sole daemon can remain blocked until
process exit; this is not a complete output-retirement or callback-latency guarantee. Explicitly
injected warning callbacks still run synchronously and must remain prompt; their ordinary exception
and interruption behavior is unchanged.

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

Basic and Bearer credentials, credential fields and recognized token prefixes are masked before
configured literal values. A configured value such as `Bearer`, `api_key` or `ghp_` must not erase
the indicator and leave an otherwise unregistered credential visible. Direct redactor and actual
HTTP background-failure regressions cover this ordering, including persisted job metadata and
withheld public diagnostics. Literal replacement still enforces the intermediate 16,384-character
limit, including its exact boundary and safe omission when the marker is itself sensitive.

Reconstruction CLI and browser jobs own their journal through a best-effort adapter. A busy
writer, persistence failure, or phase-observer exception disables that display and emits a fixed
diagnostic without replacing the workflow result or original exception. Closing still attempts to
release the writer after a display failure and preserves the calling thread's interruption state.

The reconstruction command catches ordinary workflow failures after its progress owner closes,
prints a bounded redacted terminal diagnostic, and exits with status 1. It does not print the raw
exception chain. Configuration diagnostics and harness provenance also use the shared redactor.
The boundary preserves interruption and propagates fatal JVM errors; it does not change the
workflow's typed failure, receipt or validation authority.

Patch summary diagnostics use the same bounded redactor for failure reasons, phase/check details,
explanations, approval/isolation text and harness provenance. All supplied environment values are
included, independent of their key names. Redaction configuration is admitted before clearing output
or opening the patch logger. Complete approved diffs and retained request/response code keep their existing
artifact formatter and are not shortened by diagnostic preview limits. Their full privacy scope,
doctor diagnostics, logs, paths and historical artifacts still require separate qualification.
The patch CLI masks usage messages, provenance and ordinary failures; configuration failures exit 2,
other ordinary failures exit 1, interruption is preserved and fatal errors propagate.
If a CLI redaction inventory is rejected, the workflow does not run: reconstruction exits 1 and
patch exits 2 with no diagnostic payload from the unadmitted inventory. Admission interruption is
preserved. Normal usage errors retain their command help and exit status 2.

Captured MVP request transcripts admit their complete raw prompt, failure kind, file paths/content
and regression identifiers before rendering Markdown. The unchanged agent objective is checked
separately after trimming, and its admitted UTF-8 file bytes are reused for execution. Request
content and initial staging retain their existing 4 MiB and 2 MiB default ceilings; oversized raw
padding cannot bypass admission through a short normalized objective. File/regression entry limits
also apply before retention. The staging authority still enforces its own path, directory and
mutation rules.
Regression IDs, arguments and stdin share the existing aggregate regression-byte ceiling, and
argument counts share the aggregate argument ceiling. Argument lists and stdin are copied only
after their admitted prefix fits; the complete admitted payload also counts against the raw
request-content ceiling. Caller mutation cannot change the retained regression snapshot.

Response admission checks the raw summary before trimming, the normalized/fallback summary, patch
paths and complete replacements against the existing 16 MiB response and 2 MiB patch defaults.
Rejection follows the existing rejected-assessment path after the immutable invocation receipt is
persisted. The retention functions leave an existing transcript unchanged when admission fails. These are
input-content budgets; Markdown framing and redaction output are not an asserted artifact-size cap.
Complete permitted code and diffs retain their full formatter and are not diagnostic previews.
Raw file reads, process stream collection, full artifact masking, host memory and verified cleanup
remain separate requirements; transcript admission does not qualify those boundaries.

Legacy Doctor connectivity failures report the destination host and fixed remediation without
copying HTTP exception messages or cause chains: Java header-validation errors can include the
complete Authorization value. This diagnostic path still propagates interruption, cancellation
and fatal errors. Tools-only environment access, probe execution and profile budgets are unchanged.
Other Doctor diagnostic fields and complete artifact privacy still require separate qualification.

Doctor diagnostics accept a separate caller-owned secret inventory; the configuration map remains
opaque in both ACP and tools-only modes. The inventory is copied and admitted before probing,
with the shared limits of 4,096 values and 1,048,576 UTF-16 units. Only the explicit legacy transport path adds
the API key it already resolves. Raw configuration is checked before trimming or projecting a host,
and advertisement previews are checked before terminal quoting. Report names/details use bounded
masking and the existing private-fragment concealment index; pass/fail values retain their meaning.

The agent-enabled CLI supplies its process inventory and rechecks complete terminal lines after
formatting. Ordinary escaping exceptions are rendered without raw cause chains. Diagnostic inventory
rejection exits 2 without inspecting or emitting diagnostic payload; check/ordinary failures exit 1
and success exits 0. Interruption, cancellation and fatal errors propagate. Tools-only mode keeps
ambient/legacy configuration unenumerated, uses format-only masking and renders invalid usage with
fixed guidance instead of echoing unknown arguments. These diagnostic changes do not qualify probes,
provider execution, cleanup or the complete privacy/release scope.

```sh
./gradlew test --tests decompengine.jobs.AgentProgressJournalTest \
  --tests decompengine.jobs.BestEffortProgressJournalTest \
  --tests decompengine.web.UploadServerTest \
  --tests decompengine.web.SourceTreeJobReconstructorTest
```

Web shutdown marks admission as stopping before draining HTTP requests. Owned workers
receive one shutdown interruption; the service preserves its job-root lease until
workers actually exit. Final legacy status writes clear and restore the interrupt flag
around atomic metadata publication. Restart projects interrupted legacy work through
the durable service while preserving its historical job.json bytes. CLI shutdown uses
the bounded shutdown hook and reports incomplete cleanup explicitly.

Persisted display snapshots must account for every allocated sequence through retained events or
queue/history omission counts. Reads and writer restart reject inconsistent counts or truncation
markers with bounded diagnostics; counter validation avoids arithmetic overflow. Rejected history
is retained unchanged and writer ownership is released. These consistency checks do not authenticate
history or prove that events pending at a process crash were durable.

The browser labels its latest-30-row window separately from journal retention loss. Refresh and
polling report unavailable progress history instead of implying an empty complete stream; polling
continues after an HTTP failure. These display warnings do not alter job status or acceptance.

Optional browser qualification uses the production renderer with an inert active-job fixture. It
mocks event/status responses in Chromium without starting workflow execution. Supply Playwright
and its browser installation separately (the recorded run used Playwright 1.63.0):

```sh
java -cp 'build/libs/*:build/oracle/gcc/kotlin-boot-runtime/*' \
  scripts/fixtures/ProgressPageFixture.java build/progress-browser-fixture
DECOMP_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright \
  node scripts/verify-progress-browser.cjs \
  build/progress-browser-fixture/page.html build/progress-browser-evidence/new-run
```

Build the application JAR and staged runtime first using the relevant normal build/test task.
The evidence directory must be new. A successful run records the rendered HTML digest, browser
version, scenarios and request count, plus a screenshot and Playwright trace. This checks actual
DOM updates, row limits, separate loss/window warnings, HTTP/network failures, subsequent recovery,
and peer-text escaping. It does not qualify a real-agent job, server restart, or browser matrix.

New snapshots persist `omittedSequenceRanges` as ordered, nonoverlapping half-open ranges with
`startInclusive` and `endExclusive` decimal strings. They identify the exact complement of retained
event sequences below `nextSequence`, including trailing omissions. There are at most one more
range than retained events (1,025 at the largest configured history), and ranges share the existing
snapshot byte cap. Reads reject inconsistent ranges when supplied. Older schema-1 snapshots without
this field remain readable and acquire ranges on the next writer publication. Queue/history
counters retain aggregate causes; individual ranges do not distinguish those causes. These ranges
cannot account for events lost before an interrupted process published its snapshot.


### Complete MVP artifact privacy projection

MVP evidence snapshots one bounded environment-value inventory for diagnostics and
complete artifact display. Complete projections apply the shared credential-format
precedence and control-character policy, then use a packed sparse multi-pattern
literal index; they do not apply the diagnostic preview cutoff to permitted code
or diffs. Request filenames and complete rendered Markdown are checked as well.
The existing `maximumProjectionBytes` bounds each builder and masking stage before
growth; byte accounting includes surrogate pairs formed across append boundaries.
Fixed-point/marker collisions or projection excess refuse before replacing a
transcript. Authoritative captured bytes, receipts, hashes and compilation inputs
are unchanged. These components still require exact-source Actions qualification;
stream collection, chunk/session privacy, cleanup and real-agent qualification
remain separate open acceptance.


### MVP logger and interactive approval privacy

The workflow logger and default approval prompt reuse the admitted immutable
privacy inventory. Log display also conceals private line fragments derived from
that same bounded inventory and retains credential-value continuation state for
each pipe and emitted record order. Complete console and retained prefixes are
checked before either destination is written. Raw command/binary results and
injected approval callback inputs remain validation data; the default prompt
projects its complete summary and refuses an unsafe decision label before input.
Command reader/display failures are latched privately and rethrown unchanged after
the existing concurrent drains and wait, rather than accepting a partial capture
or printing raw child-thread exceptions. This changes neither
process launch/isolation recipes nor cleanup policy. Raw collector size, blocking
I/O and bounded failure termination still require separate resource work; the
binary boundary, unlike the command logger, still reads stdout/stderr sequentially.
These source components require their own ordinary Actions qualification.


### Combined coverage and rejected response display

Credential-format, complete configured-literal and continuation spans are computed
on the same normalized input and merged before replacement. Delimiters inside an
admitted secret therefore cannot leave a tail after a generic field mask. Both
pipe-local and emitted-order continuation scopes plan from raw normalized lines
before either can conceal an introducer. Returned receipt/candidate bindings now
precede response transcript projection, so a display refusal reaches the existing
rejected-assessment path rather than leaving the captured turn pending. The
immutable receipt, capture validation and assessment serialization remain intact.
These review corrections require current-source ordinary Actions evidence.
