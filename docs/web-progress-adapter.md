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

The mapper and HTTP adapter below implement producer projection and bounded
JSON snapshot/replay reads for this schema. The UI activity view, SSE and broader
concurrency/retention qualification remain open.

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

## Authenticated JSON snapshot and polling endpoints

The versioned API now exposes read-only `GET /api/v1/jobs/J/runs/R/snapshot` and
`GET /api/v1/jobs/J/runs/R/events?cursor=...&limit=...`, including nested base paths.
Both require the existing local session/origin policy and JSON Accept rules.
The server resolves the exact durable attempt, reads its fixed journal artifact
through the checked descriptor boundary, and rejects a changed attempt version
after the read with `409 PROGRESS_CHANGED`. Missing/inaccessible journal bytes
return `503 PROGRESS_UNAVAILABLE`, never an invented empty history. The reader's
missing-target exception needed explicit mapping; the HTTP regression caught
and fixed an initial generic 500 response for that case.

Snapshots include the authoritative run presentation and separate display
progress metadata: next sequence, queue/history omission counts and retained
record count. This optional v1 field preserves old snapshot fixture compatibility;
new endpoint responses always supply it. Consumers must not interpret its absence
as complete history. Counter/cursor consistency checks run in the typed client
and shared verifier. Snapshot run state remains independent of journal claims.
The version check covers a stable attempt observation around a stable journal
file read; it is not a transaction between workflow state and journal publication.

Use `oldestCursor` to explicitly read retained history and `throughCursor` to
resume after the snapshot cutover. Gaps return `410 PROGRESS_GAP`; clients must
read a fresh snapshot and visibly acknowledge lost history before resuming.
Polling is ordinary bounded HTTP with no retained stream/queue. Bootstrap now
reports the implemented source-journal read ceilings (1,024 events / 2 MiB);
pages remain capped at 200 events / below one MiB. A zero terminal-retention
window advertises no guaranteed time retention. These limits do not claim the
larger D0 target workload or timed retention policy is complete.

Actual HTTP tests exercise unauthenticated/foreign-origin/method/Accept denial,
wrong-job and cross-session cursor rejection, snapshot/oldest/paged/idle reads,
new writer continuation, explicit retention gap and omission counters, missing
journals and byte preservation without workflow execution. 161 JVM tests,
214 frontend tests, 38 valid/28 invalid shared fixtures, lint and typechecked
`distZip` passed. The packaged history fixture now includes an inert progress
journal and checks snapshot/two-page/idle reads with exact large token counts.

The packaged polling journey passed with the pinned browser:
[`web-progress-http-20260905.json`](evidence/web-progress-http-20260905.json).
It reads the new endpoints from an authenticated browser tab, verifies the exact
attempt/writer distinction and unsigned usage value, and confirms journal bytes
are unchanged. Chrome used test-only `--no-sandbox`. That checkpoint qualified endpoint reads
only. It did not establish automatic reconnection, SSE, long-lived slow-client
behavior or full #174 completion. The later activity UI checkpoint follows.


## Retained activity UI and bounded continuation

Attempt pages now offer opt-in polling with pause/resume. The view reads an
identity-bound snapshot, starts at its oldest retained cursor, and follows the
journal with one read at a time and a 2.5-second delay between reads. Attempt
state and acceptance are explicitly labeled as values at the snapshot; observed
phases never override them. Exact queue/history omission counts remain visible.
Missing counts do not imply complete history, and no percentage is inferred.

The display holds at most 200 observations. Reaching that bound pauses reads and
changes the same focused control to **Continue activity on next page**. Explicit
continuation replaces the displayed rows while retaining the cursor and last
observation for cross-page sequence checks. It does not restart at the oldest
record. Pause/resume keeps the current page. Conflicting replay, noncontiguous
continuation and incorrect attempt binding fail closed. Retention gaps require
an explicit fresh-history read; this replaces the old position and snapshot.
Unmount cancels reads and timers; session denial clears retained activity.

All message text remains withheld because the journal lacks an explicit public
visibility guarantee. This includes thought, system, assistant and unknown
roles. Current rows show observation metadata and available task/revision IDs;
public messages, plans/tool summaries, durable evidence links and full stage
presentation remain part of #175. A missing task/revision is labeled rather
than guessed. The list is outside a live region; a short polite status reports
following/paused state and the bounded row count.

The packaged history journey uses 205 inert persisted observations, including a
thought-role message, without starting a workflow. It proves exact 200/5 page
ordering, native Enter activation, focus preservation, no requests during a
three-second pause or after route departure, resumed idle polling without
repeated rows, text withholding and a polite accessibility-tree status. Journal,
report and installation bytes remain unchanged. Evidence:
[`web-activity-ui-20260905.json`](evidence/web-activity-ui-20260905.json), UI build
`f39cdd2f9270c3a4291c61e4fd2f0c743f53978e021f7cdbc6b36774893f5b9e`.
Chrome used test-only `--no-sandbox`; the packaged application ran without Node
or npm on its PATH. Shutdown and owned-work cleanup were confirmed.

222 frontend tests, lint and typechecked `distZip` passed. Focused tests also
cover a gap across the display boundary and activity cleanup on explicit
session logout. The first browser attempt failed because the driver omitted
the Enter character; correcting that input produced the retained passing run.
Manual screen-reader behavior, live producer scenarios, restart/reconnect,
multiple tabs and long-running qualification remain outstanding. This scoped
evidence does not close #174 or #175.

## Activity filters and correlation references

The activity page offers category and task-reference filters over its current
bounded page. Categories separate stage observations, message metadata, plan
metadata, tools/changes and other observations. Task matching is a literal,
case-sensitive substring of the recorded task ID or digest. Filters make no
requests, do not move the cursor, and do not discard nonmatching rows. Clearing
filters restores those rows. A no-match result explicitly says that other
retained pages have not been searched. Filter choices are local to the mounted
attempt view; they are not saved across reloads.

Each row links to its exact attempt under the configured deployment prefix.
Expandable correlation details expose recorded task/session/revision digests,
turn and request references, and a tool-call digest. Missing references are
labeled; unavailable evidence pages are not invented. Observed status and plan
entry counts remain observation metadata. Missing plan counts or entry metadata
read **Not recorded**, not zero. Message and plan text remain withheld pending a
producer public-visibility contract.

The packaged history journey additionally verifies local category/task filtering,
no additional polling requests while filtering a paused page, restoration of all
200 rows, exact attempt links, expandable correlation references and 320-pixel
reflow. Existing page continuation, pause/resume, focus, text withholding and
byte-preservation checks remain in the same journey. The retained report is
[`web-activity-filters-20260905.json`](evidence/web-activity-filters-20260905.json).
225 frontend tests, lint and typechecked distribution build passed. This extends
#175 fixture evidence without claiming complete stage views, public provider
messages, durable task/session/revision evidence pages or full accessibility
qualification.

## Activity connection recovery

A shared browser-availability hook suspends activity reads when the browser
reports offline or the document becomes hidden. It unregisters its listeners on
unmount. Suspension cancels the current read/timer but keeps the bounded page,
filters and cursor. Returning online or visible reads a new identity-checked
snapshot before continuing from the retained cursor. Obsolete responses are
ignored after cancellation. None of these transitions controls server work.

Network errors, timeouts and HTTP 502/504 trigger at most four automatic retries
with exponential delays of 1, 2, 4 and 8 seconds, each jittered by ±20%. Each
retry reconciles a new snapshot. A successful event-page read resets the retry
budget; exhaustion stops reading until explicit fresh-history recovery. Session
401 and access 403 are distinct non-retry failures and clear retained content.
Protocol/identity errors and retention gaps are not automatically retried.

The view distinguishes paused, background-suspended, browser-reported offline,
reconnecting, exhausted and session/access-denied states. It displays the browser
UTC time of the last successfully received activity page outside the live region.
That timestamp is a receipt time, not an assertion about the source journal's
freshness. The latest snapshot remains labeled separately from observation rows.
A retention gap may result from restart or eviction; this implementation does
not infer which occurred or automatically discard history to conceal the gap.

231 frontend tests, lint and typechecked `distZip` passed. Six focused connection
tests cover visibility/offline suspension, cursor/selection preservation,
reconciliation, bounded retries, session/access denial and late-response rejection.
The packaged browser uses actual tab foreground/background changes and CDP
network offline/online emulation. It verifies no reads in three-second suspended
windows, exactly one fresh snapshot for each resumption and retention of the
same five rows. Existing pause, pagination, focus, filters and fixture byte
preservation checks also pass. Evidence:
[`web-activity-connection-20260905.json`](evidence/web-activity-connection-20260905.json).
The application used inert observations only; Chrome ran with test-only
`--no-sandbox`, and shutdown/owned-work cleanup were confirmed.

This is the activity observer portion of #179. A shared connection state machine
across every private view, a distinct authenticated server-restart signal,
conflicting multi-tab workflow controls, full restart scenarios and long-running
qualification remain open. This checkpoint does not close #179 or D4.

## Reported usage and agent outcomes

The activity category **Usage and agent outcomes** selects `context_usage` and
`agent_finished` observations. Expand a row to inspect exact context occupancy,
input/output/cached-input tokens, tool-call counts, or its reported stop reason
and failure classification. These values remain scoped to the individual report
or receipt; the client does not sum them into attempt totals, derive progress
percentages, or infer a stop/acceptance decision. Completed, cancelled,
limit-exhausted, timeout, resource-exhausted, process-crash and transport values
remain distinct. Unknown future classifications remain recorded text.

Each panel identifies the report/receipt source and writer, journal recording
time, and the absence of a provider measurement timestamp. Recording time is not
substituted for measurement time. Missing counters stay **Not reported**; real
zero remains zero. Supported nonnegative producer duration text (`PT` with hours,
minutes and/or seconds, up to nine fractional digits) is converted to decimal
seconds using integer arithmetic. Unsupported or truncated duration text is
explicitly unavailable, not zero. Large token counters are rendered from their
exact decimal strings. Attempt limits and receipt usage also carry source labels
on the attempt page, and tool-call limits have explicit count units.

No monetary estimate is shown because this observation contract supplies no
configured pricing/version basis. Queue position and worker resource metrics are
explicitly unavailable here. This does not implement queue/worker summaries or
close #181; those remain planned work together with broader usage provenance and
measurement-time support.

250 frontend tests, lint, 161 targeted web/journal JVM tests and typechecked
`distZip` passed. Tests cover absent, partial, zero and maximum unsigned counters,
unknown and distinct outcome classifications, exact duration conversion, no
invented percentages/totals and missing pricing information. The packaged browser
opens two inert usage observations on the second activity page and checks exact
large values, nanosecond precision in decimal seconds, units, source/timestamp
limitations and cursor preservation. Existing pagination, filters, connection,
focus and byte-preservation checks also pass. Evidence:
[`web-observed-usage-20260905.json`](evidence/web-observed-usage-20260905.json).
No workflow ran. Chrome used test-only `--no-sandbox`; shutdown and owned-work
cleanup were confirmed.

## Receipt age during pauses and connection loss

Activity now displays elapsed age alongside the original browser UTC receipt
timestamp. Elapsed time uses this tab's monotonic clock, so wall-clock corrections
do not make retained data appear newly received or years old. The label is
coalesced to ten-second updates, then whole minutes/hours/days. It explicitly
measures page receipt age, not source-observation age or provider measurement time.

The timer runs only while the document is visible, including visible paused or
offline views. Hiding the document releases the timer; returning catches up from
the monotonic receipt anchor. A new verified page resets the anchor, and session
cleanup/unmount removes it. Age updates occur outside the live region and do not
restart polling, move focus, reset filters or confer acceptance authority.

261 frontend tests, lint and typechecked `distZip` passed. Focused tests cover
forward/backward wall-clock jumps, coalesced age progression, hidden-tab timer
cleanup, return after two hours and reset on a new receipt. The packaged history
browser verifies age advancement during an eleven-second pause without an
activity request, along with the existing connection/filter/pagination and
byte-preservation checks. Evidence:
[`web-activity-age-20260905.json`](evidence/web-activity-age-20260905.json).
No workflow ran; Chrome used test-only `--no-sandbox`. Shutdown and owned-work
cleanup were confirmed. JVM tests were not rerun for this frontend-only change.
This advances #179's stale-data presentation; shared recovery across other views,
explicit restart signaling and full multi-tab workflow qualification remain open.

## Session invalidation across tabs

After a server-confirmed sign-out, the initiating tab sends a credential-free
invalidation hint through an origin- and deployment-scoped `BroadcastChannel`.
The complete payload is `{version: 1, type: "session-invalidated"}`. It includes
no session/CSRF token, sign-in link, job identity, path or diagnostic content.
Other initialized authenticated/checking tabs discard private session evidence,
forget credentials, abort pending session operations and drop queued sign-in
intents. Their UI explains that another tab reported a session change and offers
an explicit session check. Receiving a hint never authenticates, fetches a new
session, signs out on the server or starts/replays a workflow mutation.

The hint is a reason to clear UI state, not proof of server authorization or
revocation. Unknown message shapes are ignored, disposed sessions detach/close
the channel, and another deployment prefix is isolated. An unconfirmed logout
does not announce confirmed revocation. If the browser disables the channel,
server-confirmed local logout still works; peer tabs rely on their own session
checks/expiry and server authorization. Delivery is best effort and is not an
authorization boundary.

267 frontend tests, lint and typechecked `distZip` pass. Six focused tests cover
credential-free payloads, prefix isolation, peer read cancellation and late
completion, queued sign-in cancellation, ignored messages, disposal, unavailable
channels and unconfirmed logout. The packaged browser opens a second authenticated
Runtime tab and verifies that confirmed logout clears its private Runtime state,
delivers only the fixed payload, creates no storage entries and makes no peer
requests or mutations during a three-second observation window. Evidence:
[`web-session-tabs-20260905.json`](evidence/web-session-tabs-20260905.json).
Existing history/activity/scheduler checks pass; no workflow ran. Chrome used
test-only `--no-sandbox`; installation bytes, shutdown and owned-work cleanup
checks pass. JVM tests were not rerun for this frontend-only change.

This advances shared session invalidation in #179. It does not complete server
restart signaling, unconfirmed-revocation reconciliation, cross-version tab
qualification or conflicting workflow-command scenarios.

## Public transport projection

The v1 producer now withholds `text`, plan `entries` and `path` from every observation,
regardless of message role or event kind. The journal does not certify provider-supported
public visibility; hiding prose only in the activity component left it in browser responses.
Known fields still undergo the existing type and size validation before projection. Each
withheld source field increments `omittedFieldCount`, alongside unknown source fields, and
withheld `text` sets `textOmitted: true`. Entire plan entries count as one omitted source field;
entry counts and truncation metadata remain available. These counts do not imply retained
event loss, and cursors still bind the original journal records, including withheld content.

Supported correlation, usage, event sequence and observation authority are unchanged. The
schema retains optional prose fields for compatibility with its design fixtures; schema validity
alone does not certify public visibility or oblige this producer to emit a field. New public and
plan metadata fixtures capture the implemented producer output. Legacy JSON/HTML uses its own
metadata projection and omission count spelling, documented in the API compatibility section.

Mapper tests cover all message roles, exact usage values and unknown-field accounting. The
HTTP progress test checks authenticated response omission and unchanged journal bytes. The
byte-page test uses large retained metadata to keep exercising response splitting after prose
removal. Full classification of retained labels and explicit provider public-message support
remain outstanding; this change does not claim that all possible journal data is public.

### Packaged privacy qualification

The retained [packaged browser report](evidence/web-progress-privacy-browser-20260905.json)
qualifies the current v1 omission behavior with inert data. The fixture contains 205 observations
with private prose/paths and one private plan. Actual browser reads inspect the first two and
next 50 events, requiring absence of prose, plan entries and paths, `textOmitted: true`, and
exact omission counts (three for the plan-bearing record, two otherwise). The UI separately
traverses all 205 observations as 200/5 pages and retains its text-withholding behavior.

The full history journey also passed exact usage rendering, keyboard/focus continuation,
pause/age updates, background/offline recovery, native report download, cross-tab session
invalidation and unchanged journal/report/installation bytes. The archive was built from
application commit `253a0b6`; its SHA-256 is
`92daaa7adfda05238421fb2b3f1f4eb28ac9327d1369c6ae42966a03f6c7c882`.
The report records the JAR/UI/Chrome identities, read-only installation, absent Node/npm on
the application PATH and confirmed cleanup. Chrome used test-only `--no-sandbox`.
No uploaded binary, native analysis or live agent ran. This covers the embedded SPA on the
recorded Linux/Chrome environment; legacy-browser automation, other browsers, certified public
messages and complete classification of retained metadata remain outside this evidence.

## Legacy HTML progress service boundary

The legacy job controller now obtains a projected snapshot through the same bounded service
read and privacy mapper as the legacy JSON route. `renderJob` accepts that snapshot explicitly;
its progress renderer no longer opens `agent-progress.json`. Callers that do not supply a
snapshot get an unavailable-progress label, even if a journal happens to exist beside the job.
Missing, malformed or oversized journals leave the job page usable and clearly state that
missing data does not establish empty history. A valid zero-event journal has a distinct
retained-empty message. Polling errors retain displayed rows and replace the status message
with unavailable progress; a successful subsequent response can replace that state.

HTTP tests check unavailable and valid-empty HTML alongside JSON and byte preservation. A
renderer regression supplies a snapshot differing from the on-disk journal and verifies only
the supplied data appears; an omitted snapshot does not trigger an implicit read. This removes
the progress-specific direct-read gap from the D2 audit. Other legacy exploration/repair HTML
report reads and the legacy session boundary remain migration work. Browser execution of the
legacy polling script is not covered by this JVM verification.

## Target polling query compatibility

The retained-journal endpoint now accepts the planned fallback query
`events?transport=poll&after=...&limit=...`, and the activity client sends that spelling.
Existing `cursor` requests use the same replay implementation and produce identical pages.
Transport may be omitted; `after` and `cursor` are mutually exclusive even when equal.
Duplicate/unknown fields, other transport values and oversized queries fail validation.
The same 1–200 page limit, bounded source reads, HMAC cursor binding and explicit gap behavior
remain in force. Polling rejects Last-Event-ID; that header is reserved for future streaming
and cannot silently reset a polling client to the beginning of history.

HTTP/core tests compare both spellings and exercise ambiguity, invalid transport and gap
behavior. Frontend tests require `transport=poll` and continuation through `after`. This
closes the target polling-query compatibility gap; SSE, heartbeat/resource management,
transactional cutover and timed retention are still outstanding under #174.

At source `3443883`, 179 web/journal JVM tests, 269 frontend tests, lint and distZip pass.
The [packaged history/activity report](evidence/web-polling-query-browser-20260905.json)
verifies the target query and equality with the cursor alias alongside 200/5 activity pages,
pause/resume, recovery, metadata privacy and retained-byte checks. It identifies artifact
hashes, an inert test-owned fixture, no workflow execution, test-only Chrome --no-sandbox,
unchanged installation and confirmed cleanup. This does not qualify SSE or live delivery.

## Dedicated stream resource prerequisite

`WebStreamResources` provides the resource owner for the forthcoming SSE adapter. It admits
at most 16 connections globally and two per authenticated session identity, independently of
the ordinary HTTP and workflow executors. Rejection leaves the exchange with the router so
it can return a typed error or keep using polling. The component does not authenticate a
request itself: the endpoint must call LocalWebAccess before admission and revalidate while
serving private events. It is not yet attached to an HTTP route or advertised as SSE support.

Only admitted reservations can create virtual-thread work or cleanup tasks. There is no
waiting-client queue or event buffer. Separate cleanup tasks prevent a blocked writer from
preventing its connection-close attempt, and a blocked close cannot serialize other clients'
cleanup. A reservation is released only after both the writer has exited and connection
closure has succeeded. Interrupting a writer or cancelling its lease alone does not refund
capacity. Failed cleanup keeps its reservation charged and makes shutdown report incomplete.

Each reservation has a bounded 30-second connection lease; its deadline interrupts work and
requests cleanup without running connection-close code on the deadline scheduler. Shutdown
rejects new admission, requests cancellation and waits within one bounded grace period. It
reports false if writers/cleanup remain, and late completion can be observed by another
shutdown check without restarting work. The future stream transport must reconnect from its
last acknowledged cursor; ending a connection is never a workflow cancellation.

Nine resource tests cover global/session limits, simultaneous admissions, cancelled writers
that ignore interruption, blocked/failed cleanup, deadlines, work failure, exact-once closure
and bounded shutdown with late completion. The tests use controlled callbacks and latches,
not a slow browser socket. Actual SSE framing, heartbeats, authenticated transport integration,
slow socket behavior and server lifecycle integration remain required before #174's stream
resource criteria are complete.

## SSE transport integration

The v1 events route now negotiates explicit text/event-stream and hands the exchange to
WebStreamResources. UploadServer owns and shuts down that resource pool. WebEventStream
uses the same WebProgressPages instance as polling, so session/job/attempt cursor binding
and replay positions are interchangeable. Snapshot, polling and SSE share readWebProgress's
fixed journal path and attempt-version guard; this remains a guarded read, not a transaction
with journal publication.

Frames contain the existing workflow.observation projection. Resume headers are bounded
and mutually exclusive with query positions; heartbeat comments carry no cursor. Retention
loss after delivery emits the existing retention.gap schema without an SSE id and closes.
Authentication is rechecked before source reads and writes. The activity UI remains on
bounded polling; this endpoint does not enable any unfinished production workflow adapter.

HTTP tests use an actual single-worker HttpServer to prove two open streams do not occupy
its only HTTP worker, quota rejection leaves ordinary requests responsive, logout closes
streams, Last-Event-ID replays after the acknowledged record, polling/SSE documents match,
retention loss emits an unnumbered gap and reconnect receives a pre-header 410. Accelerated
heartbeat/lease tests verify real connection closure and unchanged fixture bytes. A test on
UploadServer itself verifies routing and its shared guarded artifact projection. These do
not establish arbitrary slow-socket behavior, the full client reconnect algorithm, timed
retention or transactional snapshot/event cutover.

At source `e15ba2e`, 194 web/journal tests and distZip pass. The
[packaged SSE report](evidence/web-sse-browser-20260906.json) verifies native EventSource
receipt with the session cookie and an event/id identical to polling, alongside the existing
history/activity/recovery and retained-byte checks. No workflow executes. The report
identifies archive/JAR/browser hashes, test-only --no-sandbox, unchanged installation and
confirmed shutdown/cleanup. It proves native delivery, not full browser automatic reconnect
or fallback behavior; the UI still chooses polling.
