# Embedded workbench API and evidence contract

This is the D0.4 design contract for [#148](https://github.com/minsago-elite/decomp_thing/issues/148),
within [D0](https://github.com/minsago-elite/decomp_thing/milestone/26). It specifies implementation
work; it does not declare `/api/v1`, durable web attempts, event storage or Git support implemented.
Live scope remains in the owning GitHub issues. See [architecture](web-architecture.md),
[navigation](web-navigation.md), and [browser trust](web-trust.md).

The machine-readable boundary is [contract.schema.json](../contracts/web/v1/contract.schema.json).
Its representative success, error, request, event and report examples are synthetic contracts, not
execution or release evidence. Run `python3 contracts/web/v1/verify.py` using the existing
`fastjsonschema` development tool (`requirements/oracle-generation.txt`). The verifier checks
the positive and negative fixture manifest and selected cross-field invariants. D2 adds production
DTO/HTTP and generated TypeScript drift tests; fixture validation alone cannot prove those exist.

## Wire rules and compatibility

All paths below are relative to the configured `basePath`. The default is `/`; a configured prefix
must end in `/`. Construct URLs with this bootstrap value; never infer an origin or filesystem path
from report content. `/api/v1` is the major API namespace. JSON documents use UTF-8, camelCase,
`apiVersion: 1`, a `kind` discriminator and, for HTTP responses, a server-generated `requestId`.
Responses contain `data`; errors contain `error`. SSE event records have their own schema and
origin correlation ID and are independent of the connection's request ID. Every HTTP response
also carries `X-Request-ID`; that opaque ID contains no filename, token or user input.

`Accept: application/json` (or `*/*`) selects JSON; streams require `text/event-stream`. The
implemented raw exploration download responds as `application/octet-stream` and requires an
Accept range admitting that response type; its report descriptor still identifies the underlying
artifact as JSON. JSON mutation bodies require
`Content-Type: application/json`; upload requires `multipart/form-data` with exactly one `binary`
part. No request to `/api/**` receives SPA HTML, including unknown routes, malformed requests,
exceptions and unsupported methods. Unsupported methods return `405` plus `Allow`; unsupported
`Accept` returns `406`, and unsupported request content type returns `415`. `HEAD` support is
route-specific; permitted HEAD requests return the corresponding GET status and content headers
without a response body.
GET/HEAD never upload, queue, resume, cancel, accept, initialize Git, fetch or publish anything.

Request fixtures wrap the actual body as `{apiVersion, kind, data}` only to select the schema;
send `data` as the HTTP request body. Responses and event fixtures are the actual JSON wire shape.

The checked producer schema is intentionally closed: accidental fields, internal paths and enum
values fail verification. Readers may ignore additive response object fields within v1 after
validating all known fields, but must reject unknown request fields. New optional response fields
are compatible; removal, type/meaning changes and new required fields require a new major namespace.
An unknown response kind, enum, event type or producer report version renders an explicit
unsupported/unknown state; it never maps to success or accepted. Invalid JSON or known fields with
wrong types produce a decoder error, retain the previous snapshot as stale and disable dependent
mutations. Bootstrap negotiates supported API versions and UI/application build IDs. An incompatible
major produces a version recovery view; reloading cannot repeatedly replay a mutation.
An unsupported bootstrap contract clears private session/instance observations and displays an
explicit incompatible-version recovery message with a manual browser reload action. It offers
no retry that can replay a sign-in mutation. An unsupported logout response remains unconfirmed.

IDs are case-sensitive opaque strings. Clients must not parse their spelling or synthesize them.
The existing 32-character lowercase hexadecimal `Job.id` remains a valid `jobId`; migration must
preserve it. Strings called `sha256` are exactly 64 lowercase hexadecimal characters and describe
explicit bytes, not an unverified claim from the browser.

Every potentially 64-bit address, byte size, offset, count, sequence, token usage or duration is a
JSON string. Unsigned counts use canonical decimal `0|[1-9][0-9]*`, bounded to `2^64-1`; signed
quantities, when needed, use canonical signed decimal and an explicitly documented bound. Binary
addresses use `0x` followed by 1–16 lowercase hex digits with no redundant leading zero (except
`0x0`), preserving unsigned ELF values. Do not round-trip through JavaScript `Number` or a signed
Kotlin `Long` for `ULong` values. Compare counts with `BigInt` or validated decimal-string utilities.
Small, explicitly bounded page limits, HTTP status, line numbers and schema versions are numbers.
Finite confidence ratios remain numbers in `[0,1]` with their meaning and denominator displayed.
Binary payload snippets use lowercase hex, never implicit text decoding; strict UTF-8 text reads
report decoding failure and still allow a bounded byte view/download.


### Bootstrap build and listener identities

The current bootstrap producer reports `apiVersions`, `applicationBuildId`, `uiBuildId`,
configured upload/request/page limits, and explicit workflow capability states. Unavailable
workflow adapters remain unavailable; reading bootstrap does not launch a tool or workflow.
`applicationBuildId` identifies application bytes and `uiBuildId` identifies packaged UI bytes.
Neither identifies a running server. Runtime shows a mismatched page/server UI build and asks
for a reload; the decoder rejects an unsupported API major without replaying mutations.

`serverInstanceId` is an opaque, non-secret identity generated once per listener lifetime.
It remains stable across requests and browser sessions and changes when the server restarts,
including a restart of the same application/UI build on the same job store. It is not an
authorization token, durable job/run/revision identity, or proof that a tool is available.
The property is optional in the v1 schema so older servers remain compatible; absence means
unknown and is displayed as “Not reported”. Clients must not substitute a build hash for it.

Each successfully checked bootstrap publishes a fresh page-local session generation. Private
job, history, attempt/event and dashboard subtrees use that generation as their lifetime key,
so an intermediate checking render being coalesced cannot keep an old private cache or event
connection alive. A changed or unreported server instance also invalidates pending
instance-bound upload observations. Durable upload tickets retain their explicit reconciliation
path; the browser does not replay a mutation automatically. No identity enables workflow actions
or changes their separate capability/authorization gates.

### Unexpected internal API failures

The HTTP matrix exercises unexpected exceptions inside real v1/legacy request dispatchers,
including unknown v1 routes/majors and the shared versioned session/CSRF routes in legacy mode.
It requires `500 INTERNAL_ERROR`, JSON, no-store caching, matching opaque response/header IDs and
fixed messages without exception text or private values. A response already committed is closed;
the server does not attempt to append a second error envelope. Each scenario recovers through
a read under the original session, without changing stored job bytes, invoking a workflow or
replaying an ambiguous session mutation. This covers controller routing separately from the
direct error-renderer control; it does not establish live provider/tool behavior, complete
legacy sunset migration or production-release qualification.

## Resource and authority identities

| Identity | Meaning and lifetime | Must not be substituted with |
| --- | --- | --- |
| `jobId` | Persisted upload/library record, stable across restart and retries | Filename, binary path or content digest |
| `runId` | One explicit workflow attempt for one job; immutable workflow/input revision binding | Job status, agent session ID or retry count |
| `revisionId` | Immutable source snapshot registered to the job, with `sourceSha256` | Mutable current tree, Git branch, graph head pointer |
| `graphNodeId` | Canonical repair graph node carrying accepted/rejected/root status | Web run ID or source digest |
| `artifactId`, `fileId` | Server-issued identity resolved within a job and optional run/revision binding | Relative or absolute filesystem path |
| `cursor`, `sequence` | Durable stream position; cursor is opaque, sequence is a decimal string | Wall-clock ordering or an agent's per-invocation sequence |
| `repositoryId` | Managed repository registration, including its isolation policy | Remote URL or `.git` path |
| `worktreeId` | Registered source workspace plus repository association | Branch name or working directory |
| `operationId` | Durable Git operation, including cancellations and recovery | Request ID, current worker or Git process ID |
| `refId`, `objectId` | Server ref registration and full Git object identifier respectively | Display abbreviation, accepted revision or archive digest |

`revisionId` may identify a candidate as well as an accepted revision. Acceptance is a separate
verified relationship to canonical validation and publication evidence. Multiple graph nodes or Git
commits may contain identical source bytes. The registry records each relationship rather than
assuming a content hash identifies a workflow. If older records do not establish a run/revision
association, return null/unknown and show legacy evidence without inventing an association.

## HTTP route matrix

`J=/api/v1/jobs/{jobId}`, `R=J/runs/{runId}`, `V=J/revisions/{revisionId}` and
`G=J/repositories/{repositoryId}` abbreviate path prefixes, not literal routes. Every route uses
the local session boundary defined in the browser-trust document; session bootstrap is its sole
pre-session exception. A successful upload persists a job and never starts execution. Identical
bytes uploaded with a new idempotency key create a distinct job; content deduplication is an
internal storage optimization and must not merge identity, permissions or history.

| Method and route | Success document/status | Preconditions and ownership |
| --- | --- | --- |
| `POST /api/v1/session` | `200 session` | Single-use bootstrap token in body; same-origin/Host policy; #161 |
| `DELETE /api/v1/session` | `204` | Authorized CSRF-protected logout; #161 |
| `GET /api/v1/bootstrap` | `200 bootstrap` | Sanitized capabilities/readiness/build IDs/limits; #166 |
| `GET /api/v1/jobs` | `200 jobs` | Bounded cursor/filter query; #162 |
| `GET`, `HEAD /api/v1/recovery` | `200 recovery` | Private, bounded, display-only recovery-file summary; no query parameters |
| `GET /api/v1/uploads/{uploadId}` | `200 uploadProgress` | Ephemeral session-bound transfer bytes and publication phase; #169 |
| `POST /api/v1/jobs` | `201 job`, `Location: J` | Multipart, upload limits, idempotency; #162 |
| `GET J` | `200 job`, ETag | Snapshot read; #159/#160 |
| `PATCH J` | `200 job` | Allowlisted label/archive metadata, If-Match and idempotency; #173 |
| `DELETE J` | `202 operation` | Reviewed retention/deletion policy and If-Match; #172 |
| `GET J/runs`, `GET R` | `200 runs`, `200 run` | Bounded attempts or durable attempt snapshot; #160 |
| `GET R/progress-pin` | `200 progressPin`, strong run ETag | Current per-attempt journal pin; #172 |
| `PUT R/progress-pin` | `200 progressPin`, original result on keyed replay | Strict `progressPinRequest`, session/Origin/CSRF, run If-Match and idempotency; #172/#177 |
| `POST J/runs` | `202 run`, `Location: R` | `workflowStart` request, capability/limits/input checks, job If-Match; #163 |
| `POST R/cancel` | `202 run` or `200 run` if already terminal | Closed `workflowCancel` request, idempotent recorded intent, run If-Match; #163 |
| `POST R/recover` | `202 run`, `Location` of a new attempt | Explicit `retry` or capability-gated `resume`; If-Match; #163 |
| `GET R/snapshot` | `200 snapshot`, ETag | Run state and consistent event watermark; #174 |
| `GET R/events` | `200 text/event-stream` | Resume with `Last-Event-ID` or `after`, never both; #174 |
| `GET R/events?transport=poll` | `200 events` | Same retention/cursor semantics, bounded page; #174 |
| `GET R/reports/{reportId}` | `200 report` | State may be missing/partial/unsupported/unknown; #165 |
| `GET R/source-catalog` | `200 sourceCatalog` | Bounded flat manifest metadata; selected durable job/run; #490 |
| `GET`, `HEAD R/revisions/{revisionId}/sources` | `200 revisionSources` | Bounded canonical input commitments for the selected persisted candidate; #490 |
| `GET`, `HEAD R/revisions/{revisionId}/source-directories/{directoryId}` | `200 revisionDirectory` | Lazy immediate children of canonical input prefixes; use `root` for the first directory; #188 |
| `GET`, `HEAD R/revisions/{revisionId}/source-files/{fileId}` | `200 revisionFile` | Recorded file metadata and opaque parent directory, without requesting its body; #188 |
| `GET`, `HEAD R/revisions/{revisionId}/source-files/{fileId}/chunk` | `200 sourceChunk` | Digest-verified bounded UTF-8 or hex ranges of a committed input; #490, #545 |
| `GET`, `HEAD R/revisions/{revisionId}/source-files/{fileId}/content` | `200 application/octet-stream` | Complete authorized input download, at most 8 MiB; #491, #545 |
| `GET J/revisions`, `GET V` | `200 revisions`, `200 revision` | Immutable source/acceptance bindings; #165/#199 |
| `GET V/sources`, `GET V/sources/{fileId}` | `200 files`, `200 file` | Bounded tree/page/read; #165/#188/#189 |
| `GET V/search` | `200 matches` | Explicit revision and query/byte/result/deadline bounds; #190 |
| `GET J/artifacts`, `GET J/artifacts/{artifactId}` | `200 artifacts`, `200 artifact` | Optional run/revision filters validated together; #165/#192 |
| `GET`/`HEAD J/artifacts/{artifactId}/content` | `200` or `206` bytes | Immutable digest binding, contained stream; #164/#192 |
| `POST V/archive-verifications` | `202 operation` | Explicit bounded integrity verification, no binary execution; #193 |
| `GET G`, `GET G/worktrees/{worktreeId}` | `200 gitWorkspace` | Capability-gated repository/worktree registry; #200/#202 |
| `GET G/{status,diff,history,refs,worktrees,remotes,conflicts}` | Bounded typed Git read | Scoped worktree/ref/object IDs; #202/#204/#207/#210/#211 |
| `POST J/repositories` | `202 operation` | Explicit init/attach/clone, validated configuration; #201/#209 |
| `POST G/operations` | `202 operation` | Named action, selected IDs, guards, idempotency; #203–#212 |
| `GET G/operations/{operationId}` | `200 operation` | Durable outcome/recovery state; #209 |
| `POST G/operations/{operationId}/cancel` | `202 operation` or terminal `200` | Explicit cancellation, optimistic guard; #209 |

Schemas cover representative `session`, `bootstrap`, `job(s)`, `run`, `snapshot`, `events`,
`report`, `revision`, `artifact`, `gitWorkspace`, `operation`, errors and mutation requests.
The route matrix also reserves service-owned collection/detail DTOs (files, matches, refs, diffs
and metadata edits). Their owning issues must add exact bounded schemas and golden fixtures
before enabling those endpoints; this document does not claim those schemas or endpoints exist.
Optional PR publication remains a separately advertised #213 provider capability.

Collection defaults are 50 records, maximum 200. Invalid/out-of-range limits are `422`, not silently
clamped. Jobs default to `(createdAt DESC, jobId DESC)`; the opaque cursor binds the normalized
filter, sort, admission snapshot and last key. New inserts cannot appear midway through the same
snapshot or duplicate prior rows. Removed entries may be absent, and deletion is not repaired by
offset shifting. Expired snapshots return `410 CURSOR_EXPIRED` with guidance to refresh. Supported
job filters are bounded display-name search (256 characters), exact known status, inclusive
`createdAfter` and exclusive `createdBefore` RFC3339 instants, and `sort=newest`
(default) or `sort=oldest` creation/identity ordering. Cursors cannot be reused across
resources, revisions or filters. Counts are optional and explicitly exact/estimated/unknown;
absence of a total never prevents page navigation.

## Errors, deadlines and concurrent mutations

The workflow-start transport accepts only the `workflowStart` data object (not
its fixture wrapper), bounded to 4096 bytes. It uses the shared local
session/Origin/JSON/CSRF mutation boundary before reading a body or job record.
It requires a canonical job target, no query, one strong job `If-Match`, one
16–128 character `Idempotency-Key`, and no other conditional headers. Both
identity fields must be present as bounded IDs or null; all four limit fields
must be canonical unsigned decimal strings. Duplicate keys, unknown fields,
invalid UTF-8, numeric JSON limits and arbitrary command/path fields are refused.

An admitted start returns `202 run`, its run `Location` and strong run ETag.
Replay returns the same retained run identity and current retained run state,
with `Idempotency-Replayed: true`, even after later work or a restart. It neither
requeues work nor promotes candidate output to acceptance. Key conflicts are
409, a fresh stale guard is 412, per-job active work is 409, admission capacity
is 429, and unavailable workflow/harness/limits are 503. Missing guards are 428;
invalid request values or unavailable accepted input are 422. Uncertain
publication returns a recovery failure without a success location. A scheduler
refusal that was durably recorded returns its failed run; another scheduling
exception requires reconciliation through the job and retained key.

Production durable adapters remain unregistered, and bootstrap continues to
report them unavailable. Without registered adapters or retained keyed starts,
POST retains the existing 405 response without consuming a body. A retained
receipt keeps the route available for authenticated read-only replay after
registrations are removed; it does not enable fresh work. Injected inert
adapters qualify transport/storage behavior, not runtime readiness or upstream
model/binary execution and accepted-publication integration.

The reserved cancellation transport has a closed `workflowCancel` data object:
exactly `{"action":"cancel"}`, bounded to 1024 bytes. The fixture wrapper is not
the HTTP body. Job/run identity comes from the canonical route, the optimistic
run guard from one strong `If-Match`, and replay identity from one 16–128 character
`Idempotency-Key`. No query, other conditional header, caller-selected actor,
command, path or execution target is accepted. The shared local
session/Origin/JSON/CSRF mutation policy must succeed before body consumption or
any service read. Duplicate keys, unknown fields and invalid UTF-8 are refused.

Cancellation returns the current retained `run`, its strong ETag and canonical
run `Location`. An originally nonterminal acknowledgement uses 202, even if a
queued task has already become cancelled by response time. An acknowledgement
recorded for an already terminal run uses 200. Replay preserves that original
status with `Idempotency-Replayed: true` and returns current run state without a
second signal or an old task version. The actor is derived only from the
authorized session; actor and receipt internals are not response fields. Neither
202 nor receipt replay asserts worker termination or promotes candidate output
to an accepted revision.

The cancellation handler now dispatches this route through
`WebJobMutationBoundary.authorizeCancellation`. The capability derives the actor
from the authorized session and calls the owned service coordinator; the HTTP
controller cannot select an actor or write storage directly. Fresh stale guards
return 412, conflicting retained intent 409, exhausted receipt capacity 429, and
unknown/foreign targets 404. Uncertain publication returns 503 without a success
location or signal. Running work without an owned task requires reconciliation.

`WebCancellationControllerTest` adds inert HTTP controls for queued/running
cancellation, concurrent replay, completion races, accepted-reference and
diagnostic preservation, guards, strict JSON, actor isolation, revocation,
capacity and publication faults. Service/storage restart coverage retains the
same listener's in-memory authorization service. It does not establish replay by
a new session after a full listener restart. These authored methods await their
own Actions qualification; browser and production-adapter/runtime qualification
remain unfinished. Bootstrap continues to report workflows unavailable, and
fresh starts without registrations or retained start receipts retain 405.

Errors carry `code`, safe `message`, `retryable`, optional field-level `details` and
`retryAfterMs`; the correlation ID connects to redacted server logs. A detail contains a JSON
pointer plus stable code/message and never the rejected value. Resource existence is disclosed
only after session authorization. EVENT_GAP additionally carries typed recovery metadata for
the selected resource and a fresh snapshot URL. Raw exceptions, commands, environment, paths and credentials
are never browser diagnostics.

| Status | Stable examples | Client action |
| --- | --- | --- |
| `400` | `MALFORMED_JSON`, `INVALID_CURSOR` | Fix syntax or reload cursor |
| `401` / `403` | `SESSION_REQUIRED`, `SESSION_EXPIRED`, `ORIGIN_DENIED`, `CSRF_DENIED` | Reauthenticate or correct deployment; no automatic mutation replay |
| `404` | `NOT_FOUND` | Keep selected identity visible and show missing resource |
| `405` / `406` / `415` | `METHOD_NOT_ALLOWED`, `NOT_ACCEPTABLE`, `UNSUPPORTED_MEDIA_TYPE` | Correct protocol |
| `409` | `ACTIVE_RUN`, `IDEMPOTENCY_CONFLICT`, `REF_CHANGED`, `WORKTREE_BUSY` | Refresh and require a reviewed new intent |
| `410` | `CURSOR_EXPIRED`, `EVENT_GAP`, `RESOURCE_GONE` | Reconcile snapshot or explain retention |
| `412` / `428` | `VERSION_CONFLICT`, `PRECONDITION_REQUIRED` | Refresh current state and guard |
| `413` / `422` | `BODY_TOO_LARGE`, `VALIDATION_FAILED`, `UNSUPPORTED_BINARY` | Show bounds or field errors |
| `429` | `QUOTA_EXCEEDED` | Honor `Retry-After` without duplicating work |
| `501` / `503` | `CAPABILITY_UNSUPPORTED`, `CAPABILITY_UNAVAILABLE`, `SERVER_DRAINING` | Explain reason and retain view |
| `500` / `504` | `INTERNAL_ERROR`, `DEADLINE_EXCEEDED` | Show request ID; reconcile uncertain mutation outcome |

An authorized streamed upload that reports a typed uncertain publication returns
`409 RECOVERY_REQUIRED` with `Location: <basePath>api/v1/jobs/<jobId>`. The existing
error envelope remains unchanged, with `retryable:false` and no `Retry-After`.
The location identifies the retained job for an authenticated read; it is not an
instruction to submit the upload again or an assertion that analysis completed.
Private filesystem causes and paths are withheld.

Until storage is reopened, the job read truthfully reports recovery is required.
The service also refuses further uploads. That separate
`503 RECOVERY_REQUIRED` refusal has no guessed job location. After explicit
restart/reconciliation, an upload with the same idempotency key and intent can
replay its retained publication receipt rather than create another job.

The server advertises stricter configured limits at bootstrap. Contract defaults are 30 seconds
for ordinary HTTP requests, 120 seconds for upload and 120 seconds download idle time; JSON bodies
are at most 1 MiB and complete upload requests at most 32 MiB. Stream source reads in at most
256 KiB chunks and log reads in at most 64 KiB chunks. Separate request admission, disk staging,
workflow queue, workers, event clients and output quotas prevent a long upload/run from blocking
status. Long workflows/Git operations return a durable identity within the admission deadline;
their independent execution/idle/byte limits are explicit in request/capabilities. Browser fetches
use AbortController when navigation becomes obsolete. Aborting a request or closing a tab is not
a workflow cancellation. Never report a disconnected stream as a failed run.

Every mutation except single-use session bootstrap/logout requires `Idempotency-Key` (opaque,
16–128 characters). Scope it to the authenticated principal, method and canonical target. Persist
key, normalized request digest (including preconditions and upload content digest), decision and
result identity atomically with admission, before execution. Repeating the exact request returns
the original status/identity with `Idempotency-Replayed: true`, even when its old If-Match guard
would now be stale; the key lookup precedes a fresh precondition evaluation. Reusing the key with
different intent gives `409 IDEMPOTENCY_CONFLICT`. Keys survive restart and remain for at least
24 hours after terminal operation state; resource retention preserves a tombstone through that
window. A browser never automatically retries an expired key or ambiguous non-idempotent request.
It resolves the known job/run/operation or refreshes before asking for a fresh explicit action.

Mutable resources return a strong ETag derived from an opaque `version`. `If-Match` is mandatory
on changes to an existing resource; missing and stale guards produce `428` and `412`. The server
checks authorization, guard, accepted input revision, queue admission and transition under the
same transaction/lock that records the action. One active source-mutating run per job/worktree is
the default. Returning `202` means the intent is durably admitted; `completed` means the operation
ended, and says nothing about validation or acceptance. Cancelling is a recorded intermediate
state until workers report cleanup; a completion race returns the authoritative terminal state.
Retry/resume create a distinct run referencing the previous attempt and preserve its evidence.
Restart marks abandoned active attempts interrupted and reconciles committed publication journals;
it never silently launches execution or duplicates accepted publication.

## Bootstrap and capability truth

Bootstrap contains API/UI/application versions, `basePath`, readiness, sanitized runtime versions,
session expiry, an in-memory CSRF token, limits and
capabilities. Readiness distinguishes `ready`, `degraded`, `draining` and `unavailable`. Capabilities
have stable IDs, `supported`, `unavailable`, `unsupported` or `unknown` state, safe reason codes,
supported workflow names, configured bounds and (where applicable) harness contract version.
`supported` requires both an implemented route/service and satisfied runtime preflight. Configured
harness selection is not evidence that a session ran. Missing binaries/configuration produce
unavailable; unfinished built-in/ACP resume/permission/Git features remain unsupported or unknown.
Never enable controls from a fixture, environment variable name, endpoint guess or frontend flag.

Runtime information uses allowlisted implementation/version/platform names and effective limit
values. It excludes absolute installations/worktrees, environment values, credential-bearing
URLs, agent resume secrets and raw process command lines. The session response carries a CSRF
token for in-memory use only; authenticated bootstrap restores it after reload. Cookies/session
policy belong to #161. API credentials and Git
credentials never enter bootstrap, normal responses, browser storage, query parameters or logs.

## Event journal and presentation mapping

The transport-neutral [agent contract](agent-execution-contract.md) and
`AgentExecutionEvent` remain the event source for agent activity. The web adapter does not create
an alternate agent protocol. Within a run the server assigns a durable monotonic decimal
`sequence` and opaque `cursor`; it separately records `agentInvocationId` and the source
`agentSequence` because source sequences can restart for a new invocation. Persist event and
state transition together (or reconcile from a transactional outbox) before delivery.

| Shared source | Web event type | Presentation boundary |
| --- | --- | --- |
| `AgentMessageEvent` | `agent.message` | message ID, role, bounded text delta and completed flag |
| `AgentPlanEvent` | `agent.plan` | bounded plan snapshot with IDs/descriptions/statuses |
| `AgentToolEvent` | `agent.tool` | tool ID/title/status; allowlisted redacted details, artifact ID for bounded output |
| `AgentPermissionEvent` | `agent.permission` | recorded decision, request ID and safe explanation; not a new authorization grant |
| `AgentFileChangeEvent` | `agent.fileChange` | registered file ID plus reported digests/kind/size; unaccepted until validation |
| `AgentExecutionResult` / `AgentFailure` | `agent.stopped` / `agent.failed` | exact stop/failure classification and available usage; completion is not acceptance |
| Durable run service | `run.state`, `evidence.available` | persisted state/version or newly registered evidence reference |
| Web transport | `retention.gap`, `snapshot.required` | recovery control; never agent execution evidence |

The representative `agent.message`, `run.state`, `evidence.available` and `retention.gap` schemas
exercise the wrapper. Other event variants require exact payload schemas before #174 enables them.
Tool messages and model output are plain untrusted text, not executable markup or actions.
`#69` owns acquisition and faithful mapping of ACP plans/messages/tools/progress;
`#79` owns shared harness selection/evidence parity. D4 owns the durable web journal, cursors,
redaction, bounds and browser reconciliation. This division does not mark unfinished #69/#79
features complete or permit a web adapter to bypass their policies.

Use `GET R/snapshot` first. It returns run state/version, known revision/acceptance references,
and `throughCursor` at one consistent journal watermark. Connect to `R/events` after that cursor.
For persisted records, SSE `id` is the cursor, `event` is the event type, and `data` is the JSON event document. At-least-once
delivery permits duplicates and disconnects at any byte; the client applies an event only once
per cursor, preserves increasing sequence order and refetches on an unexplained discontinuity.
Events at or before the snapshot watermark cannot regress state. Terminal events are reconciled
against the authoritative run snapshot before displaying final acceptance.

Retain at most 10,000 events or 16 MiB per run, whichever bound is hit first, and by default expire
terminal-run event records after 24 hours. Durable run/revision/evidence records outlive event
retention. A cursor older than retention returns `410 EVENT_GAP` before stream headers, or a
`retention.gap` control event if eviction happens after connection, then closes. A gap is not a
journal entry: its cursor/sequence are null, it has no SSE `id`, and it cannot advance the client's
durable position. Polling reports the gap as `410`, not an entry in a persisted event page. Include
`requestedCursor`, `oldestCursor`, `latestCursor` and an actionable snapshot URL. A transport
gap never fabricates missing tool output. Re-read the snapshot, mark unavailable history, and
resume from its watermark. Invalid or foreign cursors return `400 INVALID_CURSOR`.

Send heartbeat comments at 15-second intervals with no state meaning. Reconnect after 30 seconds
without bytes, with jittered exponential delays from 1 to 30 seconds. After three failed stream
attempts, poll `R/events?transport=poll&after=...&limit=...`; poll every 2 seconds while active,
backing off to 30 seconds on repeated failures and honoring `Retry-After`. Polling uses the same
event records, cursors, gaps and snapshot reconciliation. Stop active polling after a terminal
snapshot; refresh on explicit user action or focus if stale. Session expiry stops reconnection
and asks for reauthentication without replaying work. Each tab may subscribe independently
within advertised limits; tabs exchange only non-secret invalidation hints and do not own run state.

## Evidence and revision adapters

The browser reads typed presentation views and opaque references; it never parses paths from an
HTML fragment or decides acceptance from an unversioned report. Every report adapter returns its
own `adapterVersion`, declared producer format/version, source artifact digest, job/run/revision
binding, `state`, completeness, provenance limitations and explicit acceptance state. States are
`available`, `partial`, `missing`, `unsupported`, `unknown`, `invalid` or `incompatible`.
Missing is a known absent report; unknown means the association/meaning cannot be established.
Partial means available observations cover less than the declared scope. None implies pass.

An exploration confidence score reports observed input/output breadth and active isolation,
never universal equivalence. A graph root is an initial snapshot, not an accepted repair.
For graph-backed revision acceptance, canonical accepted nodes, validation evidence, agent receipt binding and source
digest must agree before `acceptance: accepted`. Fixture/generated labels and test-only
publication cannot become release acceptance. On digest/schema/binding mismatch, return invalid
or incompatible and disable dependent actions; do not overwrite source evidence with a repaired
presentation record. `SourceTree.kt` also records module checkpoint acceptance and each file's
`acceptedImplementation`; these concern declared module implementation scope, not final source-tree
acceptance. Show them with their scope and source digest. The representative accepted `revision`
schema deliberately covers the graph-backed authority; another producer's publication authority
requires an explicit adapter/schema extension with equivalent source/evidence binding before it
can publish final acceptance. Derived counts, summaries and compatibility projections do not acquire the
authority of their inputs. Raw artifacts retain their immutable bytes and explicit content type;
sanitized derivatives have separate identity, digest and provenance.

| DTO fields | Authoritative current source or explicit implementation owner |
| --- | --- |
| `workflowCancel.action` | Constant caller intent only. The route selects job/run, If-Match selects the run version, and the shared authorized session supplies the actor. No body field chooses an actor, command or execution target. HTTP integration remains owned by #485. |
| `progressPin.jobId/runId/version/pinned` | Selected durable `WorkflowAttempt` for GET; atomic `WorkflowPinAuditEntry` original result for PUT/replay. No actor, key digest or receipt internals are public. |
| `job.jobId`, display filename, timestamps | `Jobs.kt: Job.id/filename/createdAt/updatedAt`; never expose `binaryPath` |
| `job.sizeBytes`, `binary.*` | `Job.sizeBytes` to decimal string; `ElfMetadata` names/format and unsigned `entryPoint` to hex. V1 must not reuse lossy/signed `Job.toJson()` numerics |
| `job.version/status/latestRunId/acceptedRevisionId` | #160 durable adapter/registry. Legacy `Job.status` is only historical workflow status; it cannot establish an attempt or acceptance |
| `run.*`, recovery parent, lifecycle timestamps/version/limits/terminal reason | #160/#163 attempt records; no such durable current `Job` fields. Shared stop/usage/failure portions map to `AgentExecutionResult`, `AgentUsage`, `AgentFailure` when present |
| `revision.sourceSha256/graphNodeId/parent/acceptance` | `ModuleRevisionNode.sourceRevisionSha256/id/parentId/status`, `ModuleRevisionGraphSnapshot.headId`; `revisionId`/job/run registration and verified evidence references added by #165/#199 |
| `artifact.*`, report binding/source artifact/adapter/state/limitations | #164/#165 immutable artifact registry and bounded adapters; source content from registered reports. Current `JobStore.resolveArtifact()` path is not a public identity or verified snapshot |
| Exploration `candidateCount/expandedOutputSignatures/confidence` | `AutomaticExploration.kt: ExplorationReport.toJson()`, `ConfidenceScore`, observations. Current format is unversioned; adapter must validate the recognized legacy shape and declare producer version null |
| Validation summary `result/casesCompared/sourceSha256` | #165 adapter derives scoped result/count from `BehaviorComparisonReport`; binds the canonical node's `sourceRevisionSha256`. These are new presentation names, not fields parsed from `RepairEvidence.summary` |
| `report.acceptance`, validation status | Existing canonical graph/validation strategy and receipt authority, exposed by #165. No inference from `Job.status == complete`, source-tree existence or a confidence threshold |
| Source file provenance/digest/module acceptance | `SourceTree.kt: GeneratedFileEvidence`/module checkpoints, project `source_tree_manifest.json` and exact registered source snapshot; #165 obtains byte sizes from that snapshot. Manifest is a compatibility projection after canonical repair publication, see [revision authority](repair-revision-graph.md) |
| `sourceCatalog.*` | Fixed selected-run manifest/input capture; host-profile-validated `GeneratedFileEvidence` metadata only. Manifest SHA-256 is an observation version; file IDs are scoped HMAC identities, labels are display text, flags/digests are unverified declarations, and revision binding is null |
| `revisionSources.*` | Actual selected `WorkflowAttempt.candidate` plus schema-3 build-contract source inputs, cross-checked against the host-profile-validated manifest and canonical build/repair digest preimage. Sizes are exact descriptor commitments; source bodies and acceptance are not verified by this listing |
| `revisionDirectory.*` | Immediate-child grouping of those same canonical input commitments. Counts describe recorded input files; empty physical directories are not recorded, and directory IDs are opaque selectors within the selected candidate |
| `revisionFile.*` | One exact committed input declaration and server-derived parent selector. `contentVerification: "not-performed"` explicitly excludes selected-file body verification by this metadata read |
| `sourceChunk.*` | Captured input bytes match the selected candidate's canonical path/size/digest commitment and configured host declaration. Range and line fields describe those exact bytes; compiler results, graph acceptance and release authority remain separate |
| Event `agentInvocationId/agentSequence/type/payload` | Shared `AgentExecutionEvent` variants above; #69 stream mapping; #174 durable publication and redaction |
| Event cursor/sequence/time/gap, snapshot watermark; page cursor/version | New #174 journal and #162 snapshot pagination metadata, not existing agent timestamps or `JobStore.list()` offsets |
| Bootstrap capability/harness descriptors | `selectWebReconstructionStrategy`, `AcpHarnessProvenance` safe fields; #166 performs real readiness checks. The selection report explicitly does not prove execution |
| Bootstrap builds/basePath/limits/readiness; session data; HTTP IDs/errors | #151–#159/#161/#166/#208 configuration/build/session/controller authority; never raw environment or exception serialization |
| `gitWorkspace.*`, refs/object IDs/guards/mappings; Git `operation.*` | New managed Git records and isolated adapter in #200–#215; current job and repair graph have no Git registry |
| Request workflow/harness/input revision/limits or Git selections/guards | Untrusted user intent decoded under the schema; services validate current capability, authorized IDs, version and quotas before making a durable record |

This inventory covers every representative DTO family, including nested envelope/page/reference
fields; entries marked with an issue are required new server authority, not placeholders returned
as if established facts. Collection-specific fields added by implementation must extend this table.

## Git object and revision binding

The managed repository stores `repositoryId`, object format, opaque version and source-only policy.
A worktree stores `worktreeId`, registered repository, source candidate revision, HEAD object/ref
and its own version. Git object IDs are full lowercase hexadecimal opaque strings accompanied by
`objectFormat` (`sha1`, `sha256` or unknown); do not assume 40 characters, convert them to numbers,
or accept a display abbreviation for mutation. Ref names are display/input text under a validated
ref record, never filesystem or URL authority. Paths in diffs are registered source file identities
with escaped display names; shell fragments and command strings are not API requests.

Status/diff snapshots carry repository/worktree versions plus observed HEAD/ref object IDs.
Commit, stage, branch changes, integration and push require those versions and expected object
IDs under the same repository/worktree lock as execution. A changed ref or dirty source snapshot
requires `409 REF_CHANGED`/`WORKTREE_BUSY`, with a fresh review; no implicit overwrite/stash/reset.
Push names the remote/ref registration, exact local object and reviewed expected remote object
(`null` means expected absent). The server rechecks remote state and enforces the expected value
at the remote ref-update boundary; no unchecked force update. Automatic fetch, background push,
hook/filter/helper execution and implicit PR publication are outside navigation/read semantics.

A provenance mapping records `(repositoryId, objectId, revisionId, sourceSha256, archiveArtifactId)`
and separately the canonical acceptance evidence reference/state. Validate source digests against
the exact commit tree, then validate archive identity against those source bytes. A commit/tag is
not validation or acceptance. Imported commits, resolved conflicts and changed working trees are
new candidates and return through existing validation before becoming accepted revisions. A Git
operation records intent, guards, stage/outcome, safe diagnostics and recovery requirements. A
restart never silently repeats a remote write; reconcile the exact refs and durable intent before
offering an explicit recovery action. Credentials and raw transport diagnostics stay server-side.

## Legacy compatibility

`GET /api/jobs/{id}` and JSON-requested POST `/jobs` success responses use an explicit
public projection: `id`, `filename`, `status`, `created_at`, `updated_at`, `size_bytes` and
`metadata`. The former persistence-derived `binary_path` and optional `status_message` fields
are removed for privacy: stored diagnostic text can contain host paths, environment values or
raw exceptions, including records predating redaction. No placeholder diagnostic is invented.
ELF metadata keeps its existing field names and numeric types, including signed/numeric
`entry_point`; its five categorical strings must exactly match `ElfMetadataReader` output,
otherwise the historical job is unavailable with a fixed diagnostic. This legacy shape is not
a v1 DTO. Execution POSTs still redirect.
The persistence serializer and stored `job.json` format are unchanged.
The HTTP regression in `UploadServerTest` checks both responses, an old private diagnostic,
exact public keys, retained field values and byte-for-byte preservation of stored records.
Legacy job HTML also withholds persisted `status_message` prose and displays a fixed
explanation when details exist. The job status itself remains visible. Generic request/storage
exceptions and unsupported-upload exceptions no longer supply raw text to HTML error pages;
those paths use fixed public messages. Service/storage codes are allowlisted and select fixed
messages; unknown code text collapses to `JOB_STORAGE_UNAVAILABLE` rather than being copied.
This leaves stored diagnostic bytes and background redaction behavior unchanged. It is a
privacy change for DTO diagnostics, not a certification of report/source/artifact content.

Legacy `/api/*` failures always return JSON, including unknown routes. POST `/jobs`
returns JSON failures when the existing Accept switch selects `application/json`; HTML form
requests retain HTML errors. The legacy error envelope is `{requestId, error: {code, message}}`,
with the same opaque UUID in `X-Request-ID`, `Cache-Control: no-store` and a JSON content type.
It is separate from the v1 envelope. Messages are fixed public text and never copy request
paths, query strings, uploaded filenames, persisted diagnostics or exception messages.

| Legacy failure | Status | Code |
| --- | --- | --- |
| Unknown API route | 404 | `NOT_FOUND` |
| Unsupported method on a known legacy JSON read route | 405 | `METHOD_NOT_ALLOWED` |
| JSON excluded by Accept | 406 | `NOT_ACCEPTABLE` |
| Repeated or oversized Accept header | 400 | `INVALID_HEADER` |
| Missing job / attempt | 404 | `JOB_NOT_FOUND` / `RUN_NOT_FOUND` |
| Unavailable or damaged service storage | 503 | `JOB_STORAGE_UNAVAILABLE` |
| Missing, unreadable, malformed or oversized progress journal | 503 | `PROGRESS_UNAVAILABLE` |
| Invalid request arguments | 400 | `INVALID_REQUEST` |
| Unsupported uploaded ELF | 400 | `INVALID_UPLOAD` |
| Unexpected exception | 500 | `INTERNAL_ERROR` |

Legacy event reads and v1 progress reads now use the same fixed-path service operation,
which validates job/attempt ownership and applies the retained-descriptor artifact reader's
2 MiB ceiling. Legacy event reads no longer fabricate a zero-event snapshot when the journal
is missing. Malformed and oversized journals also return `PROGRESS_UNAVAILABLE`; an actual
persisted, valid zero-event journal still returns 200. Legacy event reads require the shared
local session policy, including revocation, before this service read; this is the same
LocalWebAccess boundary used by the versioned controller. The legacy payload still adds no
cursor replay or new event authority.

Legacy successful event JSON and initial HTML now share a closed metadata projection.
Raw `text`, plan `entries`, `path` and unknown fields are withheld. Message prose is withheld
for every role, including assistant and unknown roles, because the journal does not certify
public visibility. Existing supported scalar event metadata and numeric representations remain;
nested values and oversized labels are omitted. A positive `presentationOmittedFields` count
at the snapshot/event level reports excluded fields without disclosing names or values. A removed
`text` field sets `textOmitted: true`. These presentation counts are separate from journal queue
and retention drops; events, sequence positions and durable journal bytes are not removed.
The legacy view labels the visibility restriction and omitted fields, including during polling.
This projection does not certify every retained label as public. The v1 producer also withholds
`text`, `entries` and `path`, using its existing `omittedFieldCount` and `textOmitted` fields;
the SPA retains its activity-view restriction as well. See [the transport projection](web-progress-adapter.md#public-transport-projection).

The HTTP tests cover missing/unknown resources, invalid query/upload, damaged storage,
request-ID agreement, content type, cache policy and preservation of stored bytes. Unexpected
internal failures use the same response helper but are not fault-injected by that HTTP test.
The two legacy JSON read routes (`/api/jobs/J` and `/api/jobs/J/events`) accept GET and HEAD.
Other methods return 405 with `Allow: GET, HEAD` before storage reads. HEAD returns the same
status and content headers as GET without a response body. Unknown routes retain 404.
Both methods share v1's bounded Accept policy:
a missing header allows JSON; explicit JSON, `application/*` and `*/*` ranges are supported;
a more specific `q=0` exclusion overrides a broader wildcard. Nonmatching/malformed supported
ranges yield 406. Repeated Accept headers or a value over 512 characters yield 400. Errors
remain JSON even when the client excludes JSON. All these responses use no-store caching.
HTTP tests cover both route shapes, positive/negative media ranges, methods including HEAD,
header limits and unchanged records, including negotiation before damaged storage inspection.
The legacy upload now negotiates its two existing representations before reading the body:
explicitly admitted JSON (or `application/*` when HTML is not admitted) selects JSON, while an
absent or `*/*` Accept retains the HTML form flow. A more-specific JSON `q=0` exclusion falls back
to HTML when admitted; a request admitting neither representation returns 406. Repeated or
oversized Accept values return 400. Its multipart Content-Type and session boundary remain in
force. Full mutation-route migration and deprecation/successor links remain separate work.

D2/D13 preserve the non-sensitive legacy success fields through the first D-series release and
at least one subsequent minor release, while documenting removal of `binary_path`, applying the
same session/content boundary and making API failures JSON. Do not silently change old numeric
fields to strings; clients needing lossless values migrate to v1. Expose deprecation and successor
links and publish the actual sunset release/date before removal. The legacy-mode server does not
currently expose v1 job routes, so no successor link or sunset date is advertised prematurely.
Existing persisted `job.json`
files stay readable through a versioned, recoverable migration; public response changes do not
rewrite raw report bytes. Legacy URLs redirect/map per the navigation/parity contract and never
auto-start a workflow. Unsupported legacy automation dependencies receive a documented migration
error, not an empty success response.

The optional upload progress transport, state semantics and bounded retention are defined
in [Server-observed upload progress](web-upload-progress.md). Progress identities are
fresh per transfer and do not replace durable idempotency keys.

### Current D4 JSON polling implementation

The current retained-journal adapter implements `GET jobs/J/runs/R/snapshot`
and `GET jobs/J/runs/R/events?transport=poll&after=...&limit=...` under the v1 prefix.
The activity client uses this target polling spelling. The existing `cursor` parameter
remains an alias for `after`; specifying both, duplicates, unknown fields or a transport
other than `poll` is rejected. Omitting transport retains JSON polling compatibility.
`Last-Event-ID` is rejected on polling rather than silently losing its resume position.
Activity catches up a bounded polling page, then follows SSE with bounded reconnect and polling fallback. An explicit positive `Accept: text/event-stream`
on the same endpoint now selects SSE when `transport=poll` is absent. Snapshot `progress` metadata
makes queue/history omissions and retained-record counts explicit. Missing
journals fail with `PROGRESS_UNAVAILABLE`; replay gaps require a fresh snapshot
via `EVENT_GAP` with typed recovery metadata. See [the implemented boundary and qualification limits](web-progress-adapter.md).

### Current scheduler snapshot

Authenticated bootstrap responses now include optional `runtime.scheduler` for
aggregate web workflow executor telemetry: approximate active/queued counts,
configured limits, lifecycle, source and server sample time. Borrowed executors
report unavailable metrics without zero values. Runtime uses the session-time
snapshot; it neither polls these counts nor infers workflow availability from
capacity. See [scheduler summary and verification](web-scheduler-summary.md).

## Current source catalog metadata

`GET /api/v1/jobs/{jobId}/runs/{runId}/source-catalog` requires the existing private
session and an exact durable attempt belonging to that job. It accepts only `limit`
(default 50, maximum 200) and `cursor`. It returns a flat, deterministic path-sorted
metadata page with opaque session/job/run/manifest-bound `fileId` values. `displayName`
is a portable relative display label; no endpoint accepts it as a filesystem selector.
`nextCursor` explicitly identifies more records, including when the response byte
ceiling admits fewer rows than the requested limit. A cursor from another session,
job, run or page size is rejected. A changed manifest expires a valid continuation
with `410 CURSOR_EXPIRED` and requires refreshing the first page.

The producer captures only the fixed source manifest and uploaded input through the
retained-descriptor read boundary, then rechecks their bytes, hashes and identities.
The manifest must use the same configured host profile allowlist as legacy source
evidence and bind to the uploaded input. Both readers receive one captured copy of
the server's configuration; the catalog does not restore excluded default profiles.
Metadata capture admits at most 25,000 files and a 16 MiB manifest; response items
have a separate 1,000,000-byte ceiling within the existing 1 MiB JSON response limit.
One catalog capture/page is admitted per controller at a time; concurrent catalog
reads receive `429 SOURCE_CATALOG_BUSY`. Each filesystem read retains the service's
lifecycle check and read lock, while manifest parsing runs outside the global job
lock. Admission is released on both success and failure. There is no retained
catalog cache, directory traversal or manifest-declared source file read. Missing,
malformed, unregistered or oversized metadata returns a fixed unavailable response;
changed capture or attempt identity returns a conflict without a partial page.

The `sourceCatalog` contract has `authority: "manifest-metadata"` and a null
`binding.revisionId`. `manifestSha256`/`page.snapshotVersion` identify the observed
manifest bytes. File hashes and the `declaredUtf8Text`/`declaredViewable` flags are
manifest declarations; this read does not verify source bodies, text encoding or
acceptance. It creates no immutable project revision or release relationship.
The planned revision-scoped source routes above remain separate work. Bootstrap's
source chunk limit remains zero until a source text producer is implemented.

In-memory controls exercise the 25,000-record capture/page workload, scoped cursor
refusal, byte-limited continuation and changed capture refusal. They do not qualify
HTTP/controller behavior, the source tree UI, 8 MiB source delivery, the 256 KiB line,
latency or memory budgets. Those remaining obligations stay open under #490/#188/#189.

## Candidate revision source input listings

`GET`/`HEAD /api/v1/jobs/{jobId}/runs/{runId}/revisions/{revisionId}/sources`
uses the private session boundary and accepts only `limit` and `cursor`. The selected
terminal attempt must contain that actual persisted candidate reference. The reader
never creates a revision ID from a manifest digest. Conflicting reuse of a revision
ID with a different source digest in another retained attempt returns a conflict.
Other attempts containing the same revision/digest retain their explicit run namespace.

The common metadata capture reads the fixed manifest, uploaded input and
`source-tree/reports/build_contract.json` through the retained-descriptor boundary.
Only build-contract schema 3 is supported. Its unique, sorted `sourceInputs`
must exactly match the manifest's host-declared `BUILD_INPUT` paths and file digests,
include a build definition, and reproduce the persisted candidate's source digest
using the existing `path.length:path:byteLength:fileSha256` plus newline preimage.
The build and repair producers use UTF-16 path length and exact decimal byte counts;
wire `sizeBytes` values remain decimal strings. The reader does not use the legacy
job-record digest as an ELF content digest. Manifest, descriptor and uploaded input
are rechecked, followed by the selected candidate/version and revision conflict checks.

Both metadata producers share one capture admission in the service. Parsing runs
outside the global job monitor; each read unit still checks service lifecycle and
namespace ownership. Each metadata document has a 16 MiB ceiling and the manifest
and canonical input set admit at most 25,000 records. Pages default to 50, admit at
most 200 rows and retain the separate 1,000,000-byte item ceiling. Signed continuations
bind the session, job, run, revision, page size and captured metadata version. A changed
version expires the cursor explicitly. No page cache or source body is retained.

`revisionSources` has non-null job/run/revision bindings and
`authority: "source-input-commitments"`. `sourceSha256` is the persisted canonical
commitment; `metadataVersion` identifies the observed manifest/descriptor pair.
File IDs are stable opaque values across sessions and listener restarts for the same
job/run/revision/source input set. They grant no access without the session boundary.
Display labels never become filesystem selectors. Viewability/encoding flags remain
host-profile declarations. This projection reports no compiler result, canonical graph
acceptance or release relationship, including when the stored attempt has an accepted
reference. Missing registration returns 404; inconsistent capture returns 409; missing,
malformed, unsupported or oversized metadata has a fixed unavailable response.

This endpoint lists only the canonical build input set. The observed catalog above
continues to describe other manifest entries. Reads outside that committed input set,
UI/HTTP/performance qualification and accepted publication remain open;
bootstrap source chunk advertising stays zero. In-memory controls cover canonical
identity, conflicts, exact large sizes/Unicode, 25,000 commitments, paging and capture
admission. They do not establish the D0 physical source workload or delivery budgets.

### Lazy canonical input directories

`GET`/`HEAD jobs/J/runs/R/revisions/V/source-directories/root` returns a
`revisionDirectory` envelope through the same private read and metadata capture boundaries.
Only `limit` and `cursor` are accepted, with the same default 50, maximum 200 and
sub-MiB response ceiling. Each page groups immediate children of the selected prefix;
directories sort first, then files, each in UTF-16 label order. Selecting a directory
does not recursively fetch its children. Counts include only canonical input files.
`emptyDirectories: "not-recorded"` explicitly describes the file-only inventory;
an unknown directory returns `SOURCE_DIRECTORY_NOT_FOUND`, without asserting physical
absence. File/directory prefix collisions return a source revision conflict.

Directory IDs bind the job, run, revision, source commitment and canonical prefix.
They remain stable across sessions and listener restarts for that input set. File IDs
are identical to those in the flat revision source listing. Display labels are single
components and never become path selectors. A continuation also binds its directory
and page size; session mismatch is invalid, and changed metadata expires it explicitly.

The root has a null display label and parent. Other directories include a parent ID,
depth and breadcrumbs. Breadcrumbs retain the root and at most the last 31 components;
`omittedAncestors` counts intervening components. Parent IDs retain the complete
upward navigation chain even when breadcrumbs are shortened. Shared consumers reject
inconsistent ancestry, counts, duplicate identities, ordering and continuation bounds.
Pure captured-DTO controls cover 25,000 wide directories, deep Unicode/space paths,
stable IDs and cursor isolation. These controls do not qualify physical source reads,
HTTP/browser navigation, empty directory support, timing, memory or the full D0 workload.

### Bounded canonical input source reads

The `source-files/F/chunk` and `source-files/F/content` routes bind `F` to the same
opaque file ID returned by the revision input and directory listings. The private
GET/HEAD policy applies before capture. A display label or client path never selects
the source file. Preview requires the configured `VIEWABLE` role; complete download
requires `ARCHIVE_PAYLOAD`. Missing permission returns a fixed representation refusal.
These declarations are checked independently of a file's name or extension.

The reader holds the shared source capture admission through metadata and body reads.
It selects only the exact job/run `source-tree` namespace, using the existing pinned
regular-file descriptor reader and its ancestry/identity revalidation. Source project
paths use the host's normalized grammar, including deep paths; the generic report
artifact reader retains its separate limits. At most 8 MiB is captured for one input.
The byte count and actual SHA-256 must match the selected commitment. A second body
capture must match bytes and identity, followed by descriptor, manifest, input and
persisted candidate/version rechecks. No path, stream or mutable cached source body
is handed to a later request. Missing/unreadable data has an unavailable response;
changed observed data returns a conflict. This is captured-byte verification, not an
immutable archival registry or accepted graph publication.

Chunk queries accept canonical decimal `offset` (default 0), `maxBytes` (default
65,536; 4–131,072) and optional `metadataVersion`. Unknown/repeated keys are rejected
before capture. A changed requested metadata version expires explicitly. A UTF-8
offset must be at a character boundary; out-of-file or split-character offsets return
416. The emitted end is shortened when necessary to preserve a complete character.
Empty files have one empty complete representation; nonempty files reject an EOF-only
range. `offsetBytes`, `lengthBytes`, `sizeBytes` and `nextOffsetBytes` are exact decimal
strings. `completeFile` is true only for a response containing the entire original file.
Clients must retain the binding, file/source digests and metadata version when joining
ranges; a final range alone is not a complete-file copy.

Declared UTF-8 is validated without retaining a decoded whole-file string. Valid text
with lines at most 256 KiB before LF is returned unchanged as `representation: "utf8"`.
The line byte ceiling includes a CR before LF. CRLF, BOM, Unicode and markup-like text
are preserved. `firstLine` counts LF bytes before the offset plus one; `startsMidLine`
and `endsMidLine` explicitly describe partial lines, with EOF ending the final line.
This JSON text grants no HTML/Markdown execution or remote highlighting authority.
Declared binary content, malformed UTF-8 and overlong lines select `hex`, with a fixed
fallback reason and two lowercase digits per original byte. Text line fields are null
for hex. Both representations keep the response below 1 MiB and expose the complete
byte range and continuation explicitly. Shared consumers reject inconsistent byte
lengths, completeness, continuations and line metadata, including malformed surrogates.

The `content` route accepts no query and returns the complete verified bytes as a
no-store, nosniff `application/octet-stream` attachment. The ASCII fallback filename
and encoded UTF-8 basename cannot insert header syntax; the response also carries a
sandbox/default-deny CSP. HEAD verifies the same captured file and returns its length
without a body. Range and conditional HTTP headers are explicitly unsupported on both
routes; bounded JSON offsets provide the chunk operation.

Each chunk currently verifies a complete bounded file before returning its range.
No timing, RSS, physical deep-path or actual HTTP/browser qualification is inferred
from captured-byte controls. The general viewer, all-manifest/log/report families,
direct UI line links, copying UX, local highlighting and full D0 physical budgets
remain open. Bootstrap source chunk advertising remains zero pending those gates.

## SPA recorded source navigation

The attempt page links a recorded result revision to
`jobs/J/runs/R/revisions/V/sources/root`. Directory links retain that exact selection
and an opaque directory ID; file links use
`jobs/J/runs/R/revisions/V/source-files/F`. The embedded shell admits these exact
GET/HEAD document routes and keeps its existing trailing-slash redirect policy.
The source API still verifies an actual retained candidate; a displayed result
reference alone does not establish source availability or accepted publication.

Each directory view requests one 50-entry metadata page. Expanding a directory or
opening the next page is explicit navigation; no recursive walk, body request or
download runs in the background. A continuation lives in the documented `cursor`
query so back/forward can restore the page within its valid session/snapshot.
Changed/expired continuations require first-page refresh. The rendered list contains
only the selected page, with an explicit count and next-page state. Breadcrumbs use
server selectors and show omitted ancestors; parent navigation retains the complete
chain. All display labels are escaped text with bidi isolation, separate from URLs.

Direct file links read `revisionFile` metadata through the same private bounded
transport. That endpoint accepts no query, resolves the opaque file ID, and returns
the recorded relative label, exact size/digest, host encoding/view/archive flags,
binding, metadata version and opaque parent ID. It neither requires body permissions
to explain an excluded entry nor requests the selected file's body. The UI labels
these as commitments, explains unsupported preview/download declarations and the
8 MiB reader limit, and offers an explicit authorized attachment link when applicable.
Bootstrap source-chunk advertising stays zero; the UI does not enable text reads
under that report. Text/hex preview, line links and copying remain separate viewer work.

Source reads clear the previous selection before a different request can render,
check job/run/revision/resource bindings, abort on navigation/session replacement,
and withhold late callback results even if cancellation is ignored. Directory
continuations also retain the observed source/metadata identity across loaded pages.
Failures use fixed recovery copy plus a canonical reference ID, never raw diagnostics.
Authenticated state owns the views; expiry or logout removes their private metadata.

Pure DTO/path/callback controls cover these bindings, page bounds, opaque URLs,
obsolete reads and role/size/runtime explanations. They do not qualify actual source
HTTP/browser navigation, keyboard/layout behavior, physical deep paths, all generated
manifest/log/report families or D0 timing/memory/workload budgets. Those requirements
and the original parent acceptance criteria remain open.

## Legacy session migration

Legacy pages, JSON routes and downloads now require the local session described in
`web-trust.md`. Use the CLI's `/login#bootstrap=…` handoff or exchange its token via
`POST /api/v1/session` with exact Origin and JSON content type. The response supplies the
session cookie and in-memory CSRF token. Legacy-only `GET /api/v1/session/csrf` restores the
same `session` envelope under the cookie on reload. It rejects query parameters, negotiates
JSON and is no-store. `DELETE /api/v1/session` requires cookie, exact Origin and CSRF.

Legacy upload/explore/reconstruct requests require `X-CSRF-Token` and the session cookie in
addition to exact Origin. Upload is multipart; explore/reconstruct are JSON POSTs. Browser
forms supply these through their session adapter. There is no automatic mutation retry.
This supersedes earlier descriptions of unauthenticated legacy routes; it does not change
their existing unversioned job/event payloads or add durable workflow capabilities.

## Current retained-journal SSE transport

An explicit `Accept: text/event-stream` selects SSE on `GET jobs/J/runs/R/events`.
Resume with one of `Last-Event-ID`, `after` or the retained `cursor` alias; mixed positions
are rejected. The response uses the same observational event documents and signed cursors
as polling: `id` is the cursor, `event` is `workflow.observation`, and `data` is the JSON
event. No cookie/CSRF/access credential appears in the URL. Wildcard/default requests remain
JSON, and explicit `transport=poll` continues to require an acceptable JSON response type.

The server authorizes before admission, each checked journal read and every frame/heartbeat.
Streams run outside the HTTP/workflow executors with at most 16 reservations globally and
two per session. There is no per-client event queue; each replay page retains its existing
200-record/sub-MiB ceiling. Connections have 30-second leases and heartbeat comments every
15 seconds. A disconnected idle client is detected on a write or at the lease deadline;
connection termination does not change workflow state. Admission failures use 429 and
Retry-After; clients can keep using bounded polling.

Before headers, polling and SSE return 410 `EVENT_GAP`. Its `error.recovery` contains the selected
jobId/runId, requestedCursor (nullable for an unanchored request), oldestCursor/latestCursor
(oldest null for empty retention; latest may carry an omission watermark) and a deployment-bound snapshotHref. These cursors describe
the same retained bytes that detected the gap. Recovery requires a fresh snapshot, not blind retry. After headers, loss of a non-null acknowledged
cursor produces a `retention.gap` control event with no SSE id, null cursor/sequence and
requested/oldest/latest positions plus snapshotHref, then closes. A missing journal, lost
session or other post-header failure closes the transport; it is not a workflow verdict.
If no cursor has ever existed, the connection closes and the subsequent initial request
reports the gap rather than inventing an anchor.

Activity uses SSE after bounded polling catch-up, with bounded reconnect and polling fallback.
Run state now stays locked during bounded journal capture, with locks released before HTTP delivery.
Controlled authenticated HTTP snapshot/replay and SSE eviction/resume checks now cover concurrent
cutover. Slow-socket qualification and timed retention remain outstanding under #174.

## Implemented progress-pin policy endpoint

`GET` and `PUT /api/v1/jobs/{jobId}/runs/{runId}/progress-pin` are available under the configured deployment prefix. This pin protects only the selected persisted progress journal. It does not pin the full job, source revisions, reports or downloaded evidence. Unpinning neither resets the retention deadline nor restores removed history; SPA periodic progress maintenance is enabled by default; legacy mode keeps it disabled.

GET requires a local session and returns `{jobId, runId, version, pinned}` in a `progressPin` envelope, with an ETag for the current run version and `Cache-Control: no-store`. Conditional read headers are rejected. The `progressPinRequest` wire body for PUT is exactly `{pinned: boolean}`, at most 1024 bytes, with duplicate JSON keys and unknown fields rejected. Authorization precedes body parsing. PUT requires the existing same-origin JSON mutation policy, cookie session, CSRF token, one strong If-Match version and one 16–128 character idempotency key. Caller-supplied actors, query parameters and extra conditional headers are rejected.

Successful changes and no-ops use the durable receipts described in [pin audit/replay](web-pin-audit.md). An exact replay returns the original pin/version and ETag with `Idempotency-Replayed: true`; it may describe an earlier result than a subsequent GET. It never rolls current policy or an owned task backward. Reconcile with GET before a new action. Missing If-Match returns 428, stale fresh requests 412 VERSION_CONFLICT, reused keys with different intent 409 IDEMPOTENCY_CONFLICT, and protected receipt capacity 429 PIN_RECEIPT_CAPACITY. Uncertain publication returns an unavailable/recovery response, not success.

The generated `progressPin`/`progressPinRequest` contracts and the client's guarded `put` method support this endpoint. The client performs one request without automatically retrying ambiguous mutations. The authenticated attempt page now provides explicit read/pin/unpin controls with fresh-read reconciliation. Audit presentation and denied/failed-request audit coverage remain unfinished; successful policy receipts alone do not complete #177.

Private bootstrap now includes an optional `runtime.progressRetention` sample with enabled configuration, sample time, completed attempt checks, expired journals, failed checks and the last diagnostic code. Runtime displays this process-local sample from the last session check without launching another probe. The SPA `terminalEventRetentionMs` value is 86400000: the threshold for timed expiry, not a guarantee against earlier size/count eviction or a maximum scan delay. See [production retention](web-progress-adapter.md#spa-production-retention-and-sampled-status).
