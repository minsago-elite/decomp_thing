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
| `GET /agent/preflight` | `200 agentPreflight` | Last explicit agent inspection result; never starts the agent; #493 |
| `POST /agent/preflight` | `202 agentPreflight`, `409` while one runs | Strict `agentPreflightRequest` (`{"action":"inspect"}`), session/Origin/CSRF; starts one single-flight `preflight(WEB)`; #493 |
| `POST J/runs` | `202 run`, `Location: R` | `workflowStart` request, capability/limits/input checks, job If-Match; #163 |
| `POST R/cancel` | `202 run` or `200 run` if already terminal | Closed `workflowCancel` request, idempotent recorded intent, run If-Match; #163 |
| `POST R/recover` | `202 run`, `Location` of a new attempt | Closed `recover` request; explicit `retry` or capability-gated `resume`; run If-Match and idempotency; #486 |
| `GET R/controls` | `200 attemptControls`, strong run ETag | Read-only cancel/retry/resume eligibility with closed reasons; reserves nothing; #528/#529 |
| `GET R/snapshot` | `200 snapshot`, ETag | Run state and consistent event watermark; #174 |
| `GET R/queue-position` | `200 queuePosition` | Approximate sampled position of one queued attempt; no query, counts only; #530 |
| `GET R/events` | `200 text/event-stream` | Resume with `Last-Event-ID` or `after`, never both; #174 |
| `GET R/events?transport=poll` | `200 events` | Same retention/cursor semantics, bounded page; #174 |
| `GET R/reports/{reportId}` | `200 report` | State may be missing/partial/unsupported/unknown; #165 |
| `GET R/source-catalog` | `200 sourceCatalog` | Bounded flat manifest metadata; selected durable job/run; #490 |
| `GET`, `HEAD R/reports/revision-validation` | `200 report` | Explicit graph and evidence-owner selection; checked normal summary and bounded case pages; #489, #543 |
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
| `GET J/repositories` | `200 gitRepositories` | Capability-gated repository summary and latest 20 operations; implemented by #201 |
| `GET G`, `GET G/worktrees/{worktreeId}` | `200 gitWorkspace` | Capability-gated repository/worktree registry; implemented by #201 and #204 |
| `GET G/{status,history,diff,refs}` | `200 gitStatus`, `gitHistory`, `gitDiff`, `gitRefs` | Bounded, anchored pages; full object IDs; opaque file IDs; implemented by #202 |
| `GET G/worktrees` | `200 gitWorktrees` | Primary and linked work trees with owner and HEAD; implemented by #204 |
| `GET G/provenance/{objectId}`, `GET G/exports/{objectId}` | `200 gitProvenance`, `200 application/zip` | Exact-object provenance envelope and deterministic tree export; implemented by #205 |
| `GET G/{remotes,conflicts}` | Bounded typed Git read | Scoped worktree/ref/object IDs; #207/#210/#211 |
| `POST J/repositories` | `202 operation` | Strict `gitRepositoryInit`/`gitRepositoryAttach`, session/Origin/CSRF, job If-Match and idempotency; init/attach implemented by #201, clone #209 |
| `POST G/operations` | `202 operation` | Named action, selected file IDs, full guards, work-tree If-Match, idempotency; stage/unstage/commit by #203, branch/switch/worktree by #204, tag by #205, others #207–#212 |
| `GET G/operations/{operationId}` | `200 operation` | Durable outcome/recovery state; init/attach operations implemented by #201, others #209 |
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

The recovery transport accepts only the closed `recover` data object (not its
fixture wrapper), bounded to 1024 bytes: `mode` is `retry` or `resume`, and
`expectedInputRevisionId` is the predecessor's recorded input revision or null for
the original upload. It uses the same shared session/Origin/JSON/CSRF boundary
before any body or service read, one strong run `If-Match`, one 16–128 character
`Idempotency-Key` and no query or other conditional header. Workflow, limits,
harness, checkpoint and paths are never caller fields; they come from the
trusted registration and the predecessor attempt.

Only the latest unsuccessful (failed, cancelled or interrupted) attempt can be
recovered, and only while its recorded input is the original upload or the
job's current accepted revision. A different expected input is 409
`INPUT_REVISION_CONFLICT`; an input that is no longer trusted evidence is 409
`INPUT_UNVERIFIED`, so recovery never silently starts from an unverified
workspace. `retry` always publishes a new queued attempt linked through
`previousRunId`, with `recovery.mode: retry` and no restored state. `resume`
requires the registered adapter's trusted checkpoint policy, the exact recorded
harness identity and a verified checkpoint; the new attempt records
`recovery.restores` (`agent-session` or `project-evidence`) and the checkpoint
digest, and the adapter receives the predecessor's workflow-owned report
directory. Unsupported or unsafe resume is 409 with a specific code
(`RESUME_UNSUPPORTED`, `HARNESS_CHANGED`, `CHECKPOINT_MISSING`,
`CHECKPOINT_MISMATCH`, `CHECKPOINT_UNVERIFIED`, `WORKSPACE_UNVERIFIED`,
`SESSION_QUARANTINED`, `CLEANUP_UNVERIFIED`). A newer attempt is 409
`ATTEMPT_SUPERSEDED`, unfinished or completed predecessors 409
`ATTEMPT_ACTIVE`/`ATTEMPT_COMPLETED`, a stale run guard 412, a key reused for
different intent 409, admission capacity 429 and an unavailable workflow 503.

Success is `202 run` for the new attempt with its `Location` and ETag. The
recovery receipt shares the atomic attempt publication; its replay identity is
the predecessor, its version, the mode and the expected input, so a keyed replay
returns the same new attempt with `Idempotency-Replayed: true` before any
eligibility, capacity or capability check, and never schedules again. Without
registered workflows or retained keyed receipts the route answers 503
`CAPABILITY_UNAVAILABLE` without reading the body. Production adapters remain
unregistered and none declares a checkpoint policy yet, so packaged builds
report retry and resume unavailable; ACP session continuation through the
shared `AgentSessionJournal` policy still needs a registered adapter (#68).

`GET R/controls` returns `attemptControls`: the run version and state, the
recorded input revision, `cancel`, `retry` and `resume` each with `available`
and a closed `reason`, the scope a resume would restore and any linked
`successorRunId`. It is computed from durable state and current owned work, is
private and read-only, and is not a reservation; each command re-checks its
guards. Browsers read it explicitly and never send a command on load or reload.

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

### Admission and overload

The server admits at most 16 concurrent requests, with 64 more waiting in a bounded queue. A request that finds
every worker and queue slot taken is answered immediately, without routing, session lookup or storage access, with
`429` and the fixed error code `SERVER_BUSY` (`retryable: true`, `retryAfterMs: "30000"`, `Retry-After: 30`,
`Cache-Control: no-store`, `Connection: close`), in the same error envelope as every other denial. The 30-second guidance
matches the longest ordinary request deadline, after which a slow request releases its worker. A small responder
pool (two threads, no queue) produces these answers, so overload never buffers more than the main queue holds. If
that responder pool is also busy, the connection is closed without a response; clients should treat a reset
connection like `SERVER_BUSY`. Each admitted request's exchange is closed at a 30-second deadline (120 seconds for
multipart uploads); the release of a worker pinned by a slow client at that deadline is not yet covered by a test.

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

The job's workflow availability view displays the contract version and execution
limits in that last authenticated capability report. Wall-clock and idle limits
retain their exact decimal millisecond values; output bytes and tool-call counts
also retain every decimal digit, including values above JavaScript's exact integer
range. Missing metadata is labelled not reported. A reported zero stays zero;
the view assigns it no unlimited or unsupported meaning. Reports without an
assigned workflow stay in the general capability section.

These are report-level observations, separate from an individual attempt's
recorded limits and job-specific admission. Displaying them performs no new
request, preflight, provider selection or workflow action. Implementation-version,
deprecation, selection and full workflow qualification requirements remain open.

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
The adapter's `statusDigest` is only a display-status fingerprint of bounded porcelain output and
HEAD, not either version, a content digest or an optimistic-concurrency/provenance guard. Further
edits to an already-untracked or modified file, non-HEAD ref changes and edits beyond the output
bound may leave it unchanged. Mutation services must separately bind a content-sensitive snapshot
and revalidate it under their execution lock; truncated display status cannot establish that guard.
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

### Managed repository identity mapping

Each identity below has one owner, and relationships are recorded, never inferred from equal
bytes, names or timestamps (#568). The server stores Git records under the job's private
storage. Paths never appear in a DTO.

| Relationship | Recorded by | Meaning and limits |
| --- | --- | --- |
| job → repository | Repository registration (`jobId`, `repositoryId`) | One managed repository per job source workspace, created only by an explicit init or attach operation |
| repository → worktree | Registration (`worktreeId`) | One registered work tree; neither branch name nor directory is its identity |
| worktree → run attempt, source revision | Registration (`runId`, `candidateRevisionId`) | The candidate snapshot the work tree was materialized from; `null` for an imported history |
| source revision → Git object ID | `gitMapping` | Created only by an explicit commit after the commit tree is checked against the revision's source bytes |
| Git object ID → archive digest | `gitMapping.sourceSha256`, `archiveArtifactId` | The archive is verified against the same source bytes, never against the object ID |
| revision → acceptance | `gitMapping.acceptance`, `acceptanceArtifactId` | Copied from canonical validation evidence only |

Object IDs are opaque lowercase hexadecimal strings whose length comes from the repository's
observed `objectFormat` (`git rev-parse --show-object-format`): 40 for SHA-1, 64 for SHA-256.
Unknown formats are readable but cannot be used for writes. `GitObjectFormat` is the only parser;
no code converts an ID to a number or accepts an abbreviation. HEAD is reported as
`headState`: `attached` (names an existing branch, with `headRefId` and `headObjectId`), `unborn`
(names a branch without a commit, so both IDs are `null`) or `detached` (an object without a
branch). `headRefName` is display text. No code path assumes a `master` or `main` branch; the
initial branch of a new repository is configured policy, and imported repositories keep their own.

A commit records source state. A commit, branch, tag or clean work tree never means build or
behavior validation, candidate selection or acceptance; `gitMapping.acceptance` comes from canonical
evidence alone. Every `gitWorkspace` reports `trackingPolicy: "source-only-v1"` (below).

### Source-only tracking policy

Managed repositories track reconstructed source, not job state (#569). The server writes the rules
below to the repository's private `info/exclude`. Nothing is added to the work tree, so source
bytes and file names stay exactly as the snapshot recorded them. The top-level `build` output root
of a snapshot is not copied into the work tree, which matches the archive transport layout.

| Category | Excluded patterns |
| --- | --- |
| Original binaries | `/input.elf`, `*.elf`, `*.bin`, `*.exe`, `*.dll`, `*.so`, `*.so.*`, `*.dylib`, `*.a`, `*.lib`, `*.o`, `*.obj`, `*.out` |
| Credentials | `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ecdsa*`, `id_ed25519*`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `*.token`, `credentials.json` |
| Job databases and runtime state | `job.json`, `workflow-state.json`, `*.sqlite`, `*.sqlite3`, `*.db`, `*.db-journal`, `*.db-wal`, `.upload-*/`, `.job-metadata-*`, `.git-runtime/` |
| Private transcripts | `/transcripts/`, `/sessions/`, `*.transcript`, `*.jsonl`, `*.ndjson` |
| Native build output | `/build/`, `/out/`, `cmake-build-*/`, `CMakeFiles/`, `CMakeCache.txt`, `cmake_install.cmake`, `build.ninja`, `.ninja_deps`, `.ninja_log`, `compile_commands.json`, `*.d`, `*.gcda`, `*.gcno` |
| Transient evidence | `/reports/`, `/evidence/`, `*.log`, `*.tmp`, `*.swp`, `/tmp/`, `/.tmp/` |

The patterns never match C/C++ sources, headers, CMake or Make descriptions, README files or
`source_tree_manifest.json`. `GitTrackingPolicy` holds the same list, and its tests check both
directions against real `git check-ignore` results.

`info/exclude` only makes excluded files look ignored. Git gives a `.gitignore` in source content
higher precedence, so a pattern such as `!secret.key` would re-include a credential. The policy is
therefore enforced on its own terms. `GitTrackingPolicy.excluded` evaluates paths with
`check-ignore --no-index` in a server-owned scratch repository whose only ignore source is the
policy, so no repository file can override it. Staging refuses any path it excludes.
Startup or mutation-owned runtime preparation creates this policy repository before reads. Workspace
reads only use the prepared policy; missing policy storage is unavailable, not silently recreated.
A completed recovery sweep can leave a worktree conflict available for read-only inspection; viewing
it does not retry recovery. After operator repair, sweep explicitly before reviewing new guards.

### Server-owned Git adapter

The `decompengine.git` adapter uses the system `git` executable, not a library (#570). Git is an
optional runtime prerequisite. At startup the first absolute `git` on the server's `PATH`
is resolved to its real path and probed with `git version`. Versions older than 2.36.0
(needed for `GIT_CONFIG_GLOBAL` and repository ownership checks) are unsupported.
Bootstrap reports `runtime.gitVersion` as the bare numeric version, or `null` when none is
detected, plus `git` and `git-import` capabilities. `git` is `unavailable` with `GIT_NOT_FOUND`,
`GIT_VERSION_UNSUPPORTED` or `GIT_PROBE_FAILED`, and `supported` when the managed repository
routes below are served. Every Git endpoint answers `503 CAPABILITY_UNAVAILABLE` with that reason's message when
Git is unusable. The executable path never leaves the server.

- **Argument safety.** `ProcessBuilder` receives a separate argv; no shell is involved. Callers
  name one allowlisted subcommand and its arguments. Only the runner adds global options
  (`--no-pager`, `--no-replace-objects`, `--literal-pathspecs` except for `check-ignore`, which
  takes plain names, `-c` overrides, `--git-dir`, `--work-tree`). Arguments are bounded and contain no NUL. Branch names pass a local syntax check
  and then `git check-ref-format refs/heads/<name>`, so a value can never be parsed as an option.
- **Bounds.** Each call has its own wall-clock limit (30 s by default) and stdout/stderr byte
  limits (1 MiB and 64 KiB). Exceeding either kills the process and its descendants. Stdin is
  closed. Captured stderr stays server-side; public errors use fixed messages.
- **Environment.** The child receives a fresh environment: `PATH` (the executable's directory,
  `/usr/bin`, `/bin`), a server-owned `HOME` and `XDG_CONFIG_HOME`, `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL` pointing to an empty server-owned file, `GIT_ATTR_NOSYSTEM=1`,
  `GIT_TERMINAL_PROMPT=0`, empty `GIT_ASKPASS`/`SSH_ASKPASS`, `GIT_NO_REPLACE_OBJECTS=1`,
  `GIT_OPTIONAL_LOCKS=0`, `GIT_PROTOCOL_FROM_USER=0`, `GIT_CEILING_DIRECTORIES` and a C/UTC locale.
  The runtime directories live in `<job store>/.git-runtime` and must be empty.
- **Command-line configuration.** These values outrank any repository configuration:
  `core.hooksPath` (an empty server-owned directory), `core.fsmonitor=false`,
  `core.untrackedCache=false`, empty `core.askPass` and `credential.helper`,
  `core.sshCommand=false`, `core.symlinks=false`, `core.autocrlf=false`, `core.protectNTFS`/`HFS`,
  empty `core.attributesFile`/`core.excludesFile`, `protocol.allow=never`, no submodule recursion
  (`submodule.recurse`, `fetch.recurseSubmodules`, `push.recurseSubmodules`), no automatic
  gc/maintenance, no signing, an empty `init.templateDir`, `safe.bareRepository=explicit` and
  `transfer.fsckObjects=true`. `safe.directory` is never set, so Git's ownership check stays strict.
- **Inert repository content.** Only configuration can name an executable: filter, diff and merge
  drivers, credential helpers, fsmonitor, pagers, aliases and includes. Before any command runs in
  a managed repository, its `config` is read with `git config --file … --no-includes` and must
  contain only server-written keys (`core.repositoryformatversion`, `core.filemode`,
  `core.bare=true`, `core.ignorecase`, `core.precomposeunicode`, `core.logallrefupdates`,
  `extensions.objectformat`, `user.*`). Otherwise the read fails with `REPOSITORY_CONFIG_UNTRUSTED`.
  Before config is read, the repository root and its ancestors must be non-linked directories;
  a no-follow metadata walk rejects links and special files, including linked `info`, nested refs
  and loose object storage. The walk is bounded to 100,000 entries and 20 seconds (exhaustion is
  `REPOSITORY_UNAVAILABLE`). The registered worktree root/ancestors must also be non-linked.
  These checks do not replace admission: D8.2 must select registered storage under a trusted
  managed root, isolate imported content (including shared writable inodes), validate the object
  graph and enforce ownership/locking against concurrent filesystem replacement. Inspection is
  not an arbitrary-host-path admission API or a race-safe source snapshot.
  Alternates, `commondir` and shallow files are `REPOSITORY_UNSUPPORTED`. Hooks never run because
  of the empty `core.hooksPath`. Attribute files can name a filter, but no driver exists. Built-in
  conversions need no driver (`text`/`eol` line endings, `ident`, `working-tree-encoding`), so
  every managed Git directory carries a server-owned `info/attributes`, which has the highest
  attribute precedence: `* -text !eol -crlf -ident -filter !working-tree-encoding`. The audit
  refuses a repository whose file differs, so checkout and status always see the exact blob bytes. Submodule paths stay empty gitlinks. No command fetches
  or contacts a remote. No exceptions exist yet. Any future hook, filter, submodule or helper
  support needs its own reviewed design and capability.
- **States.** A read reports `unborn`, `attached`, `detached`, `dirty` and the object format,
  without assuming a branch name. Symbolic HEAD must name a valid `refs/heads/...` branch;
  other namespaces are `REPOSITORY_UNSUPPORTED`, not attached or unborn branches. Ref display is
  bounded to 200 entries with explicit truncation; attached HEAD's matching ref is retained within
  that bound even if it sorts after the other refs. A missing or linked repository is `REPOSITORY_UNSUPPORTED`. A ref
  that does not resolve, or a non-commit HEAD, is `REPOSITORY_CORRUPT`. Bounded failures are
  `REPOSITORY_UNAVAILABLE`.

`GitAdapterTest` uses real temporary repositories under the Gradle temporary directory, including
paths with spaces and non-ASCII characters, SHA-1 and SHA-256 formats and a non-`main` branch. It
also uses fake executables for missing, old, slow, noisy and failing Git. Tripwire hooks,
fsmonitor and filter scripts show that nothing in repository content runs. This covers the
adapter boundary only.

### Managed repository initialization, import and recovery

`GET J/repositories`, `POST J/repositories`, `GET G` and `GET G/operations/{operationId}` are
served when the `git` capability is `supported` (#571-#573). Each of them returns `503
CAPABILITY_UNAVAILABLE` with the capability's reason message when Git is missing or too old.
They follow the shared session rules. A read discloses repository facts only after the job
resolves, and never runs a write, fetch or checkout. The POST uses the shared mutation boundary
(session, Origin, JSON and CSRF) before any body or service read. It also needs one strong job
`If-Match`, one 16-128 character `Idempotency-Key`, no query and a strict body of at most 2048
bytes:

- `{"action":"git.init","runId":…,"revisionId":…,"initialBranch":null|"name"}` copies the recorded
  `source-tree` snapshot of that attempt's candidate into a new work tree. `initialBranch` must
  pass `check-ref-format`; `null` selects the server's configured default branch.
- `{"action":"git.attach","sourceName":"name"}` imports one repository that the operator placed
  directly under the server's import root (`web --git-import-root <directory>`). The value is a
  single validated name, never a path. Without a configured root, `git-import` is `unavailable`
  (`GIT_IMPORT_UNCONFIGURED`) and the request is refused with 503.

An admitted request returns `202 operation`, a `Location` for `G/operations/{operationId}` and a
strong ETag. The operation is durably recorded as `queued` before any work starts. Replaying the
same key returns the original operation with `Idempotency-Replayed: true`, even with a stale
guard; the key lookup precedes the fresh job-version check. A key reused with a different body
is `409 IDEMPOTENCY_CONFLICT`. A stale job guard is `412`, and a missing one `428`. A job that
already has a repository is `409 REPOSITORY_EXISTS`, and one with a queued or running operation
is `409 WORKTREE_BUSY`. Exhausted capacity is `429`. An unknown run or revision, an invalid
branch or an import name with no admitted repository is `422`. A refused request creates no
operation record.

Initialization copies regular files byte for byte, preserving executable bits. It omits the
top-level `build` root and refuses links, special files and nested `.git` entries. Every file is
re-hashed on both sides after the copy. The managed Git directory is a bare repository with the
server's configuration: identity from configured policy, `user.useConfigOnly`, the source-only
`info/exclude` and nothing else. No file is staged and no commit is created, so the workspace
reads as an `unborn` branch with untracked files (`dirty: true`). Its `candidateRevisionId`
names the copied revision.

Import validates the admitted directory as data. A `.git` directory is a non-bare repository,
and `HEAD`/`objects`/`refs` at the top level is a bare one. A `.git` file or link, alternates,
`commondir`, a shallow file, format version above 1, or an extension other than `objectFormat`,
`worktreeConfig`, `noop` and `preciousObjects` (for example reftable or partial clone) gives
`REPOSITORY_UNSUPPORTED`. The repository configuration is read only with `git config --file …
--no-includes`. A fresh managed repository then receives the object store (without
`objects/info`), the branch and tag refs (loose and packed) and HEAD. Every branch or tag must be
a valid full ref name, such as `refs/tags/HEAD`; one that cannot be imported fails the import
instead of being dropped. Selected symbolic refs are resolved as bounded inert data (at most 16
steps), including targets in omitted namespaces, and stored as full object IDs; HEAD retains its
branch name. Cyclic or excessive symbolic chains give `REPOSITORY_UNSUPPORTED`.
Object copying pins every source ancestor with descriptor-relative no-follow directory opens.
The shared Linux filesystem boundary opens leaves with `O_PATH`, authenticates regular-file type
on the pinned descriptor, then reopens that exact inode with `O_NONBLOCK` for reading. A raced-in
FIFO cannot block an import waiting for a writer, and links cannot redirect reads. Copies stream
at most 512 MiB into newly created regular files (at most 100,000 object-store files and directories
combined). Unsupported native/default-filesystem/procfs boundaries fail closed as
`REPOSITORY_UNSUPPORTED`; there is no pathname-copy fallback. Imported HEAD, packed refs and
loose refs (including symbolic-ref targets) use the same pinned-ancestor, regular-type-authenticated
nonblocking read boundary, with their existing 4 KiB/4 MiB metadata limits and cancellation checks.
A metadata entry replaced by a link or special file is refused rather than blocking the worker.
Configuration, hooks, `info/`, the index, reflogs, remotes, notes, replace refs, worktrees, submodule repositories and
uncommitted working-tree changes are not copied. A full `git fsck` must succeed, which re-hashes
every object against its ID (integrity errors give `REPOSITORY_CORRUPT`). Verification runs with
a hard and soft 512 MiB process address-space ceiling, including mappings and inflation of
packed, dangling and historical objects, before checkout quotas run. This requires the server's
fixed `/usr/bin/prlimit` or `/bin/prlimit` utility; missing/unstartable containment fails closed as
`REPOSITORY_UNAVAILABLE`, never an unbounded retry. Fatal/resource exits give
`REPOSITORY_UNSUPPORTED` rather than claiming proven corruption. No core dump is allowed.
Before checkout, `ls-tree -r -t -l` of the HEAD tree must fit the work-tree quotas: 20,000 leaf
entries, 20,000 directories and 512 MiB of declared blob bytes. Tree paths count once per prefix;
inert gitlinks also count as directories. This bounds directory expansion as well as repeated or
highly compressed blobs before `read-tree` creates anything.
The HEAD commit is then checked out with `read-tree --reset -u` under the server configuration and
the neutral `info/attributes`. No hook, filter, fsmonitor or submodule recursion can run, and no
attribute conversion can rewrite bytes. Attached, detached and unborn HEADs
are preserved and reported as such, and SHA-256 repositories keep their format. Failed
validation becomes a `failed` operation with a fixed path-free message. The imported directory
itself is only read.

Each operation works in a private staging tree under the job's `git/staging/<operationId>`. The
registration record is written inside that tree before one atomic rename publishes it as
`git/repositories/<repositoryId>`, and an existing name is never replaced. Readers therefore see
either no repository or a complete one. Nothing is written under `reports/`, so a recorded or
accepted source snapshot cannot be overwritten. Startup prepares the private Git runtime and
reconciles retained jobs; explicit mutation admission can also reconcile a job before use.
GET routes never prepare runtime/storage or retry reconciliation. If startup recovery failed for
a retained job, reads return `503 STORAGE_UNAVAILABLE` without changing its records or staging;
only an explicit lifecycle recovery sweep or mutation admission may retry. Non-terminal records
are reconciled under those authorities. A published repository makes its operation
`completed`. Otherwise the staging tree is removed and the operation becomes `interrupted` with
`recoveryRequired: false`. If removal fails, it becomes `recovery-required` and the tree is kept
for inspection. Reconciliation never repeats work. Replaying the original key reports the
interrupted operation, and a new key starts a fresh, explicit initialization.

Shutdown interrupts the Git worker. Copy and cleanup loops stop at their next step, and Git
processes are killed. The listener releases store ownership only after the worker has actually
stopped. A worker that outlives the bounded wait keeps the store owned, so a replacement listener
cannot reconcile staging that is still being written.

`GET J/repositories` returns `gitRepositories`: the job's repository summary (at most one) and
its latest 20 operations. `GET G` returns `gitWorkspace` from a fresh bounded inspection. Its
`worktreeVersion` doubles as its ETag and changes with any observed status or HEAD change.
`repositoryVersion` changes with refs, and `refId` is stable per repository and ref name.
`mapping` stays `null` until an explicit commit records a validated source mapping (#203).

`ManagedGitRepositoriesTest` covers byte-exact initialization (spaces, non-ASCII names, executable
bits), the ignore policy against real `git status --ignored`, the absence of commits, replay and
conflicts, refused requests that leave no record, linked snapshots, and unusable Git. It also
covers every crash point (after the running record, after staging, before publication and after
publication), with recovery checked on a new instance. Import is checked on a hostile repository
whose filters, fsmonitor, hooks, hooksPath, includes and submodule never run, and whose bytes are
unchanged. Bare/detached, unborn, SHA-256, corrupt, alternates, gitfile, partial-clone, plain and
linked sources are checked as well. `WebGitControllerTest` covers the HTTP contract: bootstrap
capability states, guards, strict bodies, path-free responses and the unavailable answers. The
job page's minimal Git panel (`GitRepositoryPanel`) shows availability, the observed HEAD and a
single initialization action from the latest attempt's candidate. The full Git UI belongs to
#583.

### Bounded Git status, history, diffs and refs

`GET G/status`, `G/history`, `G/diff` and `G/refs` are capability-gated private reads (#574, #575).
They accept only their listed query parameters, each at most once. `limit` is 1-200 and defaults
to 50, and pages also stop early at a 256 KiB rendering budget. No read runs a hook, filter,
textconv, external diff tool or submodule command, and no read refreshes the index with a lock.
Every GitReads child also has a hard and soft 512 MiB address-space ceiling, including raw/numstat
comparisons, selected patches and object-size reads. Enforcement is fail-closed; a missing limiter
or an allocation failure returns an explicit repository-unavailable/corrupt error, never an
unbounded retry.

- `status` (`gitStatus`) parses `git status --porcelain=v2 -z --untracked-files=all
  --ignored=matching --find-renames` byte by byte. Each entry reports its `staged` and `unstaged`
  change (`added`, `modified`, `deleted`, `renamed`, `copied`, `type-changed` or `none`) and
  whether it is untracked, ignored (by the source-only policy), conflicted (with the exact
  conflict kind) or a submodule. Renames carry `originalPath`. `counts` covers the whole status.
  `notices` explain the current state and its available next steps: clean, dirty, unborn,
  detached, conflicted, busy (a queued or running operation) and incomplete (status output
  exceeded 4 MiB). The read itself stays usable in every one of those states. The cursor is bound to
  `worktreeVersion` plus all listed paths/states, including ignored entries; observable listing
  changes cause a later page to answer `409 REF_CHANGED`.
- `worktreeVersion` now digests HEAD plus every non-ignored status entry. That includes the
  entry's index blob and the work-tree file's size and modification time, so re-editing an
  already modified file or re-staging different content changes it. Native invalid-UTF-8 names
  are observed using their exact filesystem bytes, not their escaped display names. Observation
  errors other than a missing file fail explicitly rather than supplying a stable placeholder.
  Ignored files never change this version. This is a bounded read fingerprint, not a source-content
  identity: edits preserving size/mtime or beyond the status output bound may leave it unchanged.
- `history` (`gitHistory`) lists commits from an exact `start` object (default HEAD; an unborn
  branch has none). The output is NUL-delimited `git log` with full object IDs, all parents (merges
  included), author, timestamps and a 200-character subject with an explicit truncation flag.
  Parent arrays are never silently shortened. The raw history read (including its lookahead
  commit) is capped at 128 KiB; this also bounds any one parent list below the schema's 3200
  entries. Output above that bound returns `REPOSITORY_UNAVAILABLE`, not a partial parent list;
  a smaller page limit can help when multiple commits exhaust the bound.
  The cursor embeds the start object and offset, so a branch that moves after the first page
  cannot shift later pages. A history entry's `mapping` is non-null only for an explicitly
  recorded, validated commit-to-revision binding. A commit alone is never treated as a
  reconstruction revision.
- `diff` (`gitDiff`) compares `scope=staged` (index against HEAD, or against the empty tree on an
  unborn branch), `scope=unstaged` (work tree against the index) or `scope=commit&commit=<full id>`
  (against its first parent, or nothing for a root commit). Files come from `--raw -z --no-abbrev`
  and `--numstat -z` with rename detection. Each carries its change, old and new blob IDs and
  modes, line counts and a binary flag (`-` counts mean binary). The new blob's size comes from
  `cat-file --batch-check` without reading the content. `file=<fileId>` returns that file alone
  with a unified patch of at most 128 KiB, flagged `truncated` when cut. Binary files never
  render content. Text patches whose current or original path is invalid UTF-8 or exceeds the
  runner's 4,096 UTF-16-code-unit argument bound return `422 PATCH_UNAVAILABLE`; the exact listing
  identity and display entry remain available, including for trees never checked out at HEAD.
  Managed `info/attributes` restores automatic binary detection with `!diff`,
  overriding source-controlled forced-text/binary/driver attributes. The exact previous managed
  attributes layout is atomically upgraded on audit; unrecognized layouts are rejected without
  rewriting them. No source or index bytes change during that upgrade. Abbreviated object IDs
  are rejected with 422.
- `refs` (`gitRefs`) pages through branches and tags with exact and peeled object IDs, stable
  `refId`s and the branch HEAD currently names. Its cursor carries a digest of every ref listed
  before it. If a branch or tag is created, deleted or moved ahead of the offset, the page answers
  `409 REF_CHANGED` instead of repeating or skipping an entry.

A path has exactly one status entry. After `git rm --cached`, Git reports both a staged deletion
and an untracked record for the file, and these are merged into one entry with
`staged: "deleted"` and `untracked: true`. The patch for a selected file is the section that
belongs to its record:

- a type change keeps both its deletion and addition sections;
- an unresolved conflict returns Git's combined `diff --cc` section;
- a metadata-only rename or mode change is matched by its header, quoted as Git quotes unusual
  names.

If the bounded capture ends before the selected section (for example, an unrelated subtree
under a rename's former path fills the capture), the response reports `truncated: true`, even
if its selected text is empty. An incomplete source capture is never presented as complete.

Paths are display strings. Backslashes, control characters (newline, tab, escape and the like)
and invalid UTF-8 bytes are escaped, and `pathEscaped` marks any name whose display differs from
its bytes. Identity is the opaque `fileId`, derived from the exact bytes and the work tree, so
look-alike names never share an identity. `GitReadsTest` checks every status category, real merge
conflicts, unusual and invalid-UTF-8 names, anchored history pages across a merge and a moving
branch, renames, binary sizes, a large patch truncated within its bound, staged diffs on an unborn
branch, and paged peeled tags. `WebGitControllerTest` covers the HTTP shapes, cursors and
refusals.

### Staging and deliberate commits

`POST G/operations` accepts `git.stage`, `git.unstage` and `git.commit` (#576, #577). The body
holds the target `worktreeId`, the full `guards` taken from the reviewed status and the exact
`selectedFileIds`; a commit also carries its `message`. Bodies are strict JSON of at most 64 KiB
and never contain a path or pathspec. `If-Match` must name the guarded `worktreeVersion`, and an
`Idempotency-Key` is required. Keyed replay returns the original operation. The response is
`202 operation`, already terminal for most local actions, with the durable operation at
`Location`.

Routine work-tree operations never use up the job's operation quota. When an admission would
reach it, the oldest terminal work-tree records are retired, and the newest 63 stay replayable by
their keys. Initialization, import and `recovery-required` records are never retired. If a
retired key is sent again, it is admitted as a new request, and its guards refuse it unless the
reviewed state still holds.

After `git rm --cached`, a path is both staged for deletion and untracked, in one status entry.
Selecting that entry for `git.unstage` unstages the deletion, and selecting it for `git.stage`
stages the replacement. Its staged deletion remains protected by overlap checks: an untracked
replacement does not allow another selected path to silently unstage the deletion.

The server checks guards and selection at admission under the job lock. Mutation worktree
versions additionally bind bounded exact content/mode commitments for non-ignored status paths;
the metadata-only pagination fingerprint is not staging authorization. Status must be complete.
Stage/unstage acquire Git's `index.lock`, `HEAD.lock` and the symbolic HEAD's branch lock before
final validation. They mutate a private index and atomically publish it under those locks, so an
external Git writer cannot invalidate overlap checks between validation and mutation. Unstage
resets against the guarded parent object ID, not mutable `HEAD`. Stage captures selected file/link
bytes, verifies their reviewed commitments, and writes exact blob/index entries from the capture;
later worktree edits never supply unreviewed bytes to Git. Content reads share a 512 MiB bound and
fail closed on drift, unsupported entries or overflow; partial private mutations are not published.
Commits acquire `index.lock` and `HEAD.lock`, revalidate, and capture the reviewed index into a
private immutable tree. The commit uses that tree and the reviewed parent, never the later live index. Publication locks the
target ref, compares the reviewed HEAD under that lock, and atomically replaces the ref. Busy
writers or a changed parent are refused; no unreviewed index entries can enter the commit.
Because read-only status suppresses submodules, commit validation separately reads a bounded,
gitlink-inclusive index comparison at admission, execution and from the captured private index.
Any staged gitlink addition, pointer change, deletion or type change is refused with
`EXCLUDED_PATH`, even if it is absent from status and has not changed the status-derived guards.
An incomplete index comparison fails closed with `STATUS_INCOMPLETE`.

| Refusal | Meaning |
| --- | --- |
| `409 REF_CHANGED` | `repositoryVersion`, HEAD or the guarded ref changed |
| `WORKTREE_BUSY` (operation failure) | Another Git writer holds the index, HEAD or target-ref lock; nothing is published |
| `409 WORKTREE_CHANGED` | The work tree or index changed (any status entry, index blob or file stat) |
| `409 SELECTION_CHANGED` | A selected file identity is no longer in the current status |
| `409 SELECTION_OVERLAP` | A pathspec would affect unselected descendants, staging a descendant would remove an unselected tracked ancestor, or unstaging a deletion/rename source would remove an unselected staged ancestor |
| `409 INDEX_CHANGED` | A commit's `selectedFileIds` differ from today's staged set; nothing is swept in or left out |
| `409 CONFLICTED`, `409 NOTHING_TO_COMMIT` | Unmerged paths exist, or nothing is staged |
| `422 EXCLUDED_PATH` | The file is excluded by the source-only policy (decided independently of any repository `.gitignore`), is a submodule, or has a non-UTF-8 name |
| `422 NOTHING_SELECTED`, `422 STATUS_INCOMPLETE` | A selected file has nothing to stage or unstage, or the status/index comparison was too large to review completely |
| `503 SIGNING_UNAVAILABLE` | Server policy requires signed commits, which no capability provides |

Staging runs `git add -- <paths>` with literal pathspecs. Unstaging runs `reset -q HEAD -- <paths>`
(or `rm --cached` on an unborn branch), so work-tree contents never change. A commit uses the
server's configured identity, passed as allowlisted author and committer variables. `write-tree`
uses an operation-private index, and `commit-tree --no-gpg-sign` creates the exact reviewed commit
without running commit hooks. The message is read verbatim from an operation-private file.
Managed files-backend ref publication does not append reflogs; history remains object-based.
Nothing is pushed. Bootstrap reports
`git-signing` as `unsupported`, so a signing requirement can never hang on a hidden prompt.

A successful commit returns its object ID as `resultObjectId`. It is mapped to the repository's
candidate revision only when its tree, compared by Git blob IDs computed from the recorded
snapshot, equals exactly the copied snapshot minus policy-excluded files. The complete captured
file manifest must match the manifest retained at initialization. SHA-256 commitments, sizes and
Git blob IDs come from the same bounded read of each file, so changed canonical inputs or added
undeclared files cannot borrow the original revision's identity. The mapping is stored
under the repository as `(repositoryId, objectId, revisionId, sourceSha256)` with the
work-tree's dirty state. `gitWorkspace.mapping` and history entries show it. `acceptance` is read
from the job's canonical accepted revision at view time, never stored and never changed by a
commit. Any other commit is a new candidate and stays unmapped. Mapping/inspection IO failure
also leaves the published commit successful with an explicit unconfirmed-mapping message; it
never turns that commit into an apparently uncommitted failure. Other post-publication failures
report `recovery-required`, retaining the exact published `resultObjectId` when known, rather
than reading a possibly later writer's HEAD as this operation's result.

After a restart, stage and unstage operations become `interrupted`: their index publication may
have completed, so status must be re-read; they are never replayed. All mutation locks have private inode witnesses persisted
before the public lock names are linked, so owned locks can be reclaimed even with empty or
partial contents. A replacement inode is never reclaimed on the basis of matching contents when
a witness exists. Complete operation markers from older versions remain recoverable; legacy
partial locks without ownership proof are preserved.

A commit is `interrupted` when HEAD is still the reviewed parent and no unproven Git locks
remain. Otherwise it becomes `recovery-required`: `COMMIT_LOCKS_REQUIRE_REVIEW` means a remaining
index, HEAD or target-ref lock requires inspection of the repository and its writers. A moved
HEAD is included as `resultObjectId`, because the commit may or may not be the requested one.
Nothing is repeated automatically.

Job retention: uncommitted or unpublished Git work should hold the job against deletion. The
`JobRetentionHold` interface arrives with #1694 (D10, #509) and has not merged yet. Registering a
hold for a dirty work tree or for unmapped commits is left as a follow-up once it lands.

`GitWorkspaceMutationsTest` covers:
- exact partial staging, unstaging on an unborn branch, a mapped commit with the server identity
  and verbatim message, and a second, unmapped commit;
- acceptance derived at read time;
- every refusal above, including a `.gitignore` negation that tries to re-include a credential;
- keyed replay and idempotency conflict;
- an external edit between admission and execution, which fails with `WORKTREE_CHANGED`;
- staging a descendant refuses an unselected tracked ancestor deletion, but succeeds after that
  deletion is explicitly staged;
- external index writers after capture, busy locks, parent CAS, detached parents in both object
  formats, and exact result identity when a later writer advances HEAD;
- snapshot file additions and mutation after capture, ordinary post-publication errors and
  optional mapping-write failure;
- restart before and after the commit, empty/partial owned lock recovery, external replacement
  preservation and conservative recovery status for unproven legacy locks.

`WebGitControllerTest` covers the HTTP guards, `If-Match` binding, strict bodies and the mapping
shown on the workspace and in history.

### Branches, linked work trees, tags and source exports

`POST G/operations` also accepts the actions below (#578, #579, #581). Each carries the reviewed
`guards` of its target work tree and the same `If-Match`, idempotency and two-phase recheck as
staging and committing.

| Action | Body fields | Effect and refusals |
| --- | --- | --- |
| `git.branch.create` | `name`, `startObjectId` | `update-ref refs/heads/<name> <id> ""` creates the branch only if absent (`409 BRANCH_EXISTS`); nothing is checked out |
| `git.switch` | `refId` with the branch's reviewed tip as `objectId`, or `objectId` alone for a detached switch | `switch --no-guess --no-recurse-submodules` (or `--detach`). A branch that moved since review is `REF_CHANGED`. The tip may be omitted only while the repository's refs fit the 200-ref observation that the guards cover. Refused with `409 WORKTREE_DIRTY` for staged or unstaged changes, `CONFLICTED`, or `ACTIVE_RUN` while a lease is held. Nothing is stashed or discarded, and untracked files are kept. Git's own refusal is `SWITCH_REFUSED`. The target tree must fit the checkout bound. |
| `git.branch.delete` | `refId`, `expectedObjectId` | `update-ref -d` with the expected tip. Refused with `BRANCH_CURRENT` when any work tree has it checked out, `REF_CHANGED` when it moved, or `BRANCH_UNMERGED` (with a count) when commits are reachable only from it. Never forced. |
| `git.tag` | `name`, `targetObjectId` | A lightweight tag with no timestamps, created only if absent (`409 TAG_EXISTS`); existing tags are never overwritten |
| `git.worktree.add` | `startObjectId`, `branchName` or null, `runId` or null | `git worktree add` under the repository's private `worktrees/<worktreeId>`. At most four linked work trees, a checkout-size bound, and an optional owning attempt that must belong to the job. The new identity is the operation's `worktreeId`. |
| `git.worktree.remove` | none | Removes a linked work tree. Refused with `WORKTREE_PRIMARY`, `ACTIVE_RUN` while its owner runs, `WORKTREE_DIRTY` for any uncommitted, untracked or ignored local file (Git would delete ignored files) or for files inside a submodule (gitlink) directory, or `WORKTREE_UNMERGED` for detached commits that no branch or tag reaches. Uses `git worktree remove` without `--force`. |

Leases: the primary work tree is leased to every active workflow attempt of the job, and a linked
work tree to the attempt that owns it. While a lease is held, switch and removal answer `409
ACTIVE_RUN`, so checkout never replaces files under a running worker. Workflow admission and
checkout/removal also share an atomic reservation: a new workflow start, retry or checkpoint
resume answers `409 WORKTREE_BUSY` while Git owns it. Replays of retained workflow commands
remain read-only and do not schedule another worker. At most one Git operation runs per job,
on a single executor.

A branch switch also holds the destination's common-repository Git ref lock through final
validation and checkout, so an external ref writer cannot substitute a new tip after the size
and identity checks. A busy destination is `WORKTREE_BUSY`; symbolic branch aliases are refused
as `SWITCH_REFUSED` because locking an alias would not pin its referent. Restart reclaims only
inode-witnessed owned locks and does not report a later external destination move as a completed
checkout of the reviewed object.

`GET G/worktrees` (`gitWorktrees`) lists the primary and linked work trees with HEAD, dirty state,
version and owner. `GET G/worktrees/{worktreeId}` returns that work tree's `gitWorkspace`.
`G/status`, `G/history` and `G/diff` accept `worktree=<id>`, and every mutation names its target
`worktreeId`. Each linked work tree has its own index and guards. Its administrative directory is
audited: it must point back to the common repository and carry no configuration, hooks or info
files of its own. Linked commits lock their private index and HEAD, but publish attached branch
refs in the common repository; detached commits update only their own HEAD. Commit recovery
checks the same private and shared lock locations and never deletes an unproven writer's lock.

Restart reconciliation compares each intent with the actual refs and never repeats it:

- A branch or tag that exists at the requested object is `completed`; an absent one is
  `interrupted`; one at a different object is `recovery-required` (`REF_CONFLICT`).
- A delete is `completed` when the ref is gone and `interrupted` otherwise.
- A switch is `completed` when HEAD is at the target and `interrupted` when HEAD is still at the
  reviewed state. Otherwise it is `recovery-required`, with the HEAD state named. A HEAD left on a
  branch that no longer exists is reported as `REF_DELETED` (unborn).
- A work-tree creation without its registration is removed again and becomes `interrupted`.
- A removal whose directory is gone is `completed`.

Reconciliation never touches recorded source snapshots.

`GET G/provenance/{objectId}` (`gitProvenance`) is the envelope for one exact commit. It carries
the object format, commit time and subject, the recorded revision mapping (with `acceptance`
derived at read time) and `worktreeDirtyAtCommit`. `refNames` lists the branches and tags that
currently name the commit, as display labels only. It also describes the deterministic export:
digest, size, file count, skipped non-file entries and its verification. Moving a branch or tag
changes only `refNames`; the object ID, mapping and export digest stay the same.

`GET G/exports/{objectId}` (`application/zip`) returns the deterministic source export of that
commit's tree (#582). It contains only the tree's regular files, in unsigned byte order of their
paths. Entries are stored uncompressed with a fixed 1980-01-02 DOS timestamp (1980-01-01 00:00 is the JDK's "before 1980" sentinel, which would add a time-zone-dependent extended timestamp) and no extra fields,
and there is no `.git`, reflog, configuration, commit message, author or timestamp. Equal trees
therefore export identical bytes whatever their commit metadata or work-tree state. Submodule
links and symbolic links are omitted and counted in `skippedEntries`. File modes are not
represented. The provenance envelope travels separately and is never inside the payload.

`GitSourceExports.verify` checks an export independently. It recomputes every entry's Git blob ID
from the archive bytes and compares the set with the commit tree; it needs no remote and trusts no
ref name. It verifies this deterministic STORED ZIP profile, not arbitrary ZIP variants: local
headers, the complete matching central directory and end record must reproduce exactly, with no
trailing bytes. Truncated directories and non-ZIP payloads fail even for an empty expected tree;
a complete empty ZIP succeeds. The reconstruction pipeline's own deterministic `source-tree.zip` is unchanged: it is
still built from recorded snapshots, and its packager still refuses any `.git` path. A Git
repository is never an input to it.

`GitBranchesWorktreesTest` covers:
- branch creation, refusals and dirty and leased switches, with untracked files kept;
- current-branch, moved-branch and unmerged deletes, and tag non-overwrite;
- linked work-tree containment, ownership, independent staging and committing, and every removal
  refusal and the quota;
- restart reconciliation, including a deleted branch left as an unborn HEAD and a half-created
  work tree that is cleaned up;
- byte-identical exports across commit metadata and dirty work, `.git` exclusion, fixed
  timestamps, tamper detection, and identity unchanged by moved refs.

`WebGitControllerTest` covers the HTTP endpoints and the downloaded export digest.

### Git workspace view and packaged journey

The SPA route `/jobs/{jobId}/git` (#583) is a lazily loaded view over the endpoints above. The job
page's repository panel links to it. Viewing it never mutates anything. Every change sends the
guards of the status it was reviewed against, waits for the durable operation, and then reads the
repository again. The view has these parts:

- **Capability.** When Git is unavailable, unsupported or not reported, the view says so with the
  reported reason and sends no request. Source and evidence routes are unaffected.
- **Repository.** With no repository it explains initialization, which stays on the job page, and
  offers import by name when `git-import` is supported. Otherwise it shows the repository, work
  tree, HEAD, object format and status notices.
- **Changes.** Changes are grouped as staged, not staged, untracked and conflicted. Ignored files
  are only counted. Selection is per group, so a file with both staged and unstaged changes is
  chosen separately for each action. A diff is shown for the chosen file.
- **Commit review.** It lists exactly the staged files and the parent commit before the message is
  accepted. Staging, unstaging and committing are disabled while the status is incomplete, the
  repository is busy, or (for a commit) conflicts remain.
- **History.** History pages with **Older commits**. Each commit shows whether it is mapped to a
  reconstruction revision and that revision's acceptance. A mapped commit links to the recorded
  source revision and attempt. Inspecting a commit shows its files, provenance, export digest and
  verification, and offers the export download and a tag form. Changed files and immutable-target
  tagging appear as soon as the diff pages arrive; optional provenance/export has a separate pending
  or unavailable state and cannot delay them. Obsolete export results cannot replace a new selection.
- **Branches and work trees.** Branches show their exact object IDs. The current marker comes from
  the selected tree's HEAD, not the repository-scoped primary-tree ref marker. Branches checked out
  elsewhere are labelled explicitly and cannot be switched to or deleted; the selected current
  branch has no switch-self/delete controls. Switching is disabled, with
  the reason shown, while the work tree has changes, status is incomplete or an operation is running.
  The `active-worker` status notice projects the backend lease for the selected work tree: any active
  attempt holds the primary tree, while only the owning attempt holds a linked tree. Switching and
  removal are disabled while that notice is present; reads and non-checkout actions stay available.
  This is advisory snapshot evidence, not a lease reservation: mutation admission still rechecks
  ownership and guards, and users refresh after the worker finishes. Linked work trees show their
  owning attempt, and removal is offered only for the selected, clean one. A refused removal retains
  that selection.

All controls are native buttons, checkboxes and forms. Outcomes are announced in a polite status
region.

`node scripts/check-packaged-web-browser.mjs --mode git` (#584) runs the packaged journey in the
`web-packaged` CI job. It runs the session journey, then:

1. Creates a disposable, 1,001-commit repository with `scripts/web-git-fixtures.mjs`. Its pre-commit hook always
   fails. The repository lives under the work parent and is admitted with `--git-import-root`.
2. Puts the system `git` on the packaged application's otherwise minimal `PATH`.

In the browser, the journey:

- uploads an inert ELF from the keyboard and follows the job page's link to the workspace;
- imports the repository by name from the keyboard;
- traverses all 51 bounded history pages using Enter and compares every displayed object ID, in
  order, with the admitted repository's `rev-list main`, with no mutation requests;
- edits the managed work tree on disk and checks that a policy-excluded `helper.o` is only counted;
- selects and stages one file with Space and Enter, and checks that the review lists exactly that
  file;
- commits it, so the failing hook also proves hooks are inert.

It then downloads the commit's export and checks that its SHA-256 equals the displayed provenance
digest, that its entries are stored, sorted and free of `.git` and excluded files, and that the
admitted repository is unchanged. Finally it replaces the JVM on the same origin and, with a new
session, loads `/jobs/{jobId}/git` directly. It confirms that the commit, the unstaged change and
the export digest are still there. The route is a server-classified SPA document path, so a direct
load or reload gets the shell. No network access or credentials are used.

This journey does not start a fake workflow worker. Worker lease projection/admission is covered by
HTTP, service and component regressions; the active-fake-worker packaged qualification required by
#206 remains outstanding. Component or service results do not substitute for that gate.

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

### Attempt queue position and stop reasons

`GET jobs/J/runs/R/queue-position` samples one attempt's place in this process's executor queue.
A queued attempt reports `position`/`ahead`, the total `queuedTasks` and busy/limit workers, always
with `approximate: true`: queued work can be cancelled or stopped, two workers start tasks
independently, and the queue is read separately from the attempt record. Other tasks are counted,
never identified. A started or terminal attempt reports `not-queued` with its state; a borrowed
executor or an attempt not found in the local queue reports `unavailable` with
`EXTERNAL_EXECUTOR`/`NOT_IN_LOCAL_QUEUE`. The sample is display-only, never admission authority.
The attempt view reads it on demand only while the attempt is queued.

Terminal reasons keep stop outcomes separate. `LIMIT_EXHAUSTED` is a used-up budget (tool calls,
output, tokens), `TIMED_OUT` a wall-clock or idle deadline, `CANCELLED` a recorded user request,
`FAILED` a workflow-reported failure, `INFRASTRUCTURE_FAILED` an adapter or executor submission that
could not produce any outcome, and `PROCESS_INTERRUPTED` a service stop or restart. Adapters may
report `FAILED`, `REFUSED`, `LIMIT_EXHAUSTED` or `TIMED_OUT`; only the service records
cancellation, infrastructure failure and interruption.

Reported attempt usage comes from the terminal receipt. The view gives its units, its source and
the receipt time (`endedAt`); the provider's own measurement time is not reported and stays
"Not reported", as does every missing counter. Limits name the configuration persisted at
`createdAt`. Live context-usage observations are coalesced for display only (one pending snapshot
per 100 ms window) and never change the acknowledged cursor or persisted evidence.

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

The `content` route accepts an optional canonical `metadataVersion` commitment and returns the complete verified bytes as a
no-store, nosniff `application/octet-stream` attachment. The ASCII fallback filename
and encoded UTF-8 basename cannot insert header syntax; the response also carries a
sandbox/default-deny CSP. HEAD verifies the same captured file and returns its length
without a body. Range and conditional HTTP headers are explicitly unsupported on both
routes; bounded JSON offsets provide the chunk operation.

Each chunk currently verifies a complete bounded file before returning its range.
No timing, RSS, physical deep-path or actual HTTP/browser qualification is inferred
from captured-byte controls. General viewer qualification, all-manifest/log/report
families, local highlighting and full D0 physical budgets remain open. Bootstrap
source chunk advertising remains zero pending those gates.

### Explicit source download digest observation

Successful source `content` GET/HEAD responses now include
`X-Decomp-Content-Verification: committed-digest`, `X-Decomp-Source-SHA256`,
`X-Decomp-Metadata-Version`, `X-Decomp-File-ID` and `X-Decomp-Content-SHA256`. These headers describe
the same captured file that already passed complete size/digest and repeated
identity/metadata checks. The existing ARCHIVE_PAYLOAD authorization and 8 MiB
ceiling apply. No compiler, behavior or archive verifier is invoked by this read.

For a downloadable recorded input, the file detail page offers an explicit
digest check through the existing private attachment HEAD route. The normal
session transport enforces its existing deadline and cancellation, performs one
request without retries, and reads no response body. Only status 200, a bodyless
response, octet-stream/nosniff headers, exact byte length and matching source,
metadata and file digests can produce the transient matching-byte observation.
Unknown, missing, changed or combined integrity header values fail closed.
Bodyless HEAD denials carry `X-Decomp-Session-Error` only for status 401 with
the exact `SESSION_REQUIRED` or `SESSION_EXPIRED` codes. The client accepts this
signal only with a valid request identity, JSON/nosniff error headers and no body,
and preserves it for the existing generation-bound session invalidation observer.
Other statuses or missing, combined and unknown error codes grant no session signal.
Navigation, metadata refresh and session removal discard the observation and
cancel its read. Metadata reads still report `contentVerification: not-performed`;
they do not start this check. The actual source-chunk bootstrap permission stays
zero. A matching file digest is separate from compilation, behavioral validation,
archive verification and accepted reconstruction. The general snapshot artifact
catalog and its full family/verification requirements remain outstanding.

The new controls use only captured byte arrays, synthetic identities, DTOs and
injected string lookups. Actual source HTTP/browser qualification and physical
D0 time/memory/workload evidence remain unproved; no new actual context trial is
introduced by those controls.

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
under that report. A capability from 1 to 3 bytes is also too small for the reader's
minimum UTF-8 range and remains disabled.

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

### Bounded source preview consumer

When a runtime reports at least four source-chunk bytes, a viewable input within the
8 MiB file ceiling offers an explicit preview button. Plain metadata navigation does
not start a body read. Direct range links use the closed document query
`?byte=O` or `?byte=O&line=L` on the exact job/run/revision/file route. Offsets are
canonical decimal bytes, not character indices; a linked line must match the
server's first LF-based line at that offset. Display labels never construct paths.
The private file-metadata endpoint still receives no query.

One request reads at most the lesser of the reported limit and 64 KiB. Every read
supplies the observed metadata version and checks job/run/revision/file, source
commitment, file size/digest, download declaration, exact offset and returned bound.
Foreign, changed, excessive or mismatched responses are withheld. Refresh and next
range are explicit; no prefetch, range accumulation or implicit retry occurs.
Selection/session changes abort and withhold late results through the existing
callback lifetime. The server still captures/verifies the complete bounded file for
each range; this UI does not reduce or qualify that physical work.

UTF-8 is escaped plain text, including Markdown and markup-like input. Invisible
controls, CR, BOM and bidi formatting are displayed as U+ markers, while original
LF positions and byte offsets identify line links. Tabs remain tabs. At most 200
line fragments or 16-byte hex rows are rendered at once, with explicit local row
paging and counts. Binary declarations, invalid UTF-8 and excessive line length
retain the server's named hex fallback; hex rows have byte offsets, not invented
text lines. Empty files retain line 1; a trailing LF does not invent an extra
zero-byte row/link beyond a nonempty file's readable offsets.

The copy button sends only the currently displayed UTF-8 rows' original string to
the clipboard: no line numbers, U+ marker substitutions or undisplayed ranges.
Its offset/length and partial-range status are explicit. Clipboard encoding or line
ending normalization remains possible; the complete authorized attachment is the
byte-preserving path. Hex fallback has no text-copy action. Source is never executed
or parsed as markup.

Local highlighting is an additional explicit action for C/C++, JSON and build
files. It sends only the current displayed rows to one packaged worker, with at
most 200 rows, 262144 UTF-16 units and 4096 output tokens. The one-second operation
timer requests termination on timeout; it is not a physical browser latency or
whole-operation CPU/RSS qualification. Completion, failure, view/range changes
and unmount detach callbacks, clear the owned timer and terminate the worker.
The worker also closes after its single response. Invalid, stale, excessive or
changed results leave the complete original display plain. Every accepted token
uses a closed presentation class and must concatenate to exactly its original row;
individual token boundaries cannot split Unicode surrogate pairs. Rendering uses
escaped text children, never HTML, styles or URLs supplied by the source.

Formatting has local syntax context only within the displayed rows. It changes
neither original copy data nor revision/byte/line identities and performs no
additional source read. Unsupported files and hex stay plain. The worker URL is a
static build reference emitted into the embedded hashed asset inventory, under the
existing self-only worker CSP. Page and worker module ownership share the same
production exclusions; the existing all-dist gzip budget also counts worker bytes.
No external rendering asset or new package is used.

Pure Node DTO/string controls cover the range, identity, representation, Unicode,
row and copy-span decisions, plus lexer/response and memory-only worker-owner
lifetime controls. Actual source HTTP/browser/clipboard/focus/keyboard,
packaged worker loading/termination and physical D0 workload/time/memory qualification remain
outstanding. The current zero bootstrap limit remains unchanged, so this consumer
does not activate previews against that report.

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

### Activity stages, correlation and private reasoning

The Activity view summarizes the retained page as stages. The attempt row comes from the
durable snapshot (`queued` waiting, `running`, `cancelling` blocked, `completed` accepted or
completed without acceptance, `cancelled`, `failed`/`interrupted` terminal failure). Task rows
group observations by `taskIdSha256` and keep the latest reported stage: analysis, planning
and agent work are running; policy, build and behavior checks plus provisional/compile-valid
results are validating; `unresolved` or a denied permission is blocked; `accepted`,
`rolled_back`, `completed`, `cancelled` and failure phases are final. Rows without a stage
(messages, tools, usage) keep the previous stage. Journal stages never establish acceptance.

A percentage is shown only for an authoritative, producer-declared total. Observed task counts
are not a denominator because tasks that have not started are invisible, so the view states
how many observed tasks reached a final stage and that no percentage is shown.

Correlation disclosures render on demand. The browser hashes the loaded attempt's own
identities (attempt, previous attempt, input and result revision) with SHA-256, the same plain
commitment the journal uses, and links only exact matches: a result revision to its source
browser and a workflow-run digest to the previous attempt. Every other reference states why
it is not linked (not recorded, not compared yet, no published task or session evidence page,
or no matching revision). A task digest can narrow the page filter instead.

Provider reasoning (`agent_thought_chunk`, role `thought`) is private. The journal records only
its position, role, completion and `textOmitted: true`; it never buffers, stores, measures or
commits to its text. Public projection also withholds `contentSha256`/`chunkCharacters` from
older thought records. The ACP client never requests reasoning and no workflow depends on it.

## Agent preflight and harness readiness

`GET /api/v1/agent/preflight` returns `agentPreflight` with `status` (`idle`, `inspecting`, `ready`, `failed`, `cancelled`), an application-generated `inspectionId` and a fixed `reasonCode` (`AGENT_PREFLIGHT_FAILED` only). `POST` with the exact body `{"action":"inspect"}` starts one inspection and returns `202`; a second request while one runs returns `409 AGENT_PREFLIGHT_IN_PROGRESS`. The inspection runs the configured harness's `preflight(WEB)` (initialize negotiation, no session, no model prompt) and is cancelled when the server stops. Exception text, inventories and configuration are discarded and never appear in the response.

The schema ties the detail fields to the status: `idle` has neither an inspection id nor a reason; `inspecting`, `ready` and `cancelled` have an id and no reason; `failed` has an id and exactly `AGENT_PREFLIGHT_FAILED`. The typed client submits the `POST` with the CSRF token only: this action has no resource version, so `If-Match` and `Idempotency-Key` are refused rather than given an undefined meaning. Server shutdown cancels a running inspection and waits for its provider cleanup before returning.

The server rejects resource conditional headers and replay keys before inspection work. The typed
exception is confined to POST, the exact route and request/response kinds; upload-only options are
also refused. Other mutation guards remain unchanged. Each call performs one fetch. After ambiguous
transport failure, read the current status and require a fresh explicit operator action; do not
automatically replay the POST. Shutdown closes admission, publishes cancellation immediately and
waits for the owned callback cleanup while preserving the shutdown caller's interrupt status.

Passive bootstrap never starts an agent or a helper probe. It reads configuration, helper-file
metadata and bundled-Ghidra presence. Missing or invalid prerequisites remain unavailable; a valid
configuration with no fresh helper observation is `unknown` with reason
`SANDBOX_HELPER_UNCHECKED`. Use the explicit `POST /api/v1/agent/preflight` inspect action to check
the configured agent and, after successful agent initialization, the existing bounded helper
prerequisite. A `ready` agent-preflight result describes agent initialization; helper readiness is
reported separately by bootstrap.

Configuration metadata and explicit helper observations retain the original ten-second cache
lifetime. A helper observation can supply `supported` only while it is fresh and its configuration
identity and helper metadata match the current projection. Expiry returns to `unknown`; it never
automatically runs another inspection. Configuration/helper identities stay internal and never
appear in either public JSON document. The helper observation neither reads nor seeds the native
execution capability cache and grants no workflow or admission authority.

A failed inspection belonging to the current configuration demotes a configured harness to
`unavailable`/`AGENT_PREFLIGHT_FAILED`. A `ready` inspection for that same configuration can report
that the agent started, but a result for another configuration cannot make that claim. Missing,
running, cancelled or mismatched agent observations leave agent readiness unproven. These fields
do not establish that any job can start work; unavailable workflow adapters remain unavailable.

## Implemented progress-pin policy endpoint

`GET` and `PUT /api/v1/jobs/{jobId}/runs/{runId}/progress-pin` are available under the configured deployment prefix. This pin protects only the selected persisted progress journal. It does not pin the full job, source revisions, reports or downloaded evidence. Unpinning neither resets the retention deadline nor restores removed history; SPA periodic progress maintenance is enabled by default; legacy mode keeps it disabled.

GET requires a local session and returns `{jobId, runId, version, pinned}` in a `progressPin` envelope, with an ETag for the current run version and `Cache-Control: no-store`. Conditional read headers are rejected. The `progressPinRequest` wire body for PUT is exactly `{pinned: boolean}`, at most 1024 bytes, with duplicate JSON keys and unknown fields rejected. Authorization precedes body parsing. PUT requires the existing same-origin JSON mutation policy, cookie session, CSRF token, one strong If-Match version and one 16–128 character idempotency key. Caller-supplied actors, query parameters and extra conditional headers are rejected.

Successful changes and no-ops use the durable receipts described in [pin audit/replay](web-pin-audit.md). An exact replay returns the original pin/version and ETag with `Idempotency-Replayed: true`; it may describe an earlier result than a subsequent GET. It never rolls current policy or an owned task backward. Reconcile with GET before a new action. Missing If-Match returns 428, stale fresh requests 412 VERSION_CONFLICT, reused keys with different intent 409 IDEMPOTENCY_CONFLICT, and protected receipt capacity 429 PIN_RECEIPT_CAPACITY. Uncertain publication returns an unavailable/recovery response, not success.

The generated `progressPin`/`progressPinRequest` contracts and the client's guarded `put` method support this endpoint. The client performs one request without automatically retrying ambiguous mutations. The authenticated attempt page now provides explicit read/pin/unpin controls with fresh-read reconciliation. Audit presentation and denied/failed-request audit coverage remain unfinished; successful policy receipts alone do not complete #177.

Private bootstrap now includes an optional `runtime.progressRetention` sample with enabled configuration, sample time, completed attempt checks, expired journals, failed checks and the last diagnostic code. Runtime displays this process-local sample from the last session check without launching another probe. The SPA `terminalEventRetentionMs` value is 86400000: the threshold for timed expiry, not a guarantee against earlier size/count eviction or a maximum scan delay. See [production retention](web-progress-adapter.md#spa-production-retention-and-sampled-status).


### Recorded repair validation case comparisons

The embedded repair-history view can inspect the selected canonical normal-validation
receipt using the existing checked artifact listing and request-wide byte allowance.
The source/corpus/proof bindings are checked before case projection. A closed ordered
sequence of one build scope and one reference/candidate pair per corpus input supplies
exact exit-code, standard-output and standard-error comparisons. Canonical base64 is
validated and compared without allocating another complete decoded output payload.
Before deriving outcomes, the selected case reader reuses the canonical pure sandbox
binding verifier. It recomputes the ordered field digest, rejects empty or duplicate
inventories, checks the contained-launch flags, and binds the nonempty command,
executable runtime manifests and single writable authority to each scope's records.
Self-consistent receipt hashes cannot replace those checks. These are retained-record
consistency checks and confer no execution or acceptance authority.
Matching ordinary nonzero exits remain matching comparisons; folded signal-like exits
cannot establish a runtime failure or crash cause.

Case identities use the same opaque corpus-bound identity as retained repair cases.
The table includes at most twenty rows and finite byte counts. Each compared output
stream has a preview of at most its first 128 bytes. Hexadecimal preserves every
retained prefix byte; escaped UTF-8 text is also shown when that prefix is valid.
An incomplete UTF-8 character at a truncated boundary stays in hexadecimal only;
malformed bytes are never replaced to manufacture a text preview. Backslashes,
line endings, tabs and control characters are escaped in text. Every preview states
its observed size, displayed byte count and whether it is complete or truncated.
Empty observed output stays distinct from unobserved case output. Comparison still
uses the entire retained byte sequence without normalization, so equal previews
cannot conceal a mismatch outside the prefix. Separate
`historyValidationPage` navigation retains the selected graph, report run and evidence
owner; pages beyond the captured count show an explicit out-of-range state and a
graph-bound return link. History and retained-case-reference pagination stay separate.

Empty scope evidence is unavailable. Missing, foreign, duplicated, misordered or
inconsistent scopes withhold case comparisons. Compile failure and compile-only
validation leave case pairs unobserved; neither becomes a skipped or successful run.
Fatal diagnostic phase/position identifies an enclosing producer operation and does
not prove that a child process started or completed. The normal case table does not
infer those fatal outcomes.

This is read-only presentation of retained evidence. It does not add execution or
acceptance authority. The versioned normal-operation report and case pages described
below do not complete fatal-case outcome production or source links
to the validated snapshot. Native actor attribution,
physical resource bounds, positive authentication and decompilation effectiveness
require their own evidence.

### Selected recorded validation reports and case pages

The private `GET`/`HEAD R/reports/revision-validation` route projects the existing v1
`report` contract from one selected recorded normal validation operation. Supply
`historyGraph=<64 lowercase hex digits>` and exactly one of
`historyEvidence=<attempt reference>` or `historyRunEvidence=<repair-run reference>`.
The latter selects that repair run's recorded baseline validation, not its latest
workflow outcome. Optional `historyPage` selects the same fixed20-owner history
window used by recorded inspection. Optional canonical `historyValidationPage` selects
one20-case comparison window independently of the history-owner window. Duplicate,
foreign, noncanonical and missing selection parameters are refused before capture.
Case-reference pagination does not apply to this endpoint.

The controller applies the existing session, method and JSON negotiation boundary.
Graph/owner selection precedes report inventory or payload work. Only the selected
normal primary and required derived diff are resolved through the existing checked
report inventory and descriptor-backed reader. Their captures share the existing
64 MiB recorded-evidence allowance; failed reads consume their reservation. One
capture/projection is admitted at a time. Both the captured graph digest and selected
durable attempt version are rechecked after reading; changes return an explicit409.
The common response writer retains the1 MiB JSON ceiling and private no-store headers.
These are application admission/byte bounds, not physical RSS or latency qualification.

`state` distinguishes unavailable bytes (`unknown`), unavailable required scopes or
diffs (`partial`), unsupported declared producer versions (`unsupported`) and corrupt
or inconsistent evidence (`invalid`). Their summary is null. A normal receipt
is not inferred from an owner alone: no normal receipt remains `unknown` with a null
producer version. A `partial` normal report identifies the supported producer schema.
A checked normal receipt can be `available`: compile failure reports `failed`, compile-only reports `unknown`,
and complete behavior comparisons report `passed` or `failed` from all retained paired
bytes. Exact completed-pair counts are decimal strings; the source digest and candidate
reference come from that operation's graph-bound proof. A report ID binds the selected
job, durable run, graph, evidence-owner kind/reference and primary digest. It cannot
silently name a later report or edited source. Out-of-range comparison windows return
an explicit400 after checking the captured scope population.

An available normal report includes optional v1 `validationCases`. Older reports
without this extension remain readable; an unavailable, incomplete, unsupported or
invalid report carries null case detail. Every page identifies its graph, owner kind
and reference, source and corpus digests, exact comparison policy, global input/match
counts, window/continuation numbers and stable case identities. At most20 rows retain
four128-byte output prefixes each. Exact byte counts remain decimal strings. Each
preview carries canonical hex, strict escaped UTF-8 when available, consumed/prefix
byte counts and a truncation flag. Identical truncated prefixes can still belong to
different full outputs. Compile-failed and compile-only rows retain null comparison,
byte-count and preview fields; they are not skipped or successful behavior executions.

The shared Python wire checks and SPA decoder enforce population/window/ordinal
consistency, source association, bounded preview geometry and canonical hex, exact
empty/unobserved distinctions, full-summary/page consistency and comparison flags.
When both prefixes cover complete streams their equality must match the recorded
comparison flag; truncated prefixes cannot decide full equality. These metadata
checks do not independently authenticate the receipt or certify native execution.

Every response has observation authority and `acceptance: "not-evaluated"`.
No accepted artifact, raw command, host path, credential, source-artifact download URL
or unverified fatal-case result is manufactured. A source commitment is not a navigable
validated-source snapshot. Fatal outcome production, bounded mismatch-centered diff
windows, validated-source navigation,
complete export and new physical HTTP/browser qualification remain required by their
original owners. Twenty-one API controls use authored DTOs and callbacks only; three
shared wire fixtures and three pure decoder controls cover the new protocol boundaries.
The original41 case-control bodies and actual execution fixtures are unchanged.
The new source awaits its own ordinary Actions and review.

### Validation history discovery and SPA selection

The private `GET`/`HEAD R/validation-history` response uses the closed v1
`validationHistory` envelope. An initial read needs no query. `historyGraph` pins a
continuation to the captured graph; canonical `historyPage` selects a fixed window
of at most 20 finalized attempts, 20 repair-run baselines, 20 recorded failed
operations from those repair runs, and one pending attempt on the
latest page. These are operation families within the selected durable run, not
additional jobs or runs to execute. All other selection parameters are refused.

The producer reads existing history metadata with graph and durable-attempt version
checks around the capture. It does not read a selected receipt or source body.
`hasReceipt` records metadata presence only. `canInspect` additionally requires
disclosed owner and candidate identities; withheld references cannot select evidence.
Each inspectable owner carries the source and corpus commitments of its own recorded
operation. An older receipt corpus can differ from the history's current corpus.
Absent and unavailable history remain distinct states with null graph, population
and navigation fields. Discovery and receipt projection share one admission slot.

The attempt SPA provides explicit history reads, operation selection and case-page
navigation. Each response must match the requested job, durable run, graph, owner,
candidate, source and selected receipt corpus. Case continuations also retain the
report identity. Obsolete reads are aborted on selection/context changes or unmount;
failed, denied and unverified reads clear the displayed evidence. There are no
automatic reads or retries in this panel. Output prefixes render as escaped text,
with exact byte-count strings, explicit truncation and absent/binary/empty distinctions.

Eight new metadata controls use DTOs and callbacks. Two shared discovery fixtures,
two decoder controls, eight in-memory fetch/JSDOM controls and one existing-session
route control cover this addition. These are authored component and protocol controls;
they do not establish physical browser/HTTP, authentication, native cleanup or ACP
decompilation effectiveness. The original acceptance scopes remain open until their
required evidence is available. This source still needs its own Actions and review.

### Selected failed-operation diagnostics

`R/reports/revision-validation?historyGraph=<digest>&historyFailureRun=<run>`
explicitly selects a repair run's recorded failure diagnostic. This selector cannot
be combined with an attempt or baseline selector. History discovery uses the distinct
`run-failure` owner kind and a finite `failureKind`; its candidate/source/corpus can
differ from that same run's baseline. Only the first diagnostic page is supported;
no case-page continuation or case comparison result is invented for a fatal receipt.

Normal and failed-operation capture share the existing checked inventory/target
resolver, descriptor-backed reader, 64 MiB request allowance, graph and durable-version
brackets, and single admission slot. The selected receipt and its required diagnostic
are separately byte/hash checked against the invocation-owned binding. Their source,
corpus, runtime, classification, candidate and invocation association must agree.
The disclosed input population is rederived against the selected historical corpus.
Missing primary bytes remain `unknown`; missing required diagnostics are `partial`;
unsupported declared versions and inconsistent evidence remain distinct refusals.

An available report carries optional closed `validationFailure` with
`authority: "producer-diagnostic"`, graph/owner/source/corpus bindings, finite reason
and enclosing phase, exact decimal input/count strings, optional one-based input
position and explicitly producer-reported cleanup. The report summary and
`validationCases` are null, and repair acceptance remains unevaluated. Timeout,
resource exhaustion, cancellation, unverified cleanup and other validation failures
retain their separate producer labels. A before-case or original/rebuilt operation
phase requires a position matching the reported completed prefix. Earlier phases
cannot claim completed case pairs. No raw exception, command, path or peer text is
returned.

These diagnostics identify an enclosing producer operation. They do not prove which
child process started or failed, actual process absence, independent cleanup, or
successful case comparisons. Per-case fatal outcome production, partial comparison
inspection, skipped/unsupported case evidence, bounded difference windows, source
navigation and complete export remain required in the original full scopes.

The SPA offers an explicit failure action, verifies the selected bindings and clears
unverified evidence. Eighteen added DTO/callback methods, four shared wire fixtures,
two decoder controls and four mocked-fetch/JSDOM controls cover this extension.
They do not add actual execution contexts or physical qualification. Own Actions,
generated drift verification and automatic review are still required.

### Validation source snapshot links

A checked normal case report or failed-operation diagnostic offers an explicit
source-resolution action. Repair-graph revision references and durable workflow
candidate references have separate namespaces. The action reads the selected
workflow run and its retained result candidate's root source metadata, then requires
its recomputed input-source commitment to equal the selected validation's source
SHA-256. It offers a source link only after that match. Missing retained candidates,
nonterminal runs, unavailable metadata and mismatched job/run/revision/source values
leave the source link unavailable. The reader does not substitute a different
workflow run or infer source from a display label.

A matched link carries the exact observed `sourceSha256` and `metadataVersion` in
the application URL. Directory pages, breadcrumbs, file links, refreshes and line/
range navigation preserve this pair. Both first-page and continued directory/file
responses must match it; changed observations clear the displayed source metadata.
Incomplete, repeated, malformed and foreign query fields are refused before reads.
A pin by itself does not request source text or enable the preview control. Actual
bootstrap source-chunk advertising remains zero.

Metadata requests retain their existing API selectors and authorization. Explicit
source downloads and digest HEAD observations carry the captured `metadataVersion`
to the content endpoint. That optional query accepts one lowercase 64-digit digest;
other/repeated parameters are rejected. The existing checked capture compares the
metadata commitment before invoking any source-body callback. Legacy content reads
without the optional commitment remain supported. File identity, source SHA-256,
manifest roles, byte limits and digest/identity rechecks remain required.

The link identifies retained workflow source with the validation's exact source
commitment. It does not establish accepted reconstruction, independent file-content
verification, compiler/behavior equivalence or physical HTTP/browser qualification.
Historical repair revisions without corresponding retained workflow source remain
unavailable and still require the original full historical-source/retention scope.
Complete diagnostic locations, export and all other case/report families remain open.

Three added backend methods use authored metadata/bytes/callbacks only. Thirteen new
frontend controls cover pin parsing, route/range propagation, exact digest HEAD,
source resolution and in-memory session navigation without new actual execution
contexts. The original controller/native fixtures and source-chunk limits are
unchanged. This source awaits its own Actions and review.

### Retained validation receipt consistency

A normal selected validation result additionally checks the retained source inventory against the graph-bound source commitment and resource budget, and the canonical runtime configuration against its recorded digest, registered tool roles, normalized mounts and profile. Behavior comparisons recompute the original executable/input/exit/stdout/stderr observation digest across all cases and bind it to the selected durable repair run. Missing graph or reference metadata leaves the report partial; contradictory metadata is invalid. These checks also run when a caller selects a later case page.

Failed-operation reports recompute the retained source manifest and revision before attributing a diagnostic to the selected source. A failure before source capture, or a missing bound profile, leaves the report partial with no source-attributed failure detail. Such a report still provides neither per-case failure outcomes nor cleanup qualification.

Server-rendered history withholds case rows and output previews when required diff evidence or owner/candidate identity is unavailable or corrupt. Both the SPA decoder and Python wire verifier independently derive escaped text from the exact hexadecimal preview, including strict UTF-8, incomplete suffixes, BOM and control/format escaping. Partial selected validation reports cannot carry a result summary or case detail.

### Save a selected validation observation

The recorded-validation consumer offers an explicit JSON download only for an available observation bound to its selected job/run/revision, graph, owner, source and corpus. A normal export contains the currently inspected case page, including exact string counts, comparison flags and bounded previews. A failure export contains only the selected enclosing producer diagnostic, with no inferred case rows. The versioned export identifies its limited scope and preserves report identity; it is not a complete receipt, a full multi-page export, source content or an acceptance decision.

Export uses the already-read observation, rechecks the shared closed wire projection and presentation semantics, strips additive private fields, and imposes a 192 KiB UTF-8 limit before producing a JSON data download. It makes no additional request or execution admission. Loading another page, refreshing, a denied read or a changed attempt removes the prior download with its prior observation. This does not qualify actual browser/download behavior, full validation export or physical D0 resource limits.

### Navigate directly to recorded mismatch pages

Available normal case detail now reports optional nullable `firstMismatchPage`, `previousMismatchPage` and `nextMismatchPage`. The producer computes these across every input pair in the same fully checked receipt before exposing a page, retaining only three page numbers. Multiple differences on one page yield one destination; all-match, compile-only and compile-failed observations report nulls. Corrupt or missing required evidence still withholds all case detail and navigation. Ordinary page membership, counts, exact-byte comparisons, previews and source/corpus bindings are unchanged.

The SPA and server-rendered history offer explicit first/previous/next mismatch-page actions through the existing selected-evidence route. Actions retain the graph, owner and report identity, keep at most twenty surrounding cases on each page, and never execute validation. Both wire consumers reject incomplete navigation groups, invalid directions/windows and contradictions with reported or visible differences. Older v1 producers may omit the entire group and retain ordinary paging; missing metadata never means no differences. Selected-observation JSON exports preserve recognized navigation metadata. This is bounded inspection of normal comparisons, not classification of unseen fatal child outcomes or physical HTTP/browser/resource qualification.

Available behavior comparisons with at most 10,000 inputs also carry an optional nullable `comparisonIndex`. Its `referenceObservationsSha256` is the checked durable digest of the original binary, ordered input identities and complete reference exit/stdout/stderr observations. `mismatchBitmapHex` encodes one bit per input ordinal, least significant bit first within each byte, as canonical lowercase hexadecimal. Bit one means mismatch; zero means matched. The byte length is exactly `ceil(totalInputs / 8)` and unused high bits must be zero. The producer records these bits during the existing complete receipt scan and exposes them only after all source, sandbox, budget, output and reference checks succeed. The maximum additional bitmap is 1,250 bytes / 2,500 hexadecimal characters; no additional receipt read or validation run is needed.

Both consumers check bitmap bounds, padding, complete mismatch counts, each visible case and any reported mismatch-page destinations. Compile-only/failed, incomplete, corrupt and out-of-range observations cannot supply a comparison index. Populations above 10,000 and older adapters without the extension remain inspectable through ordinary case pages, with cross-attempt comparison unavailable rather than inferred. An index preserves the existing `exact-bytes-v1` policy and observation-only authority; it does not establish repair acceptance, independent execution/containment or equivalence.

The SPA can retain one explicitly selected observation as a comparison baseline and compare it to another already-read observation. Compatibility requires the same job, run, captured graph, retained corpus, input count, exact-byte policy and complete reference-observation digest. Different source revisions are expected; a different corpus, normalization policy or reference behavior yields an incompatible message, never new/resolved regression claims. Re-selecting the same owner is not a second observation. The complete indexed population is classified into new, persistent and resolved mismatches plus inputs matched in both observations. Case ordinals are meaningful only within that exact ordered corpus.

Comparison windows show at most twenty positions per category, with local paging and explicit links to the selected observation's ordinary case pages for stable IDs/previews. Pinning and comparison paging issue no requests. Swapping the two sides uses the existing read-only selected-evidence route with the original history page, graph, owner and report identity. A new history refresh, denied/invalid read or job/run/transport binding change removes the saved baseline; compatible history pagination can retain it. The download can contain the recognized full-corpus index alongside the selected case details, with an explicit limitation that unselected details/full outputs are absent. Authored DTO/JSDOM controls are separate from physical HTTP/browser/large-resource qualification.

Normal case inspection also applies the canonical retained-input shape and budget contract to the receipt itself. IDs must be unique, sorted, nonblank and NUL-free; arguments must be NUL-free. The complete input count, argument count and combined UTF-8 ID/argument plus decoded-stdin bytes must fit the selected graph budget, including inputs outside the visible page. The archive verifier and normal reader share this pure metadata check. Receipt and corpus hashes alone do not admit out-of-policy inputs. A violation withholds every comparison, summary and compact index; it does not execute a case or alter the separate enclosing-failure projection.

Normal case inspection shares the archive verifier's exact executable metadata policy: the closed field set, recorded binary digest, reference/candidate role, immutable mode 320, positive integer byte length and runtime manifest digest must agree before any case detail is exposed. Failed-operation details with retained source and graph context also validate the complete runtime configuration against its recorded digest, canonical shape, registered tool roles, normalized mounts and selected profile. Copying the bound runtime digest into an inconsistent receipt does not admit a producer diagnostic. These checks read retained metadata and do not launch a process or read executable bytes.

For failed operations, the producer's exact empty source-snapshot object means source capture did not complete. It is treated as unavailable, like a legacy null snapshot, and yields a partial report without source-attributed failure labels. Nonempty malformed snapshots remain invalid. Before exposing details for retained source, the reader also requires the exact graph/host behavior-budget evidence and checks that the source quota's mount commitment equals the runtime's normalized source mount. Coherently bound metadata preserves the existing finite enclosing-operation diagnostic; it does not establish case comparisons or cleanup.


### Optional job snapshot navigation metadata

The shared v1 page shape permits `currentCursor`, `previousCursor` and `pageNumber`. Job responses
from this server provide the complete triplet. `currentCursor` selects the returned page,
`previousCursor` is null only for page one, and `pageNumber` is a bounded one-based display value.
Clients treat cursor bytes as opaque and return them with the same filters and page limit.
Legacy responses may omit the entire triplet; partial or contradictory job metadata is rejected.

First pages, including empty results, have a signed zero-offset return cursor. All tokens retain
the existing session, normalized query, limit, HMAC and process-local expiry checks. Current and
previous tokens do not rescan storage or execute workflows. Snapshot count/byte/scan/admission
limits remain unchanged; invalid, expired and evicted cursors retain explicit error responses.
