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

`Accept: application/json` (or `*/*`) selects JSON; streams require `text/event-stream`, and
downloads use their declared media type or `application/octet-stream`. JSON mutation bodies require
`Content-Type: application/json`; upload requires `multipart/form-data` with exactly one `binary`
part. No request to `/api/**` receives SPA HTML, including unknown routes, malformed requests,
exceptions and unsupported methods. Unsupported methods return `405` plus `Allow`; unsupported
`Accept` returns `406`, and unsupported request content type returns `415`. `HEAD` is permitted
only for immutable artifact download metadata, where its headers equal GET without a body.
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
| `GET /api/v1/uploads/{uploadId}` | `200 uploadProgress` | Ephemeral session-bound transfer bytes and publication phase; #169 |
| `POST /api/v1/jobs` | `201 job`, `Location: J` | Multipart, upload limits, idempotency; #162 |
| `GET J` | `200 job`, ETag | Snapshot read; #159/#160 |
| `PATCH J` | `200 job` | Allowlisted label/archive metadata, If-Match and idempotency; #173 |
| `DELETE J` | `202 operation` | Reviewed retention/deletion policy and If-Match; #172 |
| `GET J/runs`, `GET R` | `200 runs`, `200 run` | Bounded attempts or durable attempt snapshot; #160 |
| `POST J/runs` | `202 run`, `Location: R` | `workflowStart` request, capability/limits/input checks, job If-Match; #163 |
| `POST R/cancel` | `202 run` or `200 run` if already terminal | Idempotent recorded intent, run If-Match; #163 |
| `POST R/recover` | `202 run`, `Location` of a new attempt | Explicit `retry` or capability-gated `resume`; If-Match; #163 |
| `GET R/snapshot` | `200 snapshot`, ETag | Run state and consistent event watermark; #174 |
| `GET R/events` | `200 text/event-stream` | Resume with `Last-Event-ID` or `after`, never both; #174 |
| `GET R/events?transport=poll` | `200 events` | Same retention/cursor semantics, bounded page; #174 |
| `GET R/reports/{reportId}` | `200 report` | State may be missing/partial/unsupported/unknown; #165 |
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

Errors carry `code`, safe `message`, `retryable`, optional field-level `details` and
`retryAfterMs`; the correlation ID connects to redacted server logs. A detail contains a JSON
pointer plus stable code/message and never the rejected value. Resource existence is disclosed
only after session authorization. Raw exceptions, commands, environment, paths and credentials
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
`entry_point`; this legacy shape is not a v1 DTO. Execution POSTs still redirect.
The persistence serializer and stored `job.json` format are unchanged.
The HTTP regression in `UploadServerTest` checks both responses, an old private diagnostic,
exact public keys, retained field values and byte-for-byte preservation of stored records.
Legacy job HTML also withholds persisted `status_message` prose and displays a fixed
explanation when details exist. The job status itself remains visible. Generic request/storage
exceptions and unsupported-upload exceptions no longer supply raw text to HTML error pages;
those paths use fixed public messages. Typed service/access error messages remain available.
This leaves stored diagnostic bytes and background redaction behavior unchanged. It is a
privacy change for generic diagnostics, not a certification of report summaries or every
retained metadata label as public.

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
persisted, valid zero-event journal still returns 200. This does not add cursor replay or v1
session authorization to the legacy route, nor add a new event authority.

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
The two legacy JSON read routes (`/api/jobs/J` and `/api/jobs/J/events`) accept GET only.
Other methods return 405 with `Allow: GET` before storage reads; HEAD sends the same error
headers without a body. Unknown routes retain 404. GET shares v1's bounded Accept policy:
a missing header allows JSON; explicit JSON, `application/*` and `*/*` ranges are supported;
a more specific `q=0` exclusion overrides a broader wildcard. Nonmatching/malformed supported
ranges yield 406. Repeated Accept headers or a value over 512 characters yield 400. Errors
remain JSON even when the client excludes JSON. All these responses use no-store caching.
HTTP tests cover both route shapes, positive/negative media ranges, methods including HEAD,
header limits and unchanged records, including negotiation before damaged storage inspection.
The legacy upload Accept switch, mutation-route negotiation, deprecation links and shared
session boundary remain migration work; upload behavior is unchanged by read negotiation.

D2/D13 preserve the non-sensitive legacy success fields through the first D-series release and
at least one subsequent minor release, while documenting removal of `binary_path`, applying the
same session/content boundary and making API failures JSON. Do not silently change old numeric
fields to strings; clients needing lossless values migrate to v1. Expose deprecation and successor
links and publish the actual sunset release/date before removal. Existing persisted `job.json`
files stay readable through a versioned, recoverable migration; public response changes do not
rewrite raw report bytes. Legacy URLs redirect/map per the navigation/parity contract and never
auto-start a workflow. Unsupported legacy automation dependencies receive a documented migration
error, not an empty success response.

The optional upload progress transport, state semantics and bounded retention are defined
in [Server-observed upload progress](web-upload-progress.md). Progress identities are
fresh per transfer and do not replace durable idempotency keys.

### Current D4 JSON polling implementation

The current retained-journal adapter implements `GET jobs/J/runs/R/snapshot`
and `GET jobs/J/runs/R/events?cursor=...&limit=...` under the v1 prefix.
This is bounded JSON polling; `transport`/`after` parameters and SSE negotiation
from the target design above are not implemented. Snapshot `progress` metadata
makes queue/history omissions and retained-record counts explicit. Missing
journals fail with `PROGRESS_UNAVAILABLE`; replay gaps require a fresh snapshot
via `PROGRESS_GAP`. See [the implemented boundary and qualification limits](web-progress-adapter.md).

### Current scheduler snapshot

Authenticated bootstrap responses now include optional `runtime.scheduler` for
aggregate web workflow executor telemetry: approximate active/queued counts,
configured limits, lifecycle, source and server sample time. Borrowed executors
report unavailable metrics without zero values. Runtime uses the session-time
snapshot; it neither polls these counts nor infers workflow availability from
capacity. See [scheduler summary and verification](web-scheduler-summary.md).
