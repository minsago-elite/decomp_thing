# Pinned workflow-attempt reads

Issues: #160, #167, #170. This checkpoint exposes existing durable attempts without
registering workflow execution or mutation endpoints.

`GET /api/v1/jobs/{jobId}/runs/{runId}` returns the shared v1 `run` envelope from
`WebJobService.getAttempt`. It requires the existing local session and JSON Accept
policy, rejects query parameters, and applies private no-store response headers.
The exact job/run association is checked in the durable snapshot; a missing run or
one belonging to another job returns 404. Reads never initialize an attempt or
execute a workflow. Startup recovery precedes serving, so unfinished attempts are
reported with their stored interrupted outcome. Legacy jobs have no invented run.

The projection includes lifecycle timestamps, previous/input/result identities,
terminal reason, recorded limits and optional usage. Every unsigned count remains
a decimal string; absent usage is null, including individually unreported fields.
A candidate result revision is distinct from acceptance. Only a trusted retained
acceptance reference produces `accepted`; without it the projection reports
`not-evaluated`, never inferred success or rejection. Private paths, raw diagnostics
and publication artifact internals are not part of this representation.

The SPA `/jobs/{jobId}/runs/{runId}` page works beneath the configured base path.
The job overview links its latest recorded attempt; the attempt page links a
recorded previous attempt. Navigation preserves exact identities in the URL and
never follows a newer latest pointer automatically. Refresh requests that same
attempt again. Status can change with its version; pinning identity does not claim
that an active run is immutable. Each response must match both requested IDs.
Obsolete reads are aborted and late responses ignored; session loss removes the
private view. Missing/invalid identities provide an explanation and the shell's
safe parent navigation.

Limits and usage are displayed without floating-point conversion. Missing values
are explicitly unreported, and completion is explained separately from accepted
reconstruction retained elsewhere on the job. The page does not yet provide an event stream, source/artifact/evidence navigation
or workflow controls. Paginated history is described below.

Verification includes HTTP authorization, interrupted startup projection,
job/run mismatch and missing-run rejection, strict query handling, read-only
metadata preservation, unsigned precision and candidate/acceptance separation.
Frontend fixtures cover exact deep links, prior-attempt links, absent usage,
logout clearing, aborted reads and rejection of a different job response. JVM SPA
checks serve pinned attempt routes. Packaged populated-attempt qualification remains
outstanding; the packaged browser check covers the missing-attempt route and reload.


The actual packaged upload-mode browser journey passed against `5da81bc`, including
a pinned missing-attempt direct request, reload, exact parent-job link and absence
of mutations. Existing session, asset-recovery, dashboard and upload cancellation/
retry checks also passed. [Retained report](evidence/web-run-route-20260905.json).
Pinned Chrome used the test-only --no-sandbox option. This does not qualify a
populated multi-attempt journey in the packaged browser.


## Version-bound attempt history

GET `/api/v1/jobs/{jobId}/runs` returns a v1 `runs` envelope with its explicit job
identity, rows and page metadata. Default 50, maximum 200 rows; the existing durable
store bounds a job to 1,024 attempts. Ordering reverses recorded admission order,
so identical timestamps do not cause unstable ties. A response remains below 1 MiB.
Only `limit` and `cursor` query parameters are accepted, with duplicate fields and
unknown filters rejected. POST remains unavailable and now returns method refusal
for this registered read route.

An opaque HMAC-authenticated continuation binds the session, job, limit, offset and
job-version digest. No page snapshots or cursor map are retained in memory. Each
page reads the bounded durable job snapshot; it is not a full job-root scan. If the
job version changed, a valid cursor receives 410 CURSOR_EXPIRED and must restart
from the first page. A modified cursor or changed session/job/limit receives 400
INVALID_CURSOR. Server restart invalidates its process-local signing secret.
An unchanged version permits repeatable pages; this is not a retained historical
snapshot across active state updates. Reads never mutate workflow state.

The SPA `/jobs/{jobId}/runs` route is linked from job overview and individual
attempts. It renders 50 rows, exact attempt links, separate state/acceptance labels,
explicit empty/denied/error states, first/next controls and deliberate refresh.
Cursor selection is URL state and participates in browser history. Invalidated
continuations retain explicitly outdated prior rows until refresh; denied access
clears them. Obsolete reads are aborted. There is no polling or automatic reorder.

Verification covers all 1,024 attempts without duplicate/omitted rows, cursor
replay, session/job/limit isolation, version expiry, empty histories and strict
queries. Shared schema fixtures reject duplicate and cross-job rows. Component
checks cover URL continuation and browser back navigation. Populated packaged
multi-attempt qualification and evidence/source/artifact navigation remain open.
