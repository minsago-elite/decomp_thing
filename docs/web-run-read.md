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
reconstruction retained elsewhere on the job. The page does not yet provide an
attempt collection, event stream, source/artifact/evidence navigation or workflow
controls. Following a previous-run link is not a complete paginated attempt history.

Verification includes HTTP authorization, interrupted startup projection,
job/run mismatch and missing-run rejection, strict query handling, read-only
metadata preservation, unsigned precision and candidate/acceptance separation.
Frontend fixtures cover exact deep links, prior-attempt links, absent usage,
logout clearing, aborted reads and rejection of a different job response. JVM SPA
checks serve pinned attempt routes. Packaged populated-attempt qualification remains
outstanding; the packaged browser check covers the missing-attempt route and reload.
