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


The packaged upload-mode journey passed against `f4b896e`, including history client
navigation from an attempt, direct reload and an explicit missing-job limitation,
with no mutation requests from those views. Existing attempt and upload/recovery
checks also passed. [Retained history report](evidence/web-attempt-history-20260905.json).
Pinned Chrome used test-only --no-sandbox. Populated multi-page history in an actual
packaged browser remains unqualified; bounded populated behavior is covered by the
JVM and component fixtures described above.


## Populated packaged history qualification

The `history` mode of `scripts/check-packaged-web-browser.mjs` now seeds one
synthetic ELF-header job with 55 terminal attempts before launching the installed
JVM. The test-only generator lives in `scripts/packaged-browser-history.mjs`, is
not shipped as a production workflow, and refuses an existing destination root.
Run IDs, timestamps, outcomes, limits and usage are deterministic. The required
stored binary path is derived only inside the disposable test installation's data
root. No user binaries, providers or execution adapters participate.

The real browser and HTTP service traverse 50 then 5 exact identities, restore the
second-page cursor after reload, open and reload an earlier completed candidate,
and follow its previous interrupted attempt. The page preserves unsigned maximum
usage as `18446744073709551615` and distinguishes null usage and unaccepted output.
Every recorded attempt has no accepted reference; this does not test accepted
publication attestation. All three retained fixture files and the job directory's
entry set remain unchanged after browsing, and all view requests are GET/HEAD.

[Retained passed report](evidence/web-populated-history-20260905.json) supersedes
the earlier populated-history coverage limitation. It also includes session,
asset-recovery and missing-route checks. Pinned Chrome used test-only --no-sandbox.
This is packaged integration coverage with inert persisted fixtures, distinct from
mock transport tests and from live workflow execution. Evidence/source/artifact
navigation, active history changes and broader fixture families remain outstanding.


## Earlier-attempt and accepted-work navigation

Each attempt-history row now links that exact attempt's **Activity** and **Evidence and
report snapshots** views, and its result revision's source browser when a result revision
is recorded (a row without one says so). Link names include the attempt and revision
identities, so rows stay distinguishable to assistive technology. These are the existing
read-only routes; no request is made until a link is followed.

The job overview has a **Current and accepted work** section that keeps the two apart:

- **Latest attempt** links the latest recorded attempt's activity and evidence. Its
  progress and reports belong to that attempt only.
- **Accepted reconstruction** reads at most two newest-first history pages (100 attempts)
  to find the attempt whose own recorded acceptance is exactly the job's
  `acceptedRevisionId`. A candidate with the same revision identity but no recorded
  acceptance, or an attempt accepted for another revision, is never substituted. When
  found, it links that attempt, its evidence and report snapshots, and the accepted
  revision's sources. Otherwise it states that the attempt is not among the newest 100
  and points to attempt history. A read failure is an alert with an explicit retry and
  shows no attempt. With no accepted revision, no history read is made.

Browser history restores the saved history page after opening an earlier attempt or one
of its named views, and Forward returns to that view. This is covered by
`frontend/tests/attempt-navigation.test.tsx` and by the packaged `history` journey in
`scripts/packaged-browser-history.mjs`. The general artifact catalog (progress journal,
manifest, build contract, source archive) is not linked yet; it depends on the catalog
route proposed in #1698. Per-attempt artifacts reachable today are the exploration and
validation reports in the evidence view and source-file downloads.

## Recorded harness identity

The attempt metadata includes its persisted `harnessCapabilityId` beside the
recorded workflow identity. It is an opaque public capability ID, not a current
server selection or a reconstruction of private configuration. The v1 response
decoder requires a canonical ID or null. An explicit null is shown as not recorded
for that attempt. A malformed or non-string value rejects the entire response;
the page clears unverified attempt metadata and presents its standard error.
It never infers evidence-only mode, provider choice, authentication, availability
or acceptance from this field.

The row uses the same job/attempt/session/deployment-bound retained metadata as
the rest of the page: a same-identity transient refresh may keep it, while an
unverified/refused/different-identity response clears it. No new read, command,
preflight, adapter registration or automatic retry is introduced. Server defaults,
workflow launch, immutable submitted configuration across all choices and actual
packaged/assistive-technology qualification remain separate full requirements.

Nine additional consumer controls cover exact recorded identity, explicit null,
invalid values and refresh retention/refusal. They delegate attempt reads through
the actual API client and response decoder using bounded mocked HTTP responses,
including malformed fields that reject and clear the whole attempt. These source
controls require their own Actions qualification; no local subject was run.
