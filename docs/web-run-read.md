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
  acceptance, or an attempt accepted for another revision, is never substituted.
- The lookup is bound to the job observation it answers by durable version, not by attempt
  ID. Every history page must carry the contract's required `page.snapshotVersion`; a
  page without one, or two pages of one walk with different snapshots, is refused as an
  invalid response and no attempt is shown. For a job that was never labelled or archived
  (including records without organization fields), the job `version` is the exact history
  snapshot version, so history binds only when `page.snapshotVersion` equals it. A label or
  archive masks that version, so for an organized job whose version differs from the
  snapshot the section makes at most one further read of the job after history, and binds
  only when that read returns the same job and the version first observed; any new
  acceptance, even by the same latest attempt for the same revision, changes it. Attempts
  listed before the observed `latestRunId` are also skipped, and older accepted attempts
  behind a running or failed latest attempt are still found. Otherwise, including when the
  observed latest attempt is not listed within the bound or the job was observed with no
  attempt but history lists some, the section says history changed after the job was
  read, shows no attempt, and offers retry and attempt history.
- Retry from that state reads the job once before any history read, and the overview
  takes what it returns as a new observation. If the read fails, the failure is shown with
  no history read. One click therefore makes one job read, then at most two history pages
  and, for an organized job, one bracketing job read. Nothing repeats without another
  click or another applied job read.
- Each applied job read is a new observation, numbered in the order the page issued it,
  even when it reports a version seen before (a label set and then reverted restores the
  earlier version). A found or not-found answer is bound to its version's history, so a
  later observation of the same version reuses it and history is not read again, whether
  the read came from Refresh, a peer tab, an organization change or Retry; incidental
  renders never read. An unbound or failed state binds nothing: a later observation, even
  of the same version, gets one lookup of its own, at once or as soon as a lookup already
  reading settles, and the earlier state's Retry is withdrawn meanwhile. So **Refresh job**
  does read both again, as the unbound statement says. A Retry is owned by the state it was
  activated from: once any lookup starts after it, its late failure, stale result or
  response naming another job changes nothing shown and starts no read, so it cannot
  remove settled accepted links or move focus.
- The job page orders every job read it applies (Refresh, a peer-tab change, an
  organization change, and accepted-work Retry) by when it was issued: a response is
  applied only if nothing issued later has been applied, so a slow earlier Refresh never
  rewinds a newer Retry or organization result, whichever arrives first. The organization
  form's reread after a save is numbered when it is issued, through the same ordered read,
  so a newer Refresh or Retry is not rewound by it either. A superseded read only ends its
  own loading state, and a failure of a read superseded by a newer applied one settles on
  that newer observation instead of reporting a failure. The order resets with the page on session change
  or unmount. If the Retry job read fails, the next Retry repeats that job read before
  any history read.
- Before using a page, the lookup checks that each attempt ID appears once across the
  pages read. A page with a next cursor must be full. A continuation must contain at
  least one row and its next cursor must differ from the cursor used to request it.
  A failed check shows the lookup alert and offers Retry.
- When the lookup finds the accepted attempt, it links that attempt, its evidence and report
  snapshots, and the accepted revision's sources. If another page exists after the first
  two, the overview reports absence from the newest 100 only when it examined 100
  distinct attempts from the observed latest attempt onward. If it skipped newer rows,
  it reports reaching the two-page limit. When the history ends, it reports how many
  attempts it examined. Each absence message links to attempt history. With no accepted
  revision, the page makes no history read.
- Focus moves only when the person causes it. Retry moves focus to the status and then
  to the outcome, unless focus has moved elsewhere in the meantime; moving it out of the
  section withdraws that for good, even when the control it went to (such as **Refresh
  job**, disabled while it reads) later drops focus to the page. If a background
  refresh removes the focused accepted link, focus goes to the status that replaces it,
  including when the accepted revision changes or is cleared, but only when focus would
  otherwise drop to the page.

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
