# Persistent job dashboard checkpoint

The authenticated workspace consumes `GET /api/v1/jobs`; the public shell performs
no job reads. Filename search, workflow state, inclusive creation start, exclusive
creation end and page size are submitted explicitly. Filters live in the URL and
survive reload. Reset filters is always visible. The fixed ordering is newest
creation instant first, then job identity; the backend owns sorting and filtering.

Each page renders at most 50, 100 or 200 job rows. Previous/next controls navigate
retained server snapshots without appending rows indefinitely. There is no
background polling or automatic reordering. Refresh jobs deliberately requests a
fresh snapshot. Loading, empty library, no matches, invalid saved filters, expired
snapshots, denied access and failed reads have explicit states. A failed refresh
keeps previously loaded rows with an outdated-state warning; denied access clears
them. A corrupt record currently fails collection admission instead of yielding a
partial page, as documented in [the collection contract](web-job-pagination.md).

Rows show exact decimal byte counts, original timestamp/time-zone strings, public
workflow state, latest recorded attempt and accepted revision separately. A count
labels jobs on the current page; it is not a library total or a run count. Completion
does not imply successful validation. After explicit pagination, keyboard focus
moves to the results heading; idle pages leave focused rows and controls in place.

`/jobs/{jobId}` is a persistent SPA route under the configured base path. Direct
loads, refresh and canonical trailing-slash redirects work for exact job-store
identities. Its authenticated detail read checks response identity and renders
ELF metadata, exact hexadecimal entry address and exact byte counts without
conversion to JavaScript numbers. An unavailable job has an explicit explanation.
Session loss removes private components and aborts their requests. Route/filter
changes abort obsolete reads; late completions cannot replace the newer result.

## Verification and remaining scope

At application commit `3c9df92`, 164 frontend tests pass, including a synthetic
10,000-job source served in 50-row pages, filter persistence/reset, stale/denied
reads, cancellation, idle focus, explicit-page focus and an authenticated nested
job deep link with logout clearing. All 108 JVM web/jobs tests pass; ZIP/TAR serving
gates cover the classpath asset closure and deep-link routing.

The dashboard browser driver additionally checks the real packaged empty library,
filtered no-match state, saved filters after reload, reset, and a missing-job deep
link/refresh. A retained passed report is needed to claim those browser results.

This does not complete #168 or #170. Populated-library packaged browser journeys,
full accessibility/scale qualification, richer formatting/preferences, earlier
attempt selection and evidence/source/artifact navigation remain outstanding.
The metadata API does not yet report an input digest. Workflow actions are still
unavailable in the production SPA; Runtime displays the server's capability
explanations. Streaming upload and lifecycle organization remain separate D3 work.


[Retained packaged browser evidence](evidence/web-dashboard-20260905.json) records
a passed run of those empty-library and deep-link checks against `3c9df92`, in
Chrome 149.0.7827.55 with pinned Node 24.20.0 and Java 21. The isolated test browser
used `--no-sandbox`. Exact ZIP/JAR/UI identities and source-report hash are retained;
this is not multi-browser or populated-library release qualification. Session
restoration/logout, credential-storage checks, Runtime snapshots and missing-chunk
recovery also passed in the same journey.


## Upload route and shell navigation checkpoint

The SPA now has a durable `/upload` route under the configured base path, alongside
the retained dashboard upload shortcut. Both render the same upload component and
use the existing tab-scoped retry ticket; navigation aborts an active transfer and
returning asks for file reselection instead of resubmitting it.

Global navigation exposes Upload. Secondary pages show an All jobs breadcrumb and
the current page. Page titles distinguish Jobs, Upload a binary, Job overview,
Runtime status and unavailable client routes. Titles contain no filename, source,
credential or raw failure details. Path changes focus the main landmark, including
history transitions between eagerly loaded views; query-only dashboard changes
retain the dashboard's own focus policy. Asset-recovery notices keep their existing
scroll protection.

The packaged JVM serves GET/HEAD `/upload`, canonicalizes its trailing slash, and
rejects POST to this presentation route. Upload mutations remain on the existing
API endpoints. The explicit frontend URL allowlist includes the new route.

Verification: 184 frontend tests and lint passed, along with 173 web/jobs tests and
the distribution build. New checks cover prefixed direct navigation, browser
history, current-navigation labels, titles, breadcrumbs, focus, inert public views,
and server route/method handling. Run/revision/tab routing and full D3–D9 workspace
navigation remain outstanding; this checkpoint does not complete #167.
