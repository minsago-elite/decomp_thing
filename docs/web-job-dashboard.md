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


The final packaged browser run passed with the new upload direct-link/reload checks,
existing job dashboard/upload journeys, and asset-recovery visibility. Early route
focus exposed a delayed-notice scroll regression; the notice now scrolls into view
when it appears without taking keyboard focus. The driver separately verifies that
client navigation adds no document request and that explicit reload adds one.
[Retained report](evidence/web-upload-route-20260905.json); pinned Chrome used the
test-only no-sandbox option. The final frontend suite still passed all 184 tests,
lint and the rebuilt typechecked distribution.


## Dashboard acceptance audit

The current dashboard has concrete evidence for exact row fields, fixed newest-first
sorting, URL filters/reset, bounded paging, stale/denied/error states, deliberate
refresh and separate job/run/accepted-revision labels. The new storage-failure
message distinguishes an incomplete backend read from transport failure; it never
pretends that the collection returned a complete or partial library successfully.

Focused checks now assert lossless size, distinct creation/update timestamps,
completed job state, latest run and an independently retained accepted revision.
A simulated backend change does not cause polling or reorder the focused row during
one minute; deliberate Refresh jobs then reveals new data. Existing component tests
page a synthetic 10,000-job source in batches of 50, restore filters, retain stale
rows on refresh failure and clear data on denial. JVM WebJobPages tests verify
bounded 10,000-row scans and stable snapshot rows across inserts/updates/deletions.

These checks do not prove the full accessibility/scale qualification recorded in
#168's earlier checkpoint or a 10,000-job packaged-browser workload. Keep #168 open
for those release checks; this audit does not equate small populated browser data
with full scale or assistive-technology qualification. Earlier-attempt and evidence
features have advanced under their own issues, without establishing full D3 parity.


The actual packaged history-mode journey passed assertions for the populated row's
64-byte size, creation timestamp, latest attempt, completed state, absent accepted
revision and durable nested job link, alongside filter/reload/reset and existing
history/evidence/download checks. [Retained report](evidence/web-dashboard-audit-20260905.json).
Validation: 194 frontend tests passed; the nine focused dashboard tests also passed
after a test-only lint fix. Lint, bounded JVM pagination checks and the rebuilt
distribution passed. Pinned Chrome used test-only --no-sandbox.

## Persisted 10,000-job browser workload — 2026-09-05

The packaged browser driver's `--mode scale` creates 10,000 private synthetic
job directories before starting the JVM. IDs, filenames and creation ordering
match the D0 generator's job identity scheme; each input is an inert 64-byte ELF
header, and every job remains uploaded with no attempt. This fixture does not
execute a compiler, binary or model. Unlike the NDJSON workload, it exercises
actual job-store recovery, authenticated HTTP listing and the shipped SPA.

The journey checks default-page search/no-match/reset and reload, then visits all
50 maximum-size pages (200 rows each), asserting every expected identity in
order. Native Enter activation advances each page and the results heading must
receive focus. An exact filename search finds an early job after traversing the
whole library and survives reload. The report retains observed page latency and
sampled renderer JS heap after each page; these include driver polling overhead
and are not cold-load traces, post-GC retained heap or full D11 qualification.

Reproduce with the pinned tools and a current `distZip`:

```sh
node scripts/check-packaged-web-browser.mjs --mode scale \
  --archive /absolute/llm_bin_patch-0.1.0.zip \
  --chrome /absolute/pinned/chrome --java-home /absolute/jdk \
  --work-parent /absolute/scratch
```

The first development run reached page one but timed out on page two because
the driver's synthetic Enter omitted carriage-return text. The driver was fixed
to use the same native event sequence as the existing upload keyboard check.
No application workaround or listing-budget increase was introduced.

The corrected run passed; retained report:
[`web-dashboard-scale-20260905.json`](evidence/web-dashboard-scale-20260905.json).
First observed page was 1,526 ms; the 49 continuation pages were 78–114 ms
(nearest-rank p95 111 ms). Sampled renderer heap peaked at 25,729,260 bytes
(24.5 MiB), below the 128 MiB initial-browsing reference budget. This single warm
journey does not prove the 20-cold-load latency budget; its first page exceeds
1.5 seconds and needs that dedicated qualification. JVM RSS, constrained-network
runs, concurrent clients, long-session growth and other D0 workloads remain
unmeasured here. Pinned Chrome used test-only `--no-sandbox`; installation
integrity, session cleanup and owned-process shutdown passed. #168 and #220
remain open for their outstanding requirements.

Verification also reran the existing packaged `history` journey successfully
(report `build/packaged-browser-QBiM8y/report.json`) after the shared driver
changes. Both JavaScript syntax checks and `git diff --check` passed. No
production code changed, so JVM/frontend unit suites were not rerun for this
test-driver checkpoint; both journeys used the previously verified distribution
identity recorded in their reports.

## Listing admission and budget feedback — 2026-09-05

The dashboard now distinguishes `LISTING_BUSY` (another collection is being
scanned; retry deliberately) from `LISTING_LIMIT` (no partial results returned;
filters may help, but a persistent limit requires storage attention). Narrowing
filters can reduce snapshot bytes; it cannot guarantee success when the scan
itself exceeds its time or record ceiling. Neither response triggers automatic
retry or silently substitutes an incomplete library.

Two component cases start with visible rows, fail a refresh with each code,
assert the specific guidance and stale-data notice, keep forward pagination
disabled, and recover only after another explicit refresh. All 196 frontend
tests, lint, typechecked bundle, asset checks and `distZip` passed. JVM behavior
is unchanged; existing `WebJobPagesTest` covers busy admission and over-budget
scan rejection. These cases do not establish full D11 over-budget handling for
other views.

The packaged 10,000-job scale regression also passed on the new distribution:
[`web-dashboard-limit-scale-20260905.json`](evidence/web-dashboard-limit-scale-20260905.json).
This proves the existing all-page/search/keyboard journey still works with the
new bundle; the injected busy/limit recovery behavior is covered by component
tests, not by the successful browser listing. Pinned Chrome again used the
explicit test-only `--no-sandbox` option.

## Exact date filter boundaries — 2026-09-05

Dashboard date ranges now compare integer nanoseconds instead of JavaScript
millisecond timestamps. Previously, a valid range whose endpoints occupied the
same millisecond was rejected as empty even though the server's `Instant`
comparison distinguished them. The parser preserves the submitted timezone and
fraction strings in the URL, validates calendar days (including leap years),
and accepts up to nine fractional digits. Impossible dates such as February 29
in a non-leap year are rejected before a request instead of being normalized by
`Date.parse`. Inputs use ordinary 00–23 hours and 00–59 seconds.

Frontend tests cover one-nanosecond ranges, equivalent timezone endpoints,
reversed/equal bounds, pre-epoch fractions, invalid dates and excess precision.
A JVM collection test proves inclusive lower/exclusive upper boundaries with
different timezone spellings at nanosecond precision. All 198 frontend tests,
lint, `WebJobPagesTest`, the typechecked bundle and `distZip` passed.

The scale driver now also submits filename, workflow status, page size and a
one-nanosecond date range through the actual controls. It checks that all
parameters remain in the URL and that exactly the expected stored job is
returned before and after reload. This extends filter correctness evidence;
selectable sort preferences and the remaining #168 requirements are still open.

The extended packaged journey passed; retained report:
[`web-dashboard-date-scale-20260905.json`](evidence/web-dashboard-date-scale-20260905.json).
All 50 pages remain reachable in order, keyboard paging retains its focus
handoff, and the combined date-filter case survives reload. Chrome used the
explicit test-only `--no-sandbox` option. These remain single-run measurements,
not the repeated cold-load or full accessibility/soak qualification.

## Persistent creation-order preference — 2026-09-05

The dashboard's Sort by control now supports Newest first (default) and Oldest
first. Applying the preference resets pagination and saves `sort=oldest` in the
URL. Reload restores the control and requests the first page in that order;
Reset filters returns to newest-first and the default page size. A sort-only
empty library is still described as empty, not as a failed filter match.

The authenticated collection API accepts only `newest`/`oldest`, uses creation
instant and job ID as deterministic tie-breakers, and binds sort to the retained
snapshot query. Reusing a cursor under another sort is rejected. Default ordering
is unchanged. Tests cover ascending tie order across pages, invalid/duplicate
sort parameters, cursor mismatch, control restoration and reset.

199 frontend tests, 133 JVM web tests, lint, syntax checks and the typechecked
`distZip` passed. This supersedes the earlier note that selectable sort remains
unavailable. The browser scale journey also checks the first two oldest-first
pages against the 10,000-job fixture, reloads to the first page, and resets to the
50-row newest-first default. Broader accessibility, background-update behavior
and D11 performance qualification remain separate outstanding work.

The extended packaged journey passed; retained report:
[`web-dashboard-sort-scale-20260905.json`](evidence/web-dashboard-sort-scale-20260905.json).
Together with the combined-filter reload checks, this verifies #168's parameter
persistence/reset criterion. Chrome used the explicit test-only `--no-sandbox`
option; all remaining scale measurement limitations still apply.

## Stable return to the first page — 2026-09-05

Previously, returning from page two to page one sent a new cursorless request,
which admitted a new snapshot and could show newly inserted jobs midway through
navigation. The dashboard now retains its first bounded response for the current
filter/sort/refresh selection. Previous restores those rows and the results
heading focus without rescanning storage. Only one extra page (at most 200 rows)
is retained; later pages still use server cursors. Refresh, changed filters/sort
or a restored URL starts a new selection. Unmount discards the component state.

Access denial clears both visible rows and the retained first page. Previous is
disabled after a failed read, so it cannot revive private rows or hide an expired
snapshot error; Refresh remains the deliberate recovery path. A retained page
is historical like any displayed snapshot page, and following its next cursor
still checks server expiry and current session authority.

Tests change the mock library while page two is displayed, verify that Previous
shows the original first page without another read, then verify Refresh reveals
the new job. A denied-continuation case verifies private-row clearing and explicit
recovery. 200 frontend tests, lint, typechecked bundle, asset checks and `distZip`
passed. JVM code did not change, so JVM tests were not rerun at this checkpoint.

The packaged 10,000-job regression passed and verifies that returning to the
first oldest-first page restores its exact rows and results focus without a new
collection request. Retained report:
[`web-dashboard-previous-scale-20260905.json`](evidence/web-dashboard-previous-scale-20260905.json).
The concurrent insertion is tested in the component fixture; the browser check
uses the persisted static library. Chrome used test-only `--no-sandbox`. This
fix strengthens snapshot navigation, but does not establish background change
notifications or the remaining #168 accessibility/scale criteria.

## Dashboard accessibility tree and narrow reflow — 2026-09-05

The scale journey now checks the rendered dashboard at 390 and 320 CSS pixels
and rejects horizontal document/body overflow. Chrome's accessibility tree must
expose one main landmark, the named Uploaded jobs list, all three text-input
labels, all three selector labels and all five filter/pagination button names.
These are focused automated checks, not an axe audit or manual screen-reader
qualification, and do not establish all WCAG contrast/zoom/dialog requirements.

This audit also found and corrected a verification defect in the preceding
browser checkpoint: its request counter looked for `/api/v1/jobs?`, but the
driver deliberately strips query strings from retained request URLs. The old
zero-equals-zero assertion could not prove that Previous avoided a read. The
counter now matches the retained path and requires a positive count before
checking that Previous leaves it unchanged. The component test's independent
mock-call assertion was valid; the earlier browser request-count claim requires
the corrected run's evidence below.

The first reflow assertion compared scroll width with `innerWidth`, which missed
the vertical scrollbar's occupied width. Tightening it to compare against
`document.documentElement.clientWidth` reproduced a real failure: at a 320-pixel
viewport only 305 pixels were available, but the body and document remained 320
pixels wide (`build/packaged-browser-VmCrIm/report.json`). The body's `20rem`
minimum width caused this extra horizontal scrolling. Removing that minimum
lets the existing responsive layout fit the available width. The check keeps
the stricter available-width comparison rather than accepting the overflow.

The corrected packaged run passed on the rebuilt distribution:
[`web-dashboard-accessibility-20260905.json`](evidence/web-dashboard-accessibility-20260905.json).
At 390 and 320 viewport pixels the available widths were 375 and 305 pixels;
both document and body now fit those widths. Accessibility names/landmarks and
the corrected positive request-counter check passed alongside all existing
10,000-job paging/filter/sort checks. The typechecked bundle, `distZip`, driver
syntax and diff checks passed. Unit suites were not rerun for this CSS/driver
change; actual rendered-browser checks verify the layout. Chrome used test-only
`--no-sandbox`. #168 and #217 remain open for their broader requirements.
