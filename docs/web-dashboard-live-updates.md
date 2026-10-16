# Focused dashboard rows during live updates

The dashboard reads a fresh bounded first page every 30 seconds after the
previous read settles. It keeps at most one live read in flight. Filters, sort and
page size use the same server query as an explicit Refresh; no client scan or
additional page is requested.

If job identities and order stay the same, the complete new snapshot replaces
the previous one without moving focus. This updates state and metadata with its
matching server cursor. If membership or order changes while focus is inside a
job row, the complete old snapshot and cursor stay together. A status notice
explains that newer results exist, and explicit Refresh applies the current
list and intentionally focuses the results heading. No incoming snapshot queue
or mixture of rows from different snapshots is retained.

When no job row is focused, a new snapshot may update membership and order
without moving the user's focus elsewhere on the page. Continuation pages keep
their immutable listing snapshot and pause live reads. The user can pause or
resume live updates. Hidden tabs pause timers and abort their active read;
navigation, filter changes, client changes and unmount cancel obsolete work.
Late responses from cancelled reads cannot replace current data.

A failed live read stops automatic reads until deliberate recovery and uses the
existing stale/empty/incomplete-storage guidance. Access denial clears private
rows and the retained first-page cache. Live reads do not start workflows or
infer accepted reconstruction from a changed job status.

## Verification scope

`frontend/tests/dashboard-live.test.tsx` adds ten controlled cases for the
30-second boundary, unchanged-order state/cursor updates, deferred complete
snapshots, new jobs, focus preservation, single-flight behavior, hidden and
paused views, cancellation, continuation pages, stale empty failures and access
denial. The existing dashboard tests remain unchanged.

The packaged `--mode live` journey uses the real JVM/API and production browser
timers with two authored inert jobs. The test atomically changes one job's state
and publishes one new inert job. It checks the focused link and row order after
each real background read, explicit refresh, the pause control, unchanged input
bytes and only the intended fixture record changes. It sends no mutation
request or workflow start. The test does not certify polling performance,
storage-quota concurrency, full WCAG compliance or production scale.

The CI packaged browser job runs this journey with scratch under repository
`build/`, alongside its existing verification. Local subject execution remains
on hold: no local tests, compilation, syntax checks or browser run are claimed.
Required Actions and automatic review must qualify the exact published source
before completion is recorded.
