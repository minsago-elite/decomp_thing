# D3 bounded dashboard paging and keyboard recovery (#499)

Scope: one focused failure in the existing server-backed dashboard pagination.
Before this change, a failed continuation could render Page 1 rows while saying
"Page 2" and leave keyboard focus on a disabled Next button. The dashboard now
tracks the page actually displayed separately from the page requested. On a
failed continuation it retains the prior rows and truthful label, focuses the
safe error alert, disables paging, and offers explicit Refresh. Access denial
clears private rows and the retained first-page cache.

## Verification

- Focused dashboard component tests: 18/18 passed. New cases cover expired
  cursor and busy-listing continuation failures, truthful stale page labels,
  alert focus, denied continuation, and explicit recovery.
- Bun API contract check, TypeScript no-emit, ESLint, Vite production build,
  bundle report, and asset-manifest write/verify: passed. The manifest build
  ID was `c2d95f5b53eb50b9c93e08e7bba9e9d66432224bb6121e22a05af6c714e7a838`
  (9 resources, 146,289 bytes). Bun's Vitest worker could not start in this
  sandbox; the tests used pinned Node 24.
- Complete pinned-Node frontend suite: 352/353 passed. The sole failure is
  the pre-existing upload-polling test's one-GET assertion. It also fails on
  the independent #498 branch and passes when run alone. Existing issue #526
  and stacked PR #1068 track the upload-timer cleanup; that fix is not on
  `master`. This is not counted as a suite pass for #499.
- `distZip`: passed after raising the task-local Kotlin compiler daemon heap
  from 2 GiB (which ran out of heap on this clean worktree) to 4 GiB and
  limiting Gradle to one worker. Archive SHA-256:
  `4f88cbb460407bbbc85975728fdc705b7e30ac7f06db243d5e724b602047a0e8`.
- Real packaged Chrome 149 scale gate: passed. It traversed 10,000 inert
  persisted job identities in 50 pages of 200, verified exact row order and
  keyboard focus, then intercepted exactly one cursor-bearing collection read
  with a browser network failure. The 200 prior rows stayed labelled Page 1,
  the alert took focus, and explicit Refresh recovered the first page. The
  run sent no mutation request or workflow execution; installation bytes were
  unchanged, shutdown confirmed, and test-owned scratch cleaned. Chrome used
  test-only `--no-sandbox`. First-page observation was 2,102 ms, so this run
  does not establish the separate 1.5-second performance reference.
- `git diff --check` and browser driver syntax check: passed. Independent
  read-only review found the fix and failure injection in scope.

The local browser report is
`build/packaged-browser-xWzUzZ/report.json` in this disposable worktree,
with `status: passed` and explicit `scale.failedContinuationRetainsPageAndFocus`
and `scale.explicitContinuationRecovery` fields. To run on this filesystem,
which reports inode capacity as 0/0, the already-reviewed installer correction
from #497 / PR #1380 was temporarily overlaid for the browser run and removed
afterward; it is **not** in this #499 branch. The first unpatched browser
attempt stopped before extraction, and its owned scratch was cleaned.

This is one local packaged-browser and component qualification of accessible,
bounded pagination. It is not a manual screen-reader or complete WCAG audit,
constrained-profile scale result, multi-browser result, or full parent #168
completion. The #498 stale-empty-state PR touches nearby dashboard rendering;
both focused fixes require integration if one merges before the other.
