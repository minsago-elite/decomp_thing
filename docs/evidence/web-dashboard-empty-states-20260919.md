# D3 dashboard empty-state qualification (#498)

Scope: distinguish a successful empty/no-match response from an earlier empty
snapshot retained while a refresh is pending or has failed. This is focused
implementation and local verification evidence, not a full #168 release or
production accessibility qualification.

The prior dashboard showed `No uploaded jobs yet` or `No jobs match these
filters` whenever its retained data had zero rows, even while a new request was
loading or after it failed. It could therefore present an old empty snapshot as
the current result. The updated view only makes either empty assertion in the
ready state. During refresh it announces that the previous empty result may be
outdated; on failure it identifies the retained empty library or no-match
snapshot and says that current results are unknown until refresh succeeds.
Incomplete backend reads remain distinct from transport failures. Explicit
Refresh remains the recovery action; it does not invent partial results.

Verification on the #498 worktree:

- Dashboard component tests: 18/18 passed. New cases cover initial loading,
  empty library then transport timeout, filtered no-match then 503
  `JOB_RECORD_UNAVAILABLE`, retained-state wording, and successful recovery.
- Bun contract generation check, TypeScript no-emit, ESLint, Vite production
  build, and bundle report: passed. Bun's Vitest worker could not start in this
  sandbox (`getaddrinfo ENOTIMP`), so component tests used pinned Node 24.
- Complete pinned-Node frontend suite: 352/353 passed. The sole failure is the
  pre-existing upload-polling test `shows measured bytes separately from
  publication and stops progress polling with admission` (expected one `get`
  call, observed two). It also reproduces in the independent #499 worktree,
  which does not alter upload code; that test passes in isolation. This failure
  is not counted as a pass or attributed to the #498 change.
- `git diff --check`: passed. Independent read-only review found no blocking
  regression in the focused dashboard change.

Earlier retained #168 packaged-browser reports cover verified empty and
filtered no-match views. The new failure transition is component-tested here;
it has **not** been injected into a packaged browser run. No job mutation,
native analysis, or production account was used for this qualification.
