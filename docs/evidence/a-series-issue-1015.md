# A-series issue #1015 — Generate accepted implementations for clang-lib-tooling — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-1015` (branch `a-series-issue-1015`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Generate accepted implementations for clang-lib-tooling

## Acceptance criteria (from issue)
See `gh issue view 1015` for the authoritative checklist. This PR does not close #1015; it retains the gap for follow-up qualification.

## Method
- Read issue #1015 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #1015 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Generate accepted implementations for clang-lib-tooling.

Focused child of #860; owns source acceptance criteria 1, 2, 3.

## Acceptance criteria

- [ ] Bind the current authenticated emitted population and exact module ownership for `clang-lib-tooling` before dispatch; the checked planning inventory lists 3 source modules, which is planning context rather than an emitted-function denominator.
- [ ] Generate every required implementation in this shard through the qualified bounded ACP workflow, preserving ABI/call/global/name interfaces. No placeholder returns, abort/no-op stubs, undeclared shims or reduced denominators may count as accepted implementations.
- [ ] Retain exact per-module source and ACP/validation receipts. Reconcile every required entity and record unresolved entities as release blockers; cross-shard interface changes require the existing invalidation authority.

## Dependencies and evidence

Existing dependency contracts: #63, #65, #67, #68, #69, #84, #109, #110, #112, #113, #115, #118, #122, #136, #858, #859. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #860; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=860 slice=24 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #1015.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-1015.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
