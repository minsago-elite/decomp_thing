# A-series issue #863 — Reconcile source and generated compilation units under explicit prefix maps — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-863` (branch `a-series-issue-863`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Reconcile source and generated compilation units under explicit prefix maps

## Acceptance criteria (from issue)
See `gh issue view 863` for the authoritative checklist. This PR does not close #863; it retains the gap for follow-up qualification.

## Method
- Read issue #863 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #863 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Reconcile source and generated compilation units under explicit prefix maps.

Focused child of #120; owns source acceptance criteria 1, 2, 3, 6.

## Acceptance criteria

- [ ] Produce a canonical compilation-unit inventory bound to source lock and artifact manifest hashes.
- [ ] Normalize debug paths only through an explicit prefix-map policy.
- [ ] Reconcile every DWARF CU to one source/generated-source identity or an explicit exclusion.
- [ ] Record generated/tablegen inputs separately from handwritten source without losing ownership.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #120; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=120 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #863.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-863.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
