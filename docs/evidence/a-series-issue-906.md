# A-series issue #906 — Model proven indirect, virtual and thunk-mediated call targets — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-906` (branch `a-series-issue-906`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Model proven indirect, virtual and thunk-mediated call targets

## Acceptance criteria (from issue)
See `gh issue view 906` for the authoritative checklist. This PR does not close #906; it retains the gap for follow-up qualification.

## Method
- Read issue #906 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #906 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Model proven indirect, virtual and thunk-mediated call targets.

Focused child of #128; owns source acceptance criteria 4, 5.

## Acceptance criteria

- [ ] Indirect and virtual calls distinguish proven target sets, unresolved-but-observed calls, and truly unobservable targets.
- [ ] Thunk-mediated calls retain both the physical edge and normalized semantic target without double credit.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #128; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=128 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #906.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-906.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
