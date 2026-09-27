# A-series issue #864 — Reconcile emitted RVAs and every shard without missing or duplicate ownership — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-864` (branch `a-series-issue-864`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Reconcile emitted RVAs and every shard without missing or duplicate ownership

## Acceptance criteria (from issue)
See `gh issue view 864` for the authoritative checklist. This PR does not close #864; it retains the gap for follow-up qualification.

## Method
- Read issue #864 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #864 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Reconcile emitted RVAs and every shard without missing or duplicate ownership.

Focused child of #120; owns source acceptance criteria 4, 5.

## Acceptance criteria

- [ ] Reconcile every emitted function/global RVA to exactly one shard and truth record.
- [ ] Detect missing, duplicate, stale, empty, and unexpectedly merged shards.

## Dependencies and evidence

Depends on #863.

Reuse the implementation and retained checkpoints in #120; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=120 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #864.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-864.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
