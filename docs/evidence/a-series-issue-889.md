# A-series issue #889 — Reserve cumulative shard and run budgets before external work — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-889` (branch `a-series-issue-889`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Reserve cumulative shard and run budgets before external work

## Acceptance criteria (from issue)
See `gh issue view 889` for the authoritative checklist. This PR does not close #889; it retains the gap for follow-up qualification.

## Method
- Read issue #889 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #889 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Reserve cumulative shard and run budgets before external work.

Focused child of #125; owns source acceptance criteria 6, 16.

## Acceptance criteria

- [ ] Enforce global/per-shard model-call, token, wall-time, patch-size, and rebuild budgets.
- [ ] Reserve cumulative budgets before each external call/rebuild and retain spent/reserved disposition after crash; exhaustion is persisted as blocked/exhausted without publishing stubs or discarding evidence.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #125; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=125 slice=5 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #889.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-889.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
