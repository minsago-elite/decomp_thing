# A-series issue #917 — Split bounded CI smoke from full target/resource qualification — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-917` (branch `a-series-issue-917`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Split bounded CI smoke from full target/resource qualification

## Acceptance criteria (from issue)
See `gh issue view 917` for the authoritative checklist. This PR does not close #917; it retains the gap for follow-up qualification.

## Method
- Read issue #917 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #917 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Split bounded CI smoke from full target/resource qualification.

Focused child of #130; owns source acceptance criterion 9.

## Acceptance criteria

- [ ] CI uses bounded smoke thresholds; periodic/manual production evidence uses the full matrix.

## Dependencies and evidence

Depends on #914, #916.

Reuse the implementation and retained checkpoints in #130; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=130 slice=4 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #917.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-917.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
