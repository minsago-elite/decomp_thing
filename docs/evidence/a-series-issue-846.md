# A-series issue #846 — Qualify Clang frontend comparisons across valid and invalid subsystem cases — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-846` (branch `a-series-issue-846`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Qualify Clang frontend comparisons across valid and invalid subsystem cases

## Acceptance criteria (from issue)
See `gh issue view 846` for the authoritative checklist. This PR does not close #846; it retains the gap for follow-up qualification.

## Method
- Read issue #846 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #846 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Qualify Clang frontend comparisons across valid and invalid subsystem cases.

Focused child of #114; owns source acceptance criteria 1, 2, 4.

## Acceptance criteria

- [ ] Compare exit status, normalized stdout/stderr, dependency output, and emitted artifact bytes/structure.
- [ ] Exercise valid and invalid programs across subsystem shards.
- [ ] Prevent normalization from hiding semantic differences.

## Dependencies and evidence

Consume #121 diagnostic, #126 preprocessing and #124 code-generation case contracts; this task integrates actual authenticated reference/candidate observations, not caller-supplied JSON.

Reuse the implementation and retained checkpoints in #114; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=114 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #846.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-846.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
