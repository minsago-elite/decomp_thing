# A-series issue #867 — Complete the locked Clang diagnostic case and observation matrix — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-867` (branch `a-series-issue-867`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Complete the locked Clang diagnostic case and observation matrix

## Acceptance criteria (from issue)
See `gh issue view 867` for the authoritative checklist. This PR does not close #867; it retains the gap for follow-up qualification.

## Method
- Read issue #867 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #867 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Complete the locked Clang diagnostic case and observation matrix.

Focused child of #121; owns source acceptance criteria 1, 2.

## Acceptance criteria

- [ ] Cases cover errors, warnings, notes, fix-its, caret/range displays, option provenance, fatal errors, and diagnostic limits.
- [ ] Each case locks argv, environment, stdin/files, exit status, stdout/stderr bytes, and any serialized diagnostic artifact.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #121; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=121 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #867.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-867.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
