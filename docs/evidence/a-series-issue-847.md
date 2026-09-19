# A-series issue #847 — Bind Clang frontend mismatches to persistent cases and owning subsystems — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-847` (branch `a-series-issue-847`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Bind Clang frontend mismatches to persistent cases and owning subsystems

## Acceptance criteria (from issue)
See `gh issue view 847` for the authoritative checklist. This PR does not close #847; it retains the gap for follow-up qualification.

## Method
- Read issue #847 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #847 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Bind Clang frontend mismatches to persistent cases and owning subsystems.

Focused child of #114; owns source acceptance criterion 3.

## Acceptance criteria

- [ ] Attribute every mismatch to a persistent case and owning subsystem.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #114; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=114 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #847.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-847.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
