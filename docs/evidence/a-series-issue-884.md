# A-series issue #884 — Verify relocation, instruction, unwind and runtime mutation detection — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-884` (branch `a-series-issue-884`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Verify relocation, instruction, unwind and runtime mutation detection

## Acceptance criteria (from issue)
See `gh issue view 884` for the authoritative checklist. This PR does not close #884; it retains the gap for follow-up qualification.

## Method
- Read issue #884 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #884 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Verify relocation, instruction, unwind and runtime mutation detection.

Focused child of #124; owns source acceptance criterion 8.

## Acceptance criteria

- [ ] Mutation tests change one relocation, symbol binding, instruction operand, unwind entry, and runtime result.

## Dependencies and evidence

Depends on #881, #882, #883.

Reuse the implementation and retained checkpoints in #124; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=124 slice=5 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #884.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-884.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
