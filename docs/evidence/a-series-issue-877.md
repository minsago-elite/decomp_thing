# A-series issue #877 — Derive COMDAT selection and discard reasons from raw evidence — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-877` (branch `a-series-issue-877`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Derive COMDAT selection and discard reasons from raw evidence

## Acceptance criteria (from issue)
See `gh issue view 877` for the authoritative checklist. This PR does not close #877; it retains the gap for follow-up qualification.

## Method
- Read issue #877 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #877 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Derive COMDAT selection and discard reasons from raw evidence.

Focused child of #123; owns source acceptance criterion 5.

## Acceptance criteria

- [ ] COMDAT selection and discarded definitions are visible with reason codes derived from ELF/DWARF evidence.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #123; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=123 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #877.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-877.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
