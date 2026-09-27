# A-series issue #832 — Publish canonical and human full-tree accuracy reports — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-832` (branch `a-series-issue-832`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Publish canonical and human full-tree accuracy reports

## Acceptance criteria (from issue)
See `gh issue view 832` for the authoritative checklist. This PR does not close #832; it retains the gap for follow-up qualification.

## Method
- Read issue #832 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #832 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Publish canonical and human full-tree accuracy reports.

Focused child of #108; owns source acceptance criterion 5.

## Acceptance criteria

- [ ] Publish a concise human summary plus canonical machine report.

## Dependencies and evidence

Depends on #830, #831.

Reuse the implementation and retained checkpoints in #108; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=108 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #832.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-832.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
