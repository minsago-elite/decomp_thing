# A-series issue #897 — Repeat stateful frontend cases under file, depth, output and time bounds — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-897` (branch `a-series-issue-897`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Repeat stateful frontend cases under file, depth, output and time bounds

## Acceptance criteria (from issue)
See `gh issue view 897` for the authoritative checklist. This PR does not close #897; it retains the gap for follow-up qualification.

## Method
- Read issue #897 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #897 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Repeat stateful frontend cases under file, depth, output and time bounds.

Focused child of #126; owns source acceptance criteria 7, 8.

## Acceptance criteria

- [ ] Repeated runs from clean workspaces produce identical evidence.
- [ ] Resource bounds cover file count, include depth, response depth, output bytes, and wall time.

## Dependencies and evidence

Depends on #894, #895, #896.

Reuse the implementation and retained checkpoints in #126; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=126 slice=4 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #897.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-897.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
