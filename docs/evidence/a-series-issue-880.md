# A-series issue #880 — Bind emitted artifact cases to exact inputs and stable full-file identity — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-880` (branch `a-series-issue-880`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Bind emitted artifact cases to exact inputs and stable full-file identity

## Acceptance criteria (from issue)
See `gh issue view 880` for the authoritative checklist. This PR does not close #880; it retains the gap for follow-up qualification.

## Method
- Read issue #880 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #880 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Bind emitted artifact cases to exact inputs and stable full-file identity.

Focused child of #124; owns source acceptance criteria 1, 7.

## Acceptance criteria

- [ ] Lock compile argv/environment and all inputs for each optimization/debug/PIC mode.
- [ ] Detect stale or substituted artifacts through full-file hashes and manifest bindings.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #124; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=124 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #880.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-880.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
