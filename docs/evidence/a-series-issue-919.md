# A-series issue #919 — Bind overload and alias references without merging incompatible types — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-919` (branch `a-series-issue-919`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Bind overload and alias references without merging incompatible types

## Acceptance criteria (from issue)
See `gh issue view 919` for the authoritative checklist. This PR does not close #919; it retains the gap for follow-up qualification.

## Method
- Read issue #919 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #919 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Bind overload and alias references without merging incompatible types.

Focused child of #131; owns source acceptance criteria 2, 5.

## Acceptance criteria

- [ ] Preserve overload prototypes and bind every call/reference to the correct identity.
- [ ] Prevent aliases from merging incompatible types.

## Dependencies and evidence

Depends on #918.

Existing dependency contracts: #64, #84, #109, #110, #113, #115, #118, #123, #127, #128, #129, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #131; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=131 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #919.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-919.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
