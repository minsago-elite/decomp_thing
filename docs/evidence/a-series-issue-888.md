# A-series issue #888 — Define measured improvement and detect oscillating shard repairs — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-888` (branch `a-series-issue-888`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Define measured improvement and detect oscillating shard repairs

## Acceptance criteria (from issue)
See `gh issue view 888` for the authoritative checklist. This PR does not close #888; it retains the gap for follow-up qualification.

## Method
- Read issue #888 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #888 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Define measured improvement and detect oscillating shard repairs.

Focused child of #125; owns source acceptance criteria 5, 15.

## Acceptance criteria

- [ ] Detect oscillation, repeated no-progress candidates, and cross-shard regression.
- [ ] Specify the improvement ordering and oscillation key. A diagnostic disappearance that introduces a retained regression, changes frozen interfaces without migration, or moves errors across shards must not count as improvement.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #125; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=125 slice=4 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #888.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-888.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
