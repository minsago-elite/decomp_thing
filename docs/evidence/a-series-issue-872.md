# A-series issue #872 — Bind generated tables to authenticated generator inputs and actions — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-872` (branch `a-series-issue-872`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Bind generated tables to authenticated generator inputs and actions

## Acceptance criteria (from issue)
See `gh issue view 872` for the authoritative checklist. This PR does not close #872; it retains the gap for follow-up qualification.

## Method
- Read issue #872 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #872 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Bind generated tables to authenticated generator inputs and actions.

Focused child of #122; owns source acceptance criterion 2.

## Acceptance criteria

- [ ] Declare generated tables reproduced from authenticated source/generator inputs versus checked data, retaining producer/action/hash provenance.

## Dependencies and evidence

Existing dependency contracts: #64, #109, #110, #113, #115, #117, #118, #127, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #122; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=122 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #872.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-872.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
