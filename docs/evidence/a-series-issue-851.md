# A-series issue #851 — Reproduce full-tree archive and manifest bytes across independent roots — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-851` (branch `a-series-issue-851`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Reproduce full-tree archive and manifest bytes across independent roots

## Acceptance criteria (from issue)
See `gh issue view 851` for the authoritative checklist. This PR does not close #851; it retains the gap for follow-up qualification.

## Method
- Read issue #851 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #851 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Reproduce full-tree archive and manifest bytes across independent roots.

Focused child of #115; owns source acceptance criterion 4.

## Acceptance criteria

- [ ] Reproduce both archive bytes and manifest hashes across independent build roots/runs.

## Dependencies and evidence

Depends on #849.

Existing dependency contracts: #63, #84, #109, #110, #112, #125, #136, #140. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #115; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=115 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #851.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-851.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
