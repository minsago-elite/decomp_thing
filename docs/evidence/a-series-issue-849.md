# A-series issue #849 — Admit complete full-tree source and dependency provenance for archival builds — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-849` (branch `a-series-issue-849`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Admit complete full-tree source and dependency provenance for archival builds

## Acceptance criteria (from issue)
See `gh issue view 849` for the authoritative checklist. This PR does not close #849; it retains the gap for follow-up qualification.

## Method
- Read issue #849 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #849 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Admit complete full-tree source and dependency provenance for archival builds.

Focused child of #115; owns source acceptance criteria 1, 3, 5.

## Acceptance criteria

- [ ] Consume the complete accepted implementation/interface/module/runtime boundary from #118/#110/#113/#122/#127/#131.
- [ ] Bind every consumed source/header/generated input/tool/runtime dependency to the exact admitted archive revision.
- [ ] Include source/build/oracle/ACP provenance and bounded accepted/rejected repair history.

## Dependencies and evidence

Existing dependency contracts: #63, #84, #109, #110, #112, #125, #136, #140. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #115; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=115 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #849.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-849.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
