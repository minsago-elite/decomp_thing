# A-series issue #903 — Qualify C++ ABI probes against the pinned compiler with strict diagnostics — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-903` (branch `a-series-issue-903`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Qualify C++ ABI probes against the pinned compiler with strict diagnostics

## Acceptance criteria (from issue)
See `gh issue view 903` for the authoritative checklist. This PR does not close #903; it retains the gap for follow-up qualification.

## Method
- Read issue #903 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #903 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Qualify C++ ABI probes against the pinned compiler with strict diagnostics.

Focused child of #127; owns source acceptance criteria 8, 9.

## Acceptance criteria

- [ ] Compare ABI probe layout/dispatch/RTTI/unwinding observations with the pinned reference compiler.
- [ ] Pass strict-warning and relevant sanitizer fixture checks and retain canonical probe sources, reconciliation reports, and link/runtime logs.

## Dependencies and evidence

Depends on #898, #899, #901, #902.

Existing dependency contracts: #64, #67, #84, #110, #113, #115, #118, #122, #123, #124, #128, #129, #131, #132, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #127; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=127 slice=5 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #903.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-903.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
