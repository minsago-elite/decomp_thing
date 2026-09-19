# A-series issue #876 — Represent inline-only and template-instance identities with explicit observability — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-876` (branch `a-series-issue-876`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Represent inline-only and template-instance identities with explicit observability

## Acceptance criteria (from issue)
See `gh issue view 876` for the authoritative checklist. This PR does not close #876; it retains the gap for follow-up qualification.

## Method
- Read issue #876 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #876 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Represent inline-only and template-instance identities with explicit observability.

Focused child of #123; owns source acceptance criteria 3, 4.

## Acceptance criteria

- [ ] Inline-only declarations are represented as explicitly unobservable and never silently promoted into emitted-function denominators.
- [ ] Template patterns and concrete instantiations have stable, source-aligned identities.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #123; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=123 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #876.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-876.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
