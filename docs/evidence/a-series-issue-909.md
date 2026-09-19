# A-series issue #909 — Produce canonical global, TLS and local-static truth with observability reasons — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-909` (branch `a-series-issue-909`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Produce canonical global, TLS and local-static truth with observability reasons

## Acceptance criteria (from issue)
See `gh issue view 909` for the authoritative checklist. This PR does not close #909; it retains the gap for follow-up qualification.

## Method
- Read issue #909 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #909 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Produce canonical global, TLS and local-static truth with observability reasons.

Focused child of #129; owns source acceptance criteria 1, 5, 6.

## Acceptance criteria

- [ ] Global records include canonical identity, linkage, visibility, mutability, TLS class, size/alignment, owning shard, and evidence references.
- [ ] Anonymous namespaces and local statics receive stable producer-owned identities.
- [ ] Unobservable optimized-out fields/globals remain visible in denominators with reason codes.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #129; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=129 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #909.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-909.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
