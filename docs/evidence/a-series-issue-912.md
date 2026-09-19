# A-series issue #912 — Resolve bounded cross-shard data references through the authenticated index — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-912` (branch `a-series-issue-912`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Resolve bounded cross-shard data references through the authenticated index

## Acceptance criteria (from issue)
See `gh issue view 912` for the authoritative checklist. This PR does not close #912; it retains the gap for follow-up qualification.

## Method
- Read issue #912 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #912 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Resolve bounded cross-shard data references through the authenticated index.

Focused child of #129; owns source acceptance criteria 7, 8.

## Acceptance criteria

- [ ] Cross-shard references resolve through an authenticated index with no fallback string matching.
- [ ] Hard limits bound types, fields, globals, vtable slots, and serialized bytes.

## Dependencies and evidence

Depends on #909, #910, #911.

Reuse the implementation and retained checkpoints in #129; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=129 slice=4 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #912.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-912.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
