# A-series issue #887 — Isolate repair candidates and transact frozen-interface invalidation — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-887` (branch `a-series-issue-887`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Isolate repair candidates and transact frozen-interface invalidation

## Acceptance criteria (from issue)
See `gh issue view 887` for the authoritative checklist. This PR does not close #887; it retains the gap for follow-up qualification.

## Method
- Read issue #887 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #887 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Isolate repair candidates and transact frozen-interface invalidation.

Focused child of #125; owns source acceptance criteria 3, 4, 12.

## Acceptance criteria

- [ ] Apply each candidate in an isolated worktree/state snapshot and accept only measured improvements.
- [ ] Prevent modification of frozen verified interfaces without an explicit invalidation transaction.
- [ ] Kotlin/JVM validation and scoring under #136 remain authoritative; ACP receives oracle evidence read-only and cannot write or certify truth.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #125; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=125 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #887.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-887.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
