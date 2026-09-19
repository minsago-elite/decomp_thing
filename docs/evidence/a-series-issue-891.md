# A-series issue #891 — Resume shard repair by external invocation identity at every durable boundary — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-891` (branch `a-series-issue-891`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Resume shard repair by external invocation identity at every durable boundary

## Acceptance criteria (from issue)
See `gh issue view 891` for the authoritative checklist. This PR does not close #891; it retains the gap for follow-up qualification.

## Method
- Read issue #891 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #891 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Resume shard repair by external invocation identity at every durable boundary.

Focused child of #125; owns source acceptance criteria 7, 11, 17.

## Acceptance criteria

- [ ] Resume from an authenticated checkpoint without replaying accepted external calls or losing rejected evidence.
- [ ] Retry/resume never silently switches to the legacy direct HTTP client or loses the identity of an external ACP call.
- [ ] Prove deterministic replay/resume on interruption before dispatch, after dispatch, after receipt, during validation and at acceptance. Previously dispatched external calls must be resumed/reconciled by identity, never silently repeated with a new provider.

## Dependencies and evidence

Depends on #890.

Reuse the implementation and retained checkpoints in #125; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=125 slice=7 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #891.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-891.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
