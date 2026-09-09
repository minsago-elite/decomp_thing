# A-series issue #885 — Define canonical shard scheduler state and ACP repair history — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-885` (branch `a-series-issue-885`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Define canonical shard scheduler state and ACP repair history

## Acceptance criteria (from issue)
See `gh issue view 885` for the authoritative checklist. This PR does not close #885; it retains the gap for follow-up qualification.

## Method
- Read issue #885 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #885 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Define canonical shard scheduler state and ACP repair history.

Focused child of #125; owns source acceptance criteria 8, 10, 13.

## Acceptance criteria

- [ ] Emit deterministic repair history including input hashes, prompt/tool identity, patch hash, verification commands, and outcome.
- [ ] Every model-driven repair attempt runs through the ACP-first workflow tracked by #72; scheduler state records ACP implementation, session/turn, policy, sandbox, events, changes, and outcome.
- [ ] Define a versioned scheduler schema covering work/diagnostic identity, shard ownership, speculative parent, accepted parent, dependency/frozen-interface version, external invocation identity, cumulative budget reservations, outcome and resume disposition.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #125; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=125 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #885.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-885.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
