# A-series issue #904 — Join caller-local call sites to internal cross-shard identities — evidence boundary

- Milestone: A13: Scale Structural Accuracy Across the Clang/LLVM Full Tree
- Worktree: `/home/june/a-series-wt/issue-904` (branch `a-series-issue-904`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Join caller-local call sites to internal cross-shard identities

## Acceptance criteria (from issue)
See `gh issue view 904` for the authoritative checklist. This PR does not close #904; it retains the gap for follow-up qualification.

## Method
- Read issue #904 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #904 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Join caller-local call sites to internal cross-shard identities.

Focused child of #128; owns source acceptance criteria 1, 2, 6, 7.

## Acceptance criteria

- [ ] Every scored call site uses caller-local RVA plus a stable caller identity.
- [ ] Direct internal targets resolve through the authenticated full-tree function index, including cross-shard targets.
- [ ] Duplicate disassembly/DWARF observations collapse deterministically.
- [ ] Missing caller/callee shards, dangling IDs, or target-set overflow fail closed.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #128; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=128 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #904.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-904.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
