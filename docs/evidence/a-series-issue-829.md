# A-series issue #829 — Qualify declared-role authority through Make and Ninja ACP workflows — evidence boundary

- Milestone: A8: Reconstruct a Buildable GCC Driver Source Tree
- Worktree: `/home/june/a-series-wt/issue-829` (branch `a-series-issue-829`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Qualify declared-role authority through Make and Ninja ACP workflows

## Acceptance criteria (from issue)
See `gh issue view 829` for the authoritative checklist. This PR does not close #829; it retains the gap for follow-up qualification.

## Method
- Read issue #829 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #829 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Qualify declared-role authority through Make and Ninja ACP workflows.

Focused child of #84; owns source acceptance criterion 8.

## Acceptance criteria

- [ ] Prove #63/#64/#65 derive permissions and ownership from declared roles, including the alternate profile.

## Dependencies and evidence

Existing dependency contracts: #43, #46, #47, #49, #54, #63, #67, #118. See the parent for capability-specific sequencing; this split does not move their ownership.

Exercise #63 mutation, #64 reconstruction and #65 repair public paths using declared ownership; #414 local indexing proof alone cannot qualify ACP workflow authority.

Reuse the implementation and retained checkpoints in #84; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=84 slice=7 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #829.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-829.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
