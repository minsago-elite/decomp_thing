# A-series issue #859 — Integrate full-tree generation with bounded ACP scheduling and complete turn provenance — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-859` (branch `a-series-issue-859`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Integrate full-tree generation with bounded ACP scheduling and complete turn provenance

## Acceptance criteria (from issue)
See `gh issue view 859` for the authoritative checklist. This PR does not close #859; it retains the gap for follow-up qualification.

## Method
- Read issue #859 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #859 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Integrate full-tree generation with bounded ACP scheduling and complete turn provenance.

Focused child of #118; owns source acceptance criteria 4, 8, 9.

## Acceptance criteria

- [ ] Bound context, changes, output, runtime, concurrency, and repair attempts with sharded deterministic scheduling.
- [ ] Persist exact ACP implementation/protocol/capabilities/session/turn/events/changes/policy/sandbox/validation provenance for all turns.
- [ ] Missing ACP provisioning is a visible failure; no implicit direct HTTP fallback or agent-authored oracle certification is permitted.

## Dependencies and evidence

Existing dependency contracts: #63, #65, #67, #68, #69, #84, #109, #110, #112, #113, #115, #122, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #118; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=118 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #859.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-859.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
