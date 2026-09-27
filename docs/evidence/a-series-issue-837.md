# A-series issue #837 — Verify combined full-tree release evidence and authority boundaries — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-837` (branch `a-series-issue-837`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Verify combined full-tree release evidence and authority boundaries

## Acceptance criteria (from issue)
See `gh issue view 837` for the authoritative checklist. This PR does not close #837; it retains the gap for follow-up qualification.

## Method
- Read issue #837 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #837 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Verify combined full-tree release evidence and authority boundaries.

Focused child of #112; owns source acceptance criteria 1, 3, 6, 7, 8.

## Acceptance criteria

- [ ] Combine structural, clean-build, and behavioral evidence into one fail-closed release decision.
- [ ] Reject denominator drift, missing shards/cases, stale evidence, or unauthenticated artifacts.
- [ ] The release gate rejects agent-generated artifacts that lack unambiguous ACP protocol/implementation, capability, session/turn, event/change, policy, sandbox, and validation provenance required by #72.
- [ ] The release gate accepts only oracle truth, reconciliation, scoring, and release evidence produced and validated by the authoritative Kotlin/JVM path under #136.
- [ ] ACP agents receive authenticated oracle evidence read-only and cannot write, replace, score, or certify truth; any legacy direct HTTP provenance is an explicit deprecated compatibility result and cannot masquerade as ACP.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #112; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=112 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #837.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-837.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
