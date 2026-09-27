# A-series issue #856 — Qualify compile-assemble-link invocation and response-file fidelity — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-856` (branch `a-series-issue-856`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Qualify compile-assemble-link invocation and response-file fidelity

## Acceptance criteria (from issue)
See `gh issue view 856` for the authoritative checklist. This PR does not close #856; it retains the gap for follow-up qualification.

## Method
- Read issue #856 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #856 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Qualify compile-assemble-link invocation and response-file fidelity.

Focused child of #117; owns source acceptance criteria 1, 2, 4, 5.

## Acceptance criteria

- [ ] Reproduce compile-assemble-link orchestration and response-file behavior.
- [ ] Validate subprocess argv/environment and produced object/executable identities.
- [ ] Cover failure propagation from missing tools, invalid targets, and linker errors.
- [ ] Keep all external effects hermetic and resource bounded.

## Dependencies and evidence

Reuse the implementation and retained checkpoints in #117; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=117 slice=1 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #856.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-856.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
