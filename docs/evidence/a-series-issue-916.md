# A-series issue #916 — Enforce separate safety ceilings and measured regression ratios — evidence boundary

- Milestone: A15: Demonstrate Clang/LLVM Full-Tree Behavioral Fidelity
- Worktree: `/home/june/a-series-wt/issue-916` (branch `a-series-issue-916`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Enforce separate safety ceilings and measured regression ratios

## Acceptance criteria (from issue)
See `gh issue view 916` for the authoritative checklist. This PR does not close #916; it retains the gap for follow-up qualification.

## Method
- Read issue #916 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #916 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Enforce separate safety ceilings and measured regression ratios.

Focused child of #130; owns source acceptance criteria 6, 7.

## Acceptance criteria

- [ ] Set separate absolute safety ceilings and regression ratios; no threshold may be derived from a single run.
- [ ] Treat timeouts, OOM, process leaks, output explosions, and flaky mismatches as persistent failures.

## Dependencies and evidence

Depends on #915.

Reuse the implementation and retained checkpoints in #130; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=130 slice=3 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #916.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-916.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
