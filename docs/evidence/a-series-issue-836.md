# A-series issue #836 — Score recovered full-tree interfaces against authenticated A13 truth — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `/home/june/a-series-wt/issue-836` (branch `a-series-issue-836`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Score recovered full-tree interfaces against authenticated A13 truth

## Acceptance criteria (from issue)
See `gh issue view 836` for the authoritative checklist. This PR does not close #836; it retains the gap for follow-up qualification.

## Method
- Read issue #836 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #836 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Score recovered full-tree interfaces against authenticated A13 truth.

Focused child of #110; owns source acceptance criteria 6, 7.

## Acceptance criteria

- [ ] Score recovered interfaces against A13 truth with visible numerator/denominator/exclusion evidence.
- [ ] Archive canonical declarations, probe sources/results, identity mappings, collision findings, and exact compiler/input provenance.

## Dependencies and evidence

Depends on #833, #834.

Existing dependency contracts: #64, #84, #109, #113, #115, #118, #122, #127, #128, #129, #131, #132, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #110; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=110 slice=4 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #836.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-836.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
