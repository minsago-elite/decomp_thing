# A-series issue #826 — Tracker: Enforce remaining planning, generation and validation profile budgets — evidence boundary

- Milestone: A8: Reconstruct a Buildable GCC Driver Source Tree
- Worktree: `/home/june/a-series-wt/issue-826` (branch `a-series-issue-826`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Tracker: Enforce remaining planning, generation and validation profile budgets

## Acceptance criteria (from issue)
See `gh issue view 826` for the authoritative checklist. This PR does not close #826; it retains the gap for follow-up qualification.

## Method
- Read issue #826 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #826 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Coordination tracker

This issue coordinates **Enforce remaining planning, generation and validation profile budgets**. Implement the focused outcomes below as separate reviewable tasks.

## Focused work

- [ ] #1057 — Bound Doctor probe processes and output under the selected profile (source requirements 1, 2)
- [ ] #1058 — Enforce declared profile and host budgets during semantic planning (source requirements 1, 2)
- [ ] #1059 — Enforce declared profile and host budgets during source generation (source requirements 1, 2)
- [ ] #1060 — Enforce declared profile and host budgets during build execution (source requirements 1, 2)
- [ ] #1061 — Enforce declared profile and host budgets during behavior validation (source requirements 1, 2)
- [ ] #1062 — Enforce declared profile and host budgets during archive publication (source requirements 1, 2)

## Completion boundary

Every remaining source acceptance requirement is assigned above. Splitting scope does not complete implementation, integration or qualification. Keep this tracker open until its original acceptance requirements and external gates are satisfied.

This splits the remaining profile-budget audit by execution phase. Parent metadata/export remains a separate #84 child; the overall profile migration cannot close while any required boundary is unaccounted for. The concurrent #805/#84 audit explicitly retains Doctor process/output/cancellation ceilings as phase-budget work; Doctor profile selection itself is already implemented.

Existing dependency contracts: #43, #46, #47, #49, #54, #63, #67, #84, #118. See the parent for capability-specific sequencing; this split does not move their ownership.

<details>
<summary>Original scope, acceptance criteria and retained evidence</summary>

## Outcome

Enforce remaining planning, generation and validation profile budgets.

Focused child of #84; owns source acceptance criterion 5.

## Acceptance criteria

- [ ] Audit each planning/generation/build/validation/archive boundary for its declared profile budgets and independently enforced host safety ceilings.
- [ ] Implement missing budget consumption/recording at those boundaries and retain focused rejection evidence; earlier export/context checks cannot stand in for other phases.

## Dependencies and evidence

Existing dependency contracts: #43, #46, #47, #49, #54, #63, #67, #118. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #84; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=84 slice=5 -->

</details>

<!-- backlog-sizing-v1 reviewed -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #826.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-826.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.

## Investigator brief (explore agent, worktree /home/june/a-series-wt/issue-826)
- Contracts: `ReconstructionBudgets` (export/planner/module/context/build/archive) + `ReconstructionHostSafetyLimits.requireAllows()` + immutable profile identity in `project/ReconstructionProfile.kt`.
- Wiring to audit per boundary: `ArchivalReconstruction.kt` (export/planner/build/archive), `DeterministicModulePlanner.kt` (work-unit charging), `SourceTree.kt` (context budget), `GeneratedCModuleValidation.kt` (build wall-clock/output cap), `ArchivalAudit.kt` (archive entry/byte bounds).
- Carve-outs: `Doctor.kt:297-298` reads full output then unbounded `waitFor()` — no timeout, output cap, budget charge, or cancellation propagation (owned by #1057). Generation/planning/validation/publication consume+record + admission/exhaustion rejection evidence still absent as a single boundary inventory; export/context checks cannot substitute. Split children: #1057 Doctor, #1058 planning, #1059 generation, #1060 build, #1061 validation, #1062 archive.
