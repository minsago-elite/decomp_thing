# A-series issue #824 — Move archive, audit and view source-role conventions behind profile adapters — evidence boundary

- Milestone: A8: Reconstruct a Buildable GCC Driver Source Tree
- Worktree: `/home/june/a-series-wt/issue-824` (branch `a-series-issue-824`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Move archive, audit and view source-role conventions behind profile adapters

## Acceptance criteria (from issue)
See `gh issue view 824` for the authoritative checklist. This PR does not close #824; it retains the gap for follow-up qualification.

## Method
- Read issue #824 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #824 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Move archive, audit and view source-role conventions behind profile adapters.

Focused child of #84; owns source acceptance criteria 3, 4.

## Acceptance criteria

- [ ] Remove remaining generic archive/audit/view assumptions about source suffixes, paths, artifact omissions and control locations; consume declared profile roles and policy.
- [ ] Reuse #449/#451 routing groundwork and retain Make/Ninja fixture compatibility; profile selection cannot grant unqualified production execution.

## Dependencies and evidence

Existing dependency contracts: #43, #46, #47, #49, #54, #63, #67, #118. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #84; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=84 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #824.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-824.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.

## Investigator brief (explore agent, worktree /home/june/a-series-wt/issue-824)
- Reused groundwork: #449 web archive route via adapter, #451 `ArchiveTransportLayout` adapter-owned, #406 Ninja proof 85972445 (non-Make execution only). Branch preserves `docs/issue-824-profile-adapter-evidence.md` alongside this file.
- Remaining hardcoded conventions (inspected): `ArchivalBundle.kt` (source_tree_manifest.json, ARCHIVE_MANIFEST.sha256, ARCHIVE_README.md), `ReconstructionAdapter.kt:59` retain set, `ArchivalAudit.kt` (manifest reads, reports/archival_audit.json, reports/ discovery with .behavior.json suffix), `WebSourceEvidence.kt` (reports/source-tree/source_tree_manifest.json, reports/source-tree/ prefix, reports/confidence.json), `WebArchiveEvidence.kt` (reports/source-tree.zip, reports/source-tree/ prefix), `WebViews.kt:224` moduleId via substringBeforeLast('.'), plus generic-C assumptions in `GeneratedCProjectBuilder` (src/main.c, .c scan, build/*.o) outside adapter-routed paths.
- Neutrality gate still failing per parent (~80-85 findings); profile selection must not grant unqualified production execution; Make/Ninja fixture compatibility retained.
