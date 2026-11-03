# A-series issue #918 — Freeze stable C++ names and resolve owner-scoped collisions — evidence boundary

- Milestone: A14: Reconstruct a Buildable Clang/LLVM Full Source Tree
- Worktree: `.claude/worktrees/a-series-cpp-name-table-918` (branch `a-series/cpp-name-table-918`, based on `origin/master`)
- Status: CANDIDATE IMPLEMENTATION ONLY — this file records an inert naming slice; it does not claim production qualification.

## Outcome (from issue)
Freeze stable C++ names and resolve owner-scoped collisions

## Acceptance criteria (from issue)
See `gh issue view 918` for the authoritative checklist. This PR does not close #918; it retains the gap for follow-up qualification.

## Implemented candidate slice
- Added `StableCppNameCandidateTable` as a pure deterministic function over typed source-anchor identity candidates, lexical scopes, linkage classes, owners, module IDs and canonical source paths.
- Generated identifiers use a legal fixed prefix, sanitized bounded stem, and full SHA-256 digest. Scope and explicit owner participate in the digest; module owner participates for internal linkage. Canonical report rows bind module and path so placement changes remain visible.
- The table freezes all entries before lookup, rejects duplicate/unknown identity candidates and duplicate generated names, records sanitized-stem collision groups, and emits a canonical report marked `authority: none` and `status: candidate-only`.
- Inputs and outputs have hard entity, UTF-8, scope-depth, canonical-byte and JSON-node bounds. Scope lists are copied through bounded iterators. Entity acquisition enforces the count limit before consuming each record, then validates and charges that record against the UTF-8 budget before retaining it or requesting the next record. Report budgeting and generation use only that validated snapshot. Caller-reported list sizes cannot bypass entity limits or substitute unvalidated rows during generation. Oversized scope/name inputs fail before unbounded traversal or encoding allocation.
- No production adapter or emission path consumes this candidate table. The supplied identity candidates are not authenticated semantic identities.

## Verification evidence
- Command: `./gradlew test --tests decompengine.project.StableCppNameCandidateTableTest`
- Result: `BUILD SUCCESSFUL`; all 9 focused tests passed, including order permutation, sanitization collisions, owner/scope requirements, scope and module moves, duplicate/unknown identities, output and Unicode limits, adversarial unbounded scope iterator, and authored multi-translation-unit fixtures.
- The command also passed the frontend toolchain/build/resource checks and compiled JUnit signature guard (1,728 classes; 4,481 annotated methods).

### Review remediation verification
- Added two adversarial caller-list regressions: an underreported, endless iterator must stop before consuming an entity over the configured limit; a list that changes between traversals must not substitute an unvalidated source path.
- Focused Kotlin 2.4.0/JDK 21 compilation and JUnit Platform execution of `StableCppNameCandidateTableTest`, reusing dependency classes from the original exact PR head `56fda2387b806b9cbe728939cb442caab59c0b71`: the original implementation fails both new tests (9 pass, 2 fail); the corrected implementation passes all 11 tests, with no skips or aborts.
- Local reproduction harness and logs: `.worktrees/review-remediation/evidence/prs/1817/focused-kotlin.py`, `focused-baseline.log`, `focused-fixed.log`; run `python3 .worktrees/review-remediation/evidence/prs/1817/focused-kotlin.py fixed` from the repository root.
- `git diff --check` passed. Kotlin LSP executables/tools are unavailable in this session; focused compiler checks were used instead. This short local check does not replace hosted Gradle qualification.

### Independent-review follow-up
- Fixed the snapshot acquisition regression in `9817dea4da038b28653ec6dfe34c3041c2fd43d3`: collecting all entities before byte charging could materialize and retain oversized lazy inputs before rejection. Validation and charging now happen during collection, before each record is retained and before the next iterator request.
- Added a lazy-list traversal regression with both a one-byte budget (reject the first entity) and an exact-one-record budget (reject the second). Sentinels forbid any subsequent entity materialization. The test fails on `9817dea4` (11 pass, 1 fail), and all 12 focused tests pass after the fix, with zero skips or aborts. Both prior caller-list regressions remain intact.
- Command: `python3 .worktrees/review-remediation/evidence/prs/1817/final-fix-kotlin.py fixed`; Kotlin 2.4.0/JDK 21 recompiles the changed source and test against read-only original-head dependency classes. Logs: `final-fix-previous.log`, `final-fix-fixed.log` in the same evidence directory.
- `git diff --check` passed. Active Kotlin LSP tools/executables remain unavailable; compilation is the fallback, not an LSP success. Fresh hosted Gradle qualification and exact-head external reviews are still required; earlier-head results do not qualify this fix.

## Current boundary (truthful, no fabrication)
- This is a pure candidate-only implementation slice; no authenticated semantic-identity input, production integration, generated source, contained run, deterministic production repetition, or independent archive verification is claimed.
- All five issue acceptance criteria remain open. Qualification and upstream producer/ownership dependencies are still required before #918 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Freeze stable C++ names and resolve owner-scoped collisions.

Focused child of #131; owns source acceptance criteria 1, 3, 4, 6, 7.

## Acceptance criteria

- [ ] Derive stable legal names from authenticated identity and scope, independently of traversal or shard order.
- [ ] Assign deterministic owner-scoped names to anonymous/local entities and local statics.
- [ ] Detect sanitization collisions before emission and resolve them with documented stable suffixes.
- [ ] Make namespace/module moves visible in canonical mapping evidence.
- [ ] Freeze the global name table before emitting identity-based references.

## Dependencies and evidence

Existing dependency contracts: #64, #84, #109, #110, #113, #115, #118, #123, #127, #128, #129, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #131; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=131 slice=1 -->

```

## Limitations / next steps
- Attach production qualification evidence (exact commands, commits, artifacts, budgets) before claiming #918.
- Keep this candidate slice isolated from #919/#920 and upstream semantic-identity authority work.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.
