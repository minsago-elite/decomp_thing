# A-series issue #726 — Qualify the integrated reconstructed GCC corpus with exact per-case observations — evidence boundary

- Milestone: A10: Scale Reconstruction to GCC Compiler Engines
- Worktree: `/home/june/a-series-wt/issue-726` (branch `a-series-issue-726`, based on `origin/master`)
- Status: NOT YET QUALIFIED — this file records the current evidence boundary only; it does not claim production qualification.

## Outcome (from issue)
Qualify the integrated reconstructed GCC corpus with exact per-case observations

## Acceptance criteria (from issue)
See `gh issue view 726` for the authoritative checklist. This PR does not close #726; it retains the gap for follow-up qualification.

## Method
- Read issue #726 outcome, acceptance criteria, dependencies and parent checkpoints.
- Inspected the `origin/master` worktree for existing implementation, tests and retained checkpoints.
- Recorded only what is currently evidenced; unresolved behavior remains explicitly unclaimed.

## Current boundary (truthful, no fabrication)
- No new production behavior is claimed by this file.
- Qualification evidence (contained runs, deterministic repetitions, independent archive verification, authority boundaries) is still required before #726 can close.
- Parent checkpoints and dependency contracts referenced by the issue retain their own scope and verification requirements.

## Source excerpt (authoritative issue body, truncated)
```markdown
## Outcome

Qualify the integrated reconstructed GCC corpus with exact per-case observations.

Focused child of #57; owns source acceptance criteria 3, 4, 5.

## Acceptance criteria

- [ ] Execute the complete versioned GCC behavior corpus across preprocessing, compilation, assembly, linking, diagnostics, and produced-program execution.
- [ ] Retain exact argv/environment/stdin/stdout/stderr/exit/signal/timeout/subprocess/artifact evidence and source-revision bindings.
- [ ] Compare behavior with authenticated reference results using documented normalization and explicit per-case denominators.

## Dependencies and evidence

Depends on #725.

Existing dependency contracts: #47, #54, #55, #63, #84, #136. See the parent for capability-specific sequencing; this split does not move their ownership.

Reuse the implementation and retained checkpoints in #57; complete or verify only the remaining gap in this slice. The parent retains the original scope, verification requirements and evidence limitations. Attach focused evidence for this outcome and distinguish draft implementation, merged behavior and production qualification.

<!-- backlog-sizing-v1 parent=57 slice=2 -->

```

## Limitations / next steps
- Attach focused execution evidence (exact commands, commits, artifacts, budgets) in a follow-up before claiming #726.
- Keep implementation slices minimal and file-scoped (`docs/evidence/a-series-issue-726.md` only) so parallel A-series PRs do not conflict.
- Distinguish draft implementation, merged behavior and production qualification per the issue's evidence requirements.

## Investigator brief (explore agent, worktree /home/june/a-series-wt/issue-726)
- Reference corpus: `oracle/gcc/16.2.0/behavior-corpus.json` — 14 sorted cases, zero normalizations (assembly-file, compile-file, compile-stdin, diagnostic-invalid-input, diagnostic-invalid-option, environment-search-path, help-driver, linking, metadata-dumpmachine, metadata-dumpversion, metadata-version, preprocess-file, preprocess-stdin, response-file).
- Reference evidence `behavior-corpus-evidence.json` byte-compared when blessed executor matches (Docker 29.7.2, kernel 7.1.8-gentoo-dist-hardened); otherwise narrow skip 78; offline validator `scripts/check-behavior-corpus-evidence.py` always runs.
- Candidate side MISSING: no accepted reconstructed driver/cc1/lto1 archives, no integrated candidate run, no authenticated comparison with denominators (currently candidate 0 / compared 0 / blocked).
- Schema gap: `oracle/behavior-corpus-report.schema.json` v1 has no per-case signal/timeout/subprocess-lifecycle fields, so those acceptance items need a schema/runner change. cc1/lto1 manifests are authenticated inputs, not reconstruction completion.
- Reproduction: `scripts/run-gcc-behavior-corpus.py`, `scripts/run-behavior-corpus.py`, `scripts/check-behavior-corpus-evidence.py`.
