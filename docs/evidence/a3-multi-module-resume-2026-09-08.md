# A3 bounded multi-module resume evidence

This is the focused local evidence slice for [#678](https://github.com/minsago-elite/decomp_thing/issues/678). It records the existing four-module contract test at base commit `bf250156` and does not claim completion of the parent tracker or milestone.

## Observed contract

The test `SourceTreeTest.interface changes invalidate transitive consumers and resume preserves completed revisions` uses the authored `leaf → middle → root` chain plus an unrelated module. It verifies that:

- the initial generation produces all four modules and a buildable tree;
- changing the leaf interface regenerates the leaf and its transitive consumers;
- an interruption at `root` leaves the completed `leaf` and `middle` checkpoints available;
- resume invokes only `root`, while the completed dependency and unrelated checkpoint bytes remain unchanged;
- the final module source and checkpoint digests are recomputed from the retained files, and the same audit survives archive extraction;
- the audit reports `moduleExecutionCoverage: "not-observed"`, an empty behavior evidence list, and `behaviorMatched: null`.

The evidence is bounded to four authored modules and a scripted `ModuleReconstructor`. It demonstrates checkpoint, provenance, invalidation, resume, archive, and unresolved-behavior contracts in the repository's existing test boundary. The test does not authenticate an external agent invocation, infer behavior from structural recovery, or turn an accepted implementation into a measured behavioral result.

## Verification

Command run from the issue worktree:

```text
./gradlew test --tests 'decompengine.project.SourceTreeTest.interface changes invalidate transitive consumers and resume preserves completed revisions' --no-daemon
```

Result: `BUILD SUCCESSFUL` on 2026-09-08; zero failures and zero skips.

## Gates still unavailable

This slice does not provide:

- authenticated production agent restart/resume or authenticated external oracle execution;
- production compiler/toolchain qualification or production-scale multi-module qualification;
- revision-bound coverage, output agreement, or other measured behavioral evidence.

Those states remain explicit and unresolved by contract. The fixture uses the existing model and scripted reconstructor, does not invoke `GHIDRA_HOME` or `analyzeHeadless`, and leaves the bundled Ghidra and authenticated oracle boundaries unchanged.
