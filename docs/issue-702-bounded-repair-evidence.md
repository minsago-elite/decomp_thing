# Issue #702 bounded repair evidence

This checkpoint records one small contract slice for #702. It does not claim the
real GCC-driver repair qualification or close the issue.

## Evidence slice

`GeneratedCRepairValidationProviderTest.source and retained corpus accounting are
independent and detached` exercises the existing
`RepairCandidateValidationRequest` boundary. A request carrying a ten-byte
candidate source file and a ten-byte retained input record is accepted when both
declared limits are ten. Lowering only the source limit rejects the request;
lowering only the retained-input limit also rejects it. The test then mutates the
returned source and stdin arrays and verifies that the request's retained values
are unchanged.

The request still authenticates the source and corpus identities with the existing
`repairCandidateSourceSha256` and `repairRegressionCorpusSha256` functions. This
is independent accounting at the request contract; it is not evidence that a
production process consumed the whole GCC inventory.

## Validation

The focused command was started but interrupted before Gradle reported a result:

```text
./gradlew --no-daemon --console=plain test \
  --tests decompengine.project.GeneratedCRepairValidationProviderTest
NO RESULT (interrupted before completion)
```

`git diff --check` is required before the checkpoint commit. The production
qualification command is intentionally not reported as successful here: the
registered generated-C strategy remains `STRICT_CONTAINED` but its availability
check fails closed without the operator-provisioned configuration and quota
mounts.

## Gates still unavailable

The following #702 evidence remains unavailable in this worktree and is left
explicitly unresolved:

- no bounded repair ran across the declared real GCC file/module/function
  inventory, so there are no selected/total counts, request or patch sizes,
  retained cases, or downstream invalidation archive;
- no production toolchain/runtime closure, root-owned configuration, or
  independent finite source/output mounts were provisioned;
- terminal pids/memory event counters and exact wait-status attribution are not
  retained before cgroup cleanup, as documented by #236;
- no full retained-corpus candidate/reference replay, fresh-process reopen, or
  independently verified history/archive round trip ran;
- no skipped host capability is treated as qualification, and the public factory
  remains unavailable until these gates are satisfied.

The slice preserves the existing boundaries: bundled Ghidra is not involved,
candidate execution remains behind the authenticated contained provider, source
and corpus hashes remain part of the request contract, and unresolved production
authority is represented by the existing unavailable result rather than a
host-process fallback or a fabricated success receipt.
