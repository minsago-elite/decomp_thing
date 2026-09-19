# GCC engine CLI outcome preservation evidence

This bounded checkpoint records the current evidence for issue #983 at code
checkpoint `bf2501568f39ab52b23492dfc37839bb81895587`. It covers the normal
`gcc-engine-plan` route and its retained status fields. It does not claim that
the compiler engines ran, that an unavailable operation was published as a
result, or that any release gate passed.

## Verified in the current tree

The normal CLI entry point in `src/main/kotlin/decompengine/Main.kt`,
`runGccEnginePlan`, parses the invocation and calls
`GccBundledCliCommand.run` directly. The route contains no call to the legacy
diagnostic planning service and has no diagnostic fallback after contained
execution admission fails.

The status is fixed at each current contained-operation boundary:

| Current code or record | Preserved outcome |
| --- | --- |
| `GccBundledOperationCoordinator.GccBundledPreparedOperation` | `complete=false`, `startAuthorized=false`, `releaseEligible=false` |
| `GccBundledExecutedOperation` and `GccBundledInterruptedOperation` | `complete=false`, `releaseEligible=false` |
| `GccBundledPlannedOperation` | `complete=false`, `releaseEligible=false` |
| `GccBundledOperationCoordinator.publishCliResult` / `result.json` | `complete=false`, `releaseEligible=false`; scratch is retained because release and cold recovery are unqualified |
| `GccBundledPlannerOutputAssessment.assess` | `complete=false`, `releaseEligible=false` |
| `GccBundledOperationJournal` linked records | every record requires both flags to be false |

The exact journal consistency helper,
`src/test/kotlin/decompengine/oracle/gcc/GccBundledCliEvidenceChecks.kt`,
rejects a linked record with either flag set to true. Its focused test,
`GccBundledCliEvidenceChecksTest.missing checksums and foreign lineage are
rejected even with a recomputed outer checksum`, also rejects authored true
values. That test checks record consistency only; it does not grant START or
prove live execution.

## Current fixtures and qualification boundary

`GccBundledCliCommandTest` uses an authored temporary fixture containing text
files named `binary`, `profile`, and `archive`, plus private `output` and
`scratch` directories. Its rejection cases establish pre-staging failure and
absence of `result.json` for mismatched inputs or unreachable checkpoint
selection. They do not exercise a contained compiler start denial.

`GccBundledCliQualificationTest` is the only current real-engine CLI fixture.
Both tests require `DECOMP_REQUIRE_GCC_ENGINE_CLI=true` and separately
provisioned installation, profile, archive, genuine `cc1`/`lto1` binaries,
four scratch mounts, and an evidence root. When those prerequisites are
available, the fixture asserts `result.json` has both status flags false and
writes a comparison with `benchmarkAccepted=false` and
`releaseEligible=false`. Its source explicitly limits the comparison to
same-owner fresh/resume byte identity.

## Explicitly unverified

The following remain open under #983 and its parent:

- a contained-execution prerequisite denial and its externally visible
  unavailable outcome;
- an actual installed-launcher `cc1` or `lto1` fresh run and same-owner
  resume run;
- later-invocation or cold recovery, stale-input rejection after restart, and
  output-lineage qualification;
- whole-operation wall-time, memory, publication, and cleanup resource
  qualification; and
- benchmark acceptance, production release eligibility, and the parent
  real-engine equivalence gates.

No remaining tests were run for this documentation checkpoint, as directed.
The record is therefore source- and fixture-bound evidence of status
preservation and routing, with no new execution or production qualification
claim.

Refs #983
