# LLVM candidate four-way evidence record v2

This record captures the repository's current #140 handoff. It is a structural evidence
contract, not hosted-build or release evidence.

## Verified at the current boundary

`LlvmBehaviorCandidateFourWayBindingV2Verifier.verify` accepts exactly four raw paths and
cross-checks them through the existing Kotlin verifiers:

1. the reconstruction archive;
2. the `candidate-acp-lineage-index-v2.json` ACP lineage index;
3. the unsigned `candidate-hosted-clean-build-v2.json` receipt; and
4. the exact candidate executable.

The verifier pins each input and its lexical parent, snapshots the bytes privately, rechecks
source currentness around verification, and derives one defensive
`candidateStructuralIdentitySha256` from the canonical four-way binding. Archive and ACP lineage
facts come from `LlvmBehaviorCandidateAcpLineageIndexV2Verifier`; receipt/executable structure
comes from `LlvmBehaviorHostedCleanBuildV2Verifier`. Cross-paired or mutated inputs fail closed.

The returned contract therefore records:

```text
exactFourWayStructuralBinding=true
acpRequired=true
acpFirstClassCandidateProducerOperator=true
acpOracleAuthority=false
acpReferenceAuthoringAuthority=false
acpPolicyAuthoringAuthority=false
acpValidationAuthority=false
acpObservationAuthoringAuthority=false
acpStartAuthority=false
acpContainmentAuthority=false
acpTerminalAbsenceAuthority=false
acpScoringAuthority=false
acpCertificationAuthority=false
acpReleaseAuthority=false
hostedBuildExecutionAuthenticated=false
admittedArtifactBound=false
prepared=false
startAuthorized=false
candidateStarted=false
scoringAuthority=false
certificationAuthority=false
releaseEligible=false
```

This is the smallest truthful executable-lineage slice currently available: one immutable
structural identity joins the four inputs, while the result remains non-authoritative.

## Production gap

This record does not prove authenticated hosted execution. The following gates remain unresolved
and must stay false until separately authenticated evidence exists:

- hosted ingress, exact live image/runtime configuration, container CREATE/START/wait, cleanup,
  and terminal absence;
- workflow/attestation provenance and a receipt that is authoritative for the build environment;
- the full #115 configure/compile/link/archive reproduction beyond the inner generated-C worker;
- final immutable admission publication after cleanup and four-way authority composition.

Docker and its socket are unavailable in this checkout, so no local production container run is
claimed. This slice adds no Python execution path, external `analyzeHeadless`/`GHIDRA_HOME`
dependency, oracle authority, or release authority; bundled Ghidra isolation remains unchanged.

Sources: `src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2Verifier.kt`,
`docs/llvm-behavior-candidate-acp-lineage-index-v2.md`,
`docs/llvm-behavior-hosted-clean-build-v2.md`, and
`docs/llvm-behavior-hosted-container-coordinator-v1.md`.
