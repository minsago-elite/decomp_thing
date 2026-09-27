# A-series #117 workflow evidence v1

This is a narrow evidence record for #117 at the current repository revision. It
records existing implementation facts; it does not close the tracker or promote
any unsigned artifact to oracle or release authority.

| Workflow concern | Repository fact | Evidence state |
| --- | --- | --- |
| Generated-C build | `GeneratedCProjectBuilder` runs the profile-selected Make command with a sanitized environment, a shared wall/output budget, source-stability checks, per-module diagnostics, and a bounded `build/reconstructed` size/SHA-256 identity. | Local build lifecycle evidence. |
| Local toolchain identity | `GeneratedCToolchainEvidence` bounds `--version` probes and emits `unavailable` on probe failure; its own note says the observation is not an authenticated executable identity. | Evidence-only; unresolved for production provenance. |
| Hosted compile/assemble/link | The fixed clean-build worker performs two clean builds from an authenticated archive, uses Clang's integrated assembler, invokes retained LLD directly, commits logical argv/environment/object/link-plan identities, and compares the final ELF bytes. | Bounded producer evidence. It does not reproduce a candidate build driver's policy. |
| Response-file and driver behavior | The hosted worker intentionally uses no response file, Clang link driver, `-L`, or `-l` search. | Unresolved for #856: this does not demonstrate reconstructed driver response-file or tool-selection behavior. |
| Produced-program execution | The four-way candidate binding and clean-build receipt keep `admittedArtifactBound`, `candidateStarted`, execution/containment, and `releaseEligible` false. | Unresolved for #857: no authenticated produced-program run is claimed. |
| External effects | The worker documents bounded command/build/output/object/executable limits and keeps ACP, oracle, reference, scoring, certification, and release authority false. | Contract evidence only; bounds do not prove hosted containment or terminal absence. |

## Production gates still unavailable

The following facts remain required before #117 can close:

* A closed corpus exercising compile-assemble-link driver argv/environment,
  response-file bytes/parsing, tool search, missing-tool and invalid-target
  failures, and linker-error propagation.
* Authenticated hosted ingress and workflow/image/runtime provenance for the
  candidate archive, receipt, and executable, including cleanup and terminal
  absence. The current unsigned inner receipt cannot supply those facts.
* A Kotlin-owned generic sandbox run of the produced program with repeated,
  retained observations. Pre-start admission and runtime preflight are not a
  START or execution result.
* Full-tree configure/build/archive reproduction remains separate work under
  #115; the bounded generated-C worker is not that workflow.

This record does not alter the bundled-Ghidra boundary: production analysis
continues to use the application-linked bundled Ghidra APIs and does not require
`GHIDRA_HOME`. It also does not grant ACP or any caller-supplied observation
oracle, reference-authoring, validation, scoring, certification, or release
authority.

Sources: [`GeneratedCProjectBuilder.kt`](../src/main/kotlin/decompengine/project/GeneratedCProjectBuilder.kt), [`GeneratedCToolchainEvidence.kt`](../src/main/kotlin/decompengine/project/GeneratedCToolchainEvidence.kt), [`llvm-behavior-hosted-clean-build-v2.md`](llvm-behavior-hosted-clean-build-v2.md), [`LlvmBehaviorCandidateFourWayBindingV2Verifier.kt`](../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2Verifier.kt), [`bundled-ghidra.md`](bundled-ghidra.md).
