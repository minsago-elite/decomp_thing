# #823 profile-selection evidence slice

Status: draft repository evidence, recorded 2026-09-08. This slice does not
claim that #823 is complete.

## Repository facts

| Fact | Existing evidence | Boundary |
| --- | --- | --- |
| Profile dispatch is application-owned. | `ReconstructionAdapters.resolve` registers `generated-c-make-v1` and `generated-c-ninja-v1` and rejects an unregistered profile (`src/main/kotlin/decompengine/project/ReconstructionAdapter.kt`). | Profile data cannot install executable adapter code. |
| The public reconstruction build path carries the admitted profile into the adapter. | `ArchivalReconstructionService` resolves the adapter before work output and calls `adapter.build(project, profile)` (`src/main/kotlin/decompengine/project/ArchivalReconstruction.kt`). `GeneratedCReconstructionAdapter` reads the profile's build executable, compiler driver, flags, build definition and budgets (`src/main/kotlin/decompengine/project/GeneratedCReconstructionAdapter.kt`). | This is local profile routing evidence for the reconstruction service. |
| The remaining MVP compiler selection is still generic. | `MvpPatchWorkflow.compile` constructs every compile command with the literal `"gcc"` (`src/main/kotlin/decompengine/mvp/MvpPatchWorkflow.kt`). | The MVP patch workflow has no admitted profile input at this seam. |

The evidence supports one narrow conclusion: the profile adapter boundary is
present for the public reconstruction build path, while the MVP patch compiler
selection remains an open #823 migration seam. No implementation or behavior
claim is inferred from the source inspection beyond those facts.

## Production gate status

Production qualification is unavailable for this slice. The existing local
compiler/build records do not authenticate the compiler executable, runtime, or
complete input/output artifact closure, and do not qualify a contained
production compiler. The bundled direct-API Ghidra path and authenticated
oracle/agent boundaries are unchanged and are not requalified here. Full CI,
production ACP execution, benchmark qualification, and integration of the
remaining MVP routing were not run.

The issue remains open: the MVP compiler selection and its profile admission
still require implementation and focused verification.
