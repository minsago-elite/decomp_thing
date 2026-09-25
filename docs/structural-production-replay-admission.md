# Structural production replay admission checkpoint

This is the focused evidence record for [#679](https://github.com/minsago-elite/decomp_thing/issues/679), recorded on 2026-09-08. It documents one contract boundary and does not claim production qualification.

## Input-profile implementation checkpoint — 2026-09-25

`GccDriverStructuralInputsV1` now admits the checked GCC 16.2.0 driver input profile in Kotlin/JVM. It pins the artifact-manifest, source-lock, build-record, and toolchain-reproduction hashes; checks the manifest's source/build links; inspects the full and stripped ELF twins with the bounded Kotlin ELF reader; checks both artifact records and target identity; and derives the stripped image base and executable ranges from the inspected ELF headers. A mutation test confirms that a substituted manifest is rejected even when it repeats the expected binary hashes.

This is input-profile groundwork only. It does not launch Ghidra, capture an exported model, perform the independent boundary or identity replay, create `VerifiedStructuralInputsV1`, or register a production adapter. No live GCC production replay was performed. The remaining production execution and scoring gates below are still open.

Focused verification: `./gradlew --no-daemon -Pkotlin.daemon.jvmargs=-Xmx4g test --tests 'decompengine.oracle.gcc.GccDriverStructuralProfileTest'` passed 2 tests with the repository-pinned Node 24.20.0/npm 11.19.0. The larger heap was needed for the repository's full Kotlin compile in this local environment; the repository's default 2 GiB Kotlin daemon heap exhausted memory during the first attempt.

## Contained full-export snapshot checkpoint — 2026-09-25

Bundled runtime version 5 selects the exporter's `full` mode in the command definition. `GccBundledPreparedOperation.executeFullExport()` uses the existing contained launch, then captures the completed output only after cgroup absence. The descriptor-relative snapshot binds the input, exporter and Ghidra archive digests; validates full-mode state and terminal progress; checks the per-function, global, type and failure sidecar inventories and their record identities; and commits the model and all sidecar bytes into an output-tree digest. Its result remains explicitly non-authoritative and cannot be passed to structural scoring.

Focused verification: `GccBundledFullExportCaptureTest`, `GccBundledGhidraRuntimeTest`, `GccBundledOperationCoordinatorTest`, and `GccBundledContainedExecutionTest` passed locally. The environment-dependent `ci-live` authored-ELF execution tests were skipped locally because this checkout has no provisioned bundled-Ghidra ext4 fixture mount; the full-mode live case now runs in that CI lane.

## Profile-bound full-export provenance checkpoint — 2026-09-25

The captured full-export assessment now records byte lengths for the input, exporter and Ghidra archive, plus the actual loader language and compiler specification from the completed exporter state. `GccDriverStructuralInputsV1.bindFullExport()` ties such a snapshot to the authenticated stripped GCC driver, the checked exporter/Ghidra runtime profile, the x86-64 SysV target descriptor and its ELF-derived image base and executable ranges. It reparses canonical model bytes, checks the binary binding and function inventory, and rejects function addresses outside the authenticated executable ranges or IDs that do not encode those addresses. The resulting `GccDriverStructuralFullExportBindingV1` is provenance evidence only; it still cannot create `VerifiedStructuralInputsV1` or authorize scoring.

Focused verification covers matching and substituted input, loader, target and function-address cases. It uses a synthetic canonical model with the checked profile metadata; it does not claim a live GCC driver export, independent identity replay, production score or production qualification.

The checked replay contract binds the profile, artifact manifest, stripped input binary and image base, target and normalization descriptors, boundary report, exporter, loader, runtime, identity verifier, sandbox, full recovery mode, output observations, and identity-map payload. The model provenance commitment also binds the identity receipt, boundary report, runtime, model and structural-observation outputs, and recovered-model ID. A model that repeats only the expected input-binary hash is rejected by `StructuralProductionReplayContractTest` before receipt creation.

The production gap remains explicit: `StructuralReplayAdapterRegistry.production` is empty and fail-closed, `VerifiedStructuralInputsV1` has no creator, and the checked `oracle/gcc/16.2.0` profile has no authenticated production structural model, identity-map replay, or structural score. The authored-ELF snapshot proves the contained full-export path and bounded host capture, but does not run the checked GCC 16.2.0 structural profile or authenticate its observations. Remaining gates are independent boundary and identity-map verification, checked GCC production artifacts bound to the authenticated manifest and target, and repeated byte-identical production replay evidence.

The future production adapter must keep unresolved, unobservable, contradicted, and fabricated states visible and use the application-bundled Ghidra Java APIs. Production qualification must not depend on `GHIDRA_HOME` or an external `analyzeHeadless` installation.

The A6 acceptance criterion remains open. No scored production model or production qualification is claimed.
