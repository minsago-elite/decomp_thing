# Structural production replay admission checkpoint

This is the focused evidence record for [#679](https://github.com/minsago-elite/decomp_thing/issues/679), recorded on 2026-09-08. It documents one contract boundary and does not claim production qualification.

## Input-profile implementation checkpoint — 2026-09-25

`GccDriverStructuralInputsV1` now admits the checked GCC 16.2.0 driver input profile in Kotlin/JVM. It pins the artifact-manifest, source-lock, build-record, and toolchain-reproduction hashes; checks the manifest's source/build links; inspects the full and stripped ELF twins with the bounded Kotlin ELF reader; checks both artifact records and target identity; and derives the stripped image base and executable ranges from the inspected ELF headers. A mutation test confirms that a substituted manifest is rejected even when it repeats the expected binary hashes.

This is input-profile groundwork only. It does not launch Ghidra, capture an exported model, perform the independent boundary or identity replay, create `VerifiedStructuralInputsV1`, or register a production adapter. No live GCC production replay was performed. The remaining production execution and scoring gates below are still open.

Focused verification: `./gradlew --no-daemon -Pkotlin.daemon.jvmargs=-Xmx4g test --tests 'decompengine.oracle.gcc.GccDriverStructuralProfileTest'` passed 2 tests with the repository-pinned Node 24.20.0/npm 11.19.0. The larger heap was needed for the repository's full Kotlin compile in this local environment; the repository's default 2 GiB Kotlin daemon heap exhausted memory during the first attempt.

The checked replay contract binds the profile, artifact manifest, stripped input binary and image base, target and normalization descriptors, boundary report, exporter, loader, runtime, identity verifier, sandbox, full recovery mode, output observations, and identity-map payload. The model provenance commitment also binds the identity receipt, boundary report, runtime, model and structural-observation outputs, and recovered-model ID. A model that repeats only the expected input-binary hash is rejected by `StructuralProductionReplayContractTest` before receipt creation.

The production gap remains explicit: `StructuralReplayAdapterRegistry.production` is empty and fail-closed, `VerifiedStructuralInputsV1` has no creator, and the checked `oracle/gcc/16.2.0` profile has no authenticated production structural model, identity-map replay, or structural score. The missing gates are a host-owned exporter/loader replay with bounded output capture and independent boundary and identity-map verification, checked GCC production artifacts bound to the authenticated manifest and target, and repeated byte-identical production replay evidence.

The future production adapter must keep unresolved, unobservable, contradicted, and fabricated states visible and use the application-bundled Ghidra Java APIs. Production qualification must not depend on `GHIDRA_HOME` or an external `analyzeHeadless` installation.

Validation for this slice: `git diff --check`. No full test run or production replay was performed.
