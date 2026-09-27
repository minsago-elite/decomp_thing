# Structural production replay admission checkpoint

This is the focused evidence record for [#679](https://github.com/minsago-elite/decomp_thing/issues/679), recorded on 2026-09-08. It documents one contract boundary and does not claim production qualification.

The checked replay contract binds the profile, artifact manifest, stripped input binary and image base, target and normalization descriptors, boundary report, exporter, loader, runtime, identity verifier, sandbox, full recovery mode, output observations, and identity-map payload. The model provenance commitment also binds the identity receipt, boundary report, runtime, model and structural-observation outputs, and recovered-model ID. A model that repeats only the expected input-binary hash is rejected by `StructuralProductionReplayContractTest` before receipt creation.

The production gap remains explicit: `StructuralReplayAdapterRegistry.production` is empty and fail-closed, `VerifiedStructuralInputsV1` has no creator, and the checked `oracle/gcc/16.2.0` profile has no authenticated production structural model, identity-map replay, or structural score. The missing gates are a host-owned exporter/loader replay with bounded output capture and independent boundary and identity-map verification, checked GCC production artifacts bound to the authenticated manifest and target, and repeated byte-identical production replay evidence.

The future production adapter must keep unresolved, unobservable, contradicted, and fabricated states visible and use the application-bundled Ghidra Java APIs. Production qualification must not depend on `GHIDRA_HOME` or an external `analyzeHeadless` installation.

Validation for this slice: `git diff --check`. No full test run or production replay was performed.
