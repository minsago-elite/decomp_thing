# Issue 1726 focused verification

Base: `c5acf81875fd0518e65bb79ed957abf33972d9b1` (selected-boundary consumers).
Only new population/projection source, tests, schemas and documentation are added.
No production registration, coordinator, native exporter, independent producer,
external composer or historical fixture scorer is changed.

## JVM verification

Final focused run: **40 tests passed, zero failures, errors or skips**.

- `StructuralCallPopulationV1Test`: 17 semantic/conservation/negative-control tests.
- `StructuralSelectedBoundaryProjectionV1Test`: 10 projection, substitution,
  immutable snapshot and JVM constructor-bridge tests.
- Existing `StructuralFunctionAccuracyV1Test`: 13 regression tests.

The first run exposed the new component's requested JSON node ceiling exceeding
that of the shared parser; the component now uses the existing one-million node
limit. Independent test-inventory review then found one malformed-envelope test
was silently undiscovered because the generic fixture helper inferred a non-void
return type. The helper now explicitly accepts and returns `Unit`.

The final run passed all **40 intended tests in 4m5s**. A separate source-to-XML
inventory comparison required every `@Test` declaration's exact name to appear in
JUnit output, with no missing or unexpected cases. This explicitly includes
`unbound incomplete envelopes and noncanonical commitments fail`. The earlier
39-test result is superseded; it did not execute that assertion group.

Final log: `issue1726-call-population-test.log` alongside this file (trailing whitespace normalized).
SHA-256: `5d91c4efccafa0a87d7da97ce22e279e1ffb862047cc89663fc147492edbf445`.

Invocation used Java 21, the repository-local Gradle 9.6.1 distribution/cache,
`--offline --no-daemon`, and these arguments:

```text
test
--tests decompengine.oracle.structural.StructuralCallPopulationV1Test
--tests decompengine.oracle.structural.StructuralSelectedBoundaryProjectionV1Test
--tests decompengine.oracle.structural.StructuralFunctionAccuracyV1Test
-x stageFrontend
-x gccCompilerEnginePlanningIsolated
-x snapshotCapsuleAuditDataTest
```

`TMPDIR`, Java/JNA temporary directories, JVM user home and test-process temporary
directories were under this worktree. JVM performance-data output was disabled.
Product resource limits were unchanged. Excluded frontend and unrelated isolated
suites were not claimed as verified. No actual Ghidra/native capture or production
call qualification was performed by these authored component tests.

## Independent source and schema review

The parent independently reviewed both implementations and semantic controls,
including complete selected universes, live-capability constructor validation,
independent coordinate pairs, zero-credit unmatched recovery and raw conservation.
No remaining source defect was found. Documentation explicitly treats metrics as
conservative exact-credit fractions and leaves all call authority unavailable.

Both closed schemas compiled using the installed `fastjsonschema` validator's
compatible draft-7 subset; the schemas use no draft-2020-only validation keywords.
The parent independently checked an authored zero-call input/report, unknown root
fields and a forged `productionVerified` flag. Semantic cross-record invariants
are enforced by Kotlin and report recomputation, not JSON Schema alone.

The CI and automatic review gates still apply to the pull request. This evidence
closes only issue 1726's shared foundation when merged; it does not establish
complete native/oracle authentication or any production accuracy threshold.
