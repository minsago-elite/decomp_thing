# Issue #465 assessment-uncertainty evidence

Recorded 2026-09-08 from the current repository contracts. This is one
fixture/contract evidence slice; it does not close #465.

## Existing evidence

- `CanonicalProgramModelStreamingTest` constructs a schema-2 model from the
  checked canonical model fixture, retains an unknown global type (`undefined8`),
  and requires `ProgramModelJson` and the bounded streaming reader to return the
  same model and exact canonical bytes. The same test counts every entity as
  `recoveryAssessment: "unassessed"` and rejects substituted assessed claims.
- `GccCompilerEngineResumeEvidenceValidationTest` uses the authored two-batch
  transition fixture to validate a 512-function interrupted prefix followed by
  a 513-function resumed run and a fresh control. Its existing assertions require
  `non-authoritative-byte-assessment`, the frozen exporter-state digest, and the
  resumed model and module-plan byte digests.
- `GccCompilerEngineResumeEvidence` snapshots caller-owned state, progress,
  planning fragments, model, and plan bytes before validation; resume equivalence
  requires byte-identical state and frozen prefix artifacts, and byte-identical
  resumed/fresh model and plan bytes.

These facts preserve extraction labels separately from recovery assessment,
retain unresolved entities, and keep resumed export comparison at the committed
byte boundary.

## Production boundary

This evidence is authored-fixture and byte-contract evidence. It does not prove
that Ghidra ran, that an export was interrupted and resumed on disk, or that any
model finding is independently correct. The returned resume objects are
explicitly non-authoritative. Production assessment remains unavailable until
#40 supplies authenticated structural findings and #136 supplies the required
Kotlin-owned production oracle/replay path. Exporter-10 qualification of existing
authenticated production profiles is also outside this slice.

No full test suite or production gate was run for this note; the focused test
names above are retained source evidence, not a new execution claim.
