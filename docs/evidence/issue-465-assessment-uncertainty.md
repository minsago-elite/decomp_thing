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

## 2026-09-25 authored replay checkpoint

`GccCompilerEngineResumeEvidenceValidationTest.resumed schema two export keeps
unknown global type unassessed` places an `undefined8` global in the first
committed planning batch. It requires the recovered extraction label and
unassessed recovery label to survive typed and streaming reads, an interrupted
prefix, descriptor-bound resumed capture, and a fresh control. Resumed and fresh
model bytes must match; capture must leave the interrupted state and checkpoint
bytes unchanged. This is a synthetic exporter-10 planning transition, not a live
Ghidra run. Planning fragments cannot contain recovered function records or
decompiled bodies, so that replay fixture makes no such claim.

`CanonicalProgramModelStreamingTest.schema two keeps completed extraction and
unknown types unassessed with reader parity` separately retains a decompiled
function from the frozen historical fixture and checks that its schema-2
extraction label remains unresolved for recovery assessment. The reader parity,
historical-report, and contradictory-finding tests cover their respective
contracts independently. A joined, authenticated finding and production
exporter-10 run remain dependencies of #462, #40, and #136.

Verification on this checkpoint: the two changed focused cases passed, then
the four relevant regression classes passed with 65 tests, zero failures,
errors, or skips (`GccCompilerEngineResumeEvidenceValidationTest` 38,
`CanonicalProgramModelStreamingTest` 8, `StructuralRecoveryV1ParityTest` 3,
`ArchivalAuditProvenanceTest` 16). Both Gradle invocations used the pinned
frontend Node home. This is local regression evidence, not a full CI or
production qualification run.
