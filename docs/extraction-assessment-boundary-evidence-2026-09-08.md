# Extraction and recovery assessment boundary evidence for #363

This is a small evidence record captured from repository commit
`bf2501568f39ab52b23492dfc37839bb81895587` on 2026-09-08. It records existing
contracts; it is not production qualification or a completion claim for #363.

```yaml
schemaVersion: 1
issue: 363
kind: extraction-assessment-boundary-evidence
authority: non-authoritative-contract-evidence
releaseEligible: false
state: unresolved
```

The current tree establishes this contract:

- Schema-2 extracted entities carry `extractionStatus` and
  `recoveryAssessment: "unassessed"`. The bounded streaming reader rejects a
  scored assessment claim, while schema-1 canonical bytes remain compatible
  (`src/main/kotlin/decompengine/oracle/structural/CanonicalProgramModelStreaming.kt`).
- A completed extraction, including a retained unknown type string, supplies no
  source or ABI correctness finding. A future assessment join must retain the
  exact model identity and leave missing, unknown, contradicted, and
  oracle-unobservable findings unresolved until independently validated evidence
  is available (`docs/extracted-program-model-v2.md`).
- The production replay registry is intentionally empty. Its fixed transcript
  seam is test-only, and `VerifiedStructuralInputsV1` has no public creator;
  authenticated receipts therefore remain provenance-bound evidence rather than
  a production assessment (`StructuralReplayAdapterRegistry.kt`,
  `StructuralProductionReplayContract.kt`).

The focused existing regressions provide the checked evidence for this slice:
`CanonicalProgramModelStreamingTest` verifies typed/streaming parity and rejects
assessment claims, while `StructuralProductionReplayContractTest` verifies that
the test-only replay seam cannot reach the production registry or verified-input
capability. Fixture success does not qualify production scoring.

The following production gates remain unavailable for this record:

- #462/#40/#136: an authenticated production structural replay, independently
  validated per-entity findings, a registered production adapter, and a checked
  GCC oracle/score regenerated from those inputs are still missing.
- #42: calibrated recovery probability is unavailable until validated scored
  evidence exists; extraction labels and fixture receipts cannot supply it.
- Existing authenticated production profiles must be regenerated and qualified
  for exporter version 10. No production exporter qualification or full GCC/LLVM
  scoring run was performed here.

Any future implementation must keep bundled Java-API Ghidra execution isolated,
retain authenticated oracle and provenance bindings, and preserve explicit
unresolved states. This record does not authorize `GHIDRA_HOME`, an external
`analyzeHeadless`, a fixture as production authority, or an assessment upgrade
from successful extraction.
