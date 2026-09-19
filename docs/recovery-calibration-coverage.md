# Recovery calibration coverage record

This record is the bounded #42 evidence slice reviewed on 2026-09-08. It
describes the checked tree at base commit `bf2501568f39ab52b23492dfc37839bb81895587`.
It is a coverage boundary, not a calibrated accuracy claim or a production
qualification report.

`unavailable` means that the required authenticated artifact or run does not
exist in the checked tree. `unresolved` means that the contract has an explicit
unknown or unassessed state, but the independently validated evidence needed to
resolve it has not been admitted. A heuristic score is never treated as a
calibrated probability.

## Current coverage

| #42 acceptance area | Checked coverage | State | Remaining boundary |
| --- | --- | --- | --- |
| Extraction versus recovery assessment | Extracted model v2 carries `extractionStatus` separately from `recoveryAssessment: "unassessed"`. The model-bound recovery population lists every function, global, and type as unassessed. The structural scorer separately defines `exact`, `abi-equivalent`, `recovered-unknown`, `oracle-unobservable`, `contradicted`, and `fabricated` outcomes. | `partial` | Join those findings to model entities only after authenticated #40 production evidence exists; preserve unknown, contradicted, and unobservable findings through every consumer. |
| Entity, module, and project aggregation | The program-neutral fixture scorer emits deterministic per-entity, per-dimension, and aggregate metrics over all 20 structural dimensions. Unknown and unobservable oracle facts remain in denominators, and fabricated recovered facts do not consume an oracle denominator. | `unresolved` | No authenticated GCC production structural finding is available to derive conservative module/project recovery status. |
| Calibration artifact, support, and distribution | The version-1 score interpretation is closed and additive, but it permits only `calibrationStatus: "uncalibrated"` with null calibrated probability, artifact identity, and empirical sample count. | `unavailable` | #684 must define versioned bands, minimum support, empirical error rates, applicability, and out-of-distribution handling from validated #40 evidence. |
| Empirical error tolerance | No checked calibration sample partition, observed oracle error table, declared tolerance, or tolerance test exists. | `unavailable` | #685 must verify every reported band against measured oracle error within its declared tolerance. |
| Evidence-gated equivalence | The checked GCC behavior corpus is a 14-case reference corpus with byte-bound evidence (`behavior-corpus.json` SHA-256 `bcc1a14ca8c54f94106c943f0bc5698cb9af3151b7bf20a49ae3c8828baaad0e`; evidence SHA-256 `9dcf787aea232615a1ff8721144b86bc1f5e9a2a7068fa9e9280db0bc4ad6803`). It does not contain a current reconstructed-candidate result that can establish equivalence. | `unresolved` | #686 must derive `not-assessed`, `blocked`, or `passed` from current required behavior evidence, with missing, stale, and failed evidence blocking equivalence. |
| Report, CLI, and web consumers | Current score views identify fixed structural and exploration values as uncalibrated heuristics. Current schema-2 reports retain extraction labels and expose recovery as unassessed. | `partial` | #687 must consume one verified calibrated contract consistently and keep exploration breadth out of calibrated recovery confidence. |
| Deterministic GCC calibration regeneration | The GCC profile contains a checked source/toolchain identity, function-boundary oracle, and behavior corpus. It has no checked production structural oracle/score for interfaces, calls, globals, and types, and no calibration artifact. | `unavailable` | #679 must first admit an authenticated production replay; #680–#683 must produce and byte-identically regenerate the complete structural evidence before #688 can regenerate a GCC calibration artifact. |

The current structural contract is useful evidence of scoring semantics, not of
GCC recovery accuracy. Its fixture path is deliberately non-production: the
production structural replay registry is empty, and the fixture scorer refuses
production-scoped inputs. A schema-valid report or a caller-supplied model cannot
upgrade the states above.

## Provenance and authority boundary

The relevant checked contracts are:

- [`docs/extracted-program-model-v2.md`](extracted-program-model-v2.md) and
  [`oracle/extracted-program-model-v2.schema.json`](../oracle/extracted-program-model-v2.schema.json)
  for the extraction/unassessed split;
- [`docs/structural-recovery-scoring.md`](structural-recovery-scoring.md) and
  [`oracle/structural-score.schema.json`](../oracle/structural-score.schema.json)
  for dimensions, evidence outcomes, denominators, and fixture-only status;
- [`docs/heuristic-score-interpretation.md`](heuristic-score-interpretation.md)
  and [`oracle/heuristic-score-interpretation.schema.json`](../oracle/heuristic-score-interpretation.schema.json)
  for explicit uncalibrated output; and
- [`StructuralReplayAdapterRegistry.kt`](../src/main/kotlin/decompengine/oracle/structural/StructuralReplayAdapterRegistry.kt)
  for the fail-closed empty production registry and test-only replay seam.

Any future production qualification must retain the authenticated exporter,
loader/target, image-base, input-binary, sandbox, output-tree, model,
structural-observation, and identity-map evidence required by the replay
contract. This record does not add an adapter, accept a caller-owned model, or
change the bundled Ghidra Java-API execution and oracle authority boundaries.

## Next reviewable boundary

The next actionable dependency is #679: admit one authenticated stripped-GCC
production replay input set through a host-owned adapter, retain the complete
replay evidence above, and reject a caller-supplied JSON model that merely
repeats the expected binary hash. Until that boundary and the subsequent #40
structural scoring work land, calibrated probability, empirical tolerance, and
equivalence remain explicitly unavailable or unresolved as recorded here.

## Focused validation

At this checkpoint:

- `python3 -m unittest tests.oracle.test_structural_recovery -q` passed 40 tests;
- the focused Kotlin structural parity, mutation, production-replay-contract,
  and canonical-streaming test classes passed with Gradle; and
- no full suite, GCC production replay, reconstructed-candidate behavior run,
  or calibration qualification was performed.
