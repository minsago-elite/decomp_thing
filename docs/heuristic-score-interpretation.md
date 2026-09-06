# Heuristic score interpretation

Source-tree confidence reports include a top-level `scoreInterpretation` for their
project and module scores. Exploration reports include it inside `confidence`.
Both use the closed version-1 contract in
[`heuristic-score-interpretation.schema.json`](../oracle/heuristic-score-interpretation.schema.json).

`kind` distinguishes structural recovery from exploration breadth. The current
fixed weighting formulas have `calibrationStatus: "uncalibrated"`, with null
`calibratedProbability`, `calibrationArtifactSha256` and `empiricalSampleCount`.
Null support means unavailable evidence, not an empirical study with zero samples.
Even a heuristic score of 1.0 does not become a calibrated probability.

The descriptor is additive to existing report formats and covers only score
interpretation. Missing descriptors in historical reports do not imply calibration.
Existing numeric fields remain available for heuristic comparisons. Web and CLI
views identify these scores as uncalibrated regardless of historical labels.

Version 1 cannot represent a calibrated assessment. A future assessment contract
must validate exact revision and oracle identities, sample support, empirical error
rates, tolerance, distribution applicability and required behavior before exposing
any calibrated value. This descriptor neither supplies those inputs nor grants
structural, behavior, containment or release authority. It is a foundation for #42;
the complete production calibration requirement remains open.
