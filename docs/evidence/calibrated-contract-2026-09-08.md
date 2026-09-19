# Calibrated contract rendering evidence — 2026-09-08

This is a repository-fact checkpoint for #687 at commit `bf250156`.

The checked producers and consumers agree on the meaning of the currently
available scores:

- `SourceTree.kt` writes `scoreInterpretation` into `reports/confidence.json`
  with `kind: structural-recovery`.
- `AutomaticExploration.kt` writes the same version-1 descriptor into the
  `confidence` object in `reports/exploration.json` with
  `kind: exploration-breadth`.
- `HeuristicScoreInterpretation.kt` declares both descriptors as
  `calibrationStatus: uncalibrated` and leaves calibrated probability,
  calibration artifact identity, and empirical sample count null.
- `Main.kt` calls reconstruction accuracy `unassessed` and calls the
  exploration value an `uncalibrated exploration heuristic`.
- `WebViews.kt` labels the corresponding views as an exploration heuristic or
  an uncalibrated structural heuristic, and says scored recovery evidence is
  unavailable in the source view.
- `ArchivalAudit.kt` retains a model-bound `recoveryAssessment` whose state is
  `unassessed` and states that extraction, compilation, and local behavior do
  not establish calibrated recovery accuracy.

This evidence is presentation and contract continuity only. Production
qualification remains unavailable: the repository has no checked empirical
GCC calibration artifact, no completed validated production structural input
population, and no completed required-behavior evidence that could establish
calibration tolerances, out-of-distribution handling, or passed equivalence.
The current reports therefore preserve unresolved states and provenance and
must not be read as calibrated recovery confidence or release certification.

This record makes no claim about an external `GHIDRA_HOME` installation or an
unauthenticated oracle. Bundled Ghidra isolation and authenticated oracle
boundaries remain outside this documentation-only checkpoint.
