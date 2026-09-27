# GCC calibration artifact evidence

This record is the bounded evidence slice for #688 at commit
`bf2501568f39ab52b23492dfc37839bb81895587`. It records repository facts; it
does not claim that a calibrated GCC artifact exists.

## Checked facts

- The GCC profile retains versioned source, build, oracle, and behavior inputs
  under `oracle/gcc/16.2.0/`, including `source-lock.json`,
  `build-record.json`, `oracle-manifest.json`,
  `function-recovery-oracle.json`, `behavior-corpus.json`, and
  `behavior-corpus-evidence.json`.
- The generic score interpretation contract in
  `oracle/heuristic-score-interpretation.schema.json` permits only
  `calibrationStatus: "uncalibrated"`, with null calibrated probability,
  artifact identity, and empirical sample count.
- No checked GCC calibration artifact, production structural score, validated
  sample partition, observed error table, or declared error tolerance is
  present in this tree.

The resulting state for this issue is `unavailable`. Existing GCC source,
function-boundary, and behavior artifacts are provenance and reference inputs;
they are not empirical calibration evidence.

## Production gap

The production structural replay registry is empty, and the structural scorer's
fixture path cannot supply production authority. Therefore the authenticated
GCC replay and structural evidence required before calibration remain
unavailable. In dependency order, #679 must admit the authenticated replay,
#680–#683 must produce the complete structural oracle and score, and #685 must
verify observed band error against declared tolerances after #684 defines the
bands, support, applicability, and out-of-distribution handling.

This record deliberately adds no threshold and does not upgrade an unresolved
or uncalibrated state. A future artifact must keep GCC-specific provenance and
sample policy in `oracle/gcc`, while generic calibration and status code stays
program-neutral. Production analysis must continue to use the bundled Ghidra
Java APIs in isolated workers and authenticated oracle boundaries; this slice
does not add an external `GHIDRA_HOME` or `analyzeHeadless` dependency.

## Validation boundary

No production replay, reconstructed-candidate run, or calibration
qualification was performed for this slice. The remaining production gates are
intentionally recorded as unavailable rather than inferred from fixture or
reference-only evidence.
