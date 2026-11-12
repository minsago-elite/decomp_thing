# Historical schema-1 pending graph fixture

- Producer revision: `d58e62203c2e992183a730875c4bca9eb90b5130`.
- Producer file: `src/main/kotlin/decompengine/repair/ModuleRevisionGraph.kt` at that revision.
- State: actual schema-1 writer output after `beginAttempt()` and
  `installCandidate()` for `src/modules/alpha.c`, before accept or reject.
- Capture: compiled that producer revision and ran its graph test suite with a
  temporary test-only capture method. No production source was changed by the
  capture method. The closed project, graph, and content-addressed blobs are
  preserved here.
- Reproduce and byte-compare the complete fixture with
  `python3 scripts/verify-legacy-repair-graph-fixtures.py` from the repository
  root. `SHA256SUMS` records the checked-in payload file digests.

This fixture is historical wire evidence for current-reader pending recovery;
it does not establish archive admission or hosted/production qualification.
