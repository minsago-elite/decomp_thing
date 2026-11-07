# Historical schema-3 pending graph fixture

- Producer revision: `c19636157b1cc3081b6df3dd8417a4e53fc729aa` (the parent of the schema-4 migration commit).
- Producer file: `src/main/kotlin/decompengine/repair/ModuleRevisionGraph.kt` at that revision.
- State: actual schema-3 writer output after `beginAttempt()` and
  `installCandidate()` for `src/modules/alpha.c`, before accept or reject.
- Capture: compiled that producer revision and ran its graph test suite with a
  temporary test-only capture method. No production source was changed by the
  capture method. The closed project, graph, and content-addressed blobs are
  preserved here.
- Reproduce and byte-compare the complete fixture with
  `python3 scripts/verify-legacy-repair-graph-fixtures.py` from the repository
  root. `SHA256SUMS` records the checked-in payload file digests. The writer
  takes run start/deadline timestamps from the wall clock; the verifier
  normalizes only those two values before comparing the graph. Every other
  graph field and fixture file must match exactly.

This fixture is historical wire evidence for current-reader pending recovery;
it does not establish archive admission or hosted/production qualification.
