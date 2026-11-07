# Historical schema-4 pending graph fixture

- Producer revision: `2b1121999c806d5b3f89d3723fca8a39879c49b1` (the fetched `master` revision).
- Producer file: `src/main/kotlin/decompengine/repair/ModuleRevisionGraph.kt` at that revision.
- Producer writer: the schema-4 graph serializer and persistence path in that exact source tree.
- State: a real schema-4 graph after `enableRunContract()`, `beginAttempt()` and `installCandidate()` for `src/modules/alpha.c`, before acceptance or rejection. The full project state and content-addressed blobs are preserved beside `graph.json`.

The fixture was captured by compiling the producer revision and running its
`ModuleRevisionGraphTest` class with a temporary test-only capture method. That
method did not alter production sources; it asserted `snapshot.schemaVersion ==
4` before beginning the pending attempt and copied the completed project after
the historical writer closed. Frontend tasks were excluded because this test
uses only the backend graph writer. The temporary capture method and output
checkout are not inputs to normal tests.

Reproduce and byte-compare the complete fixture with
`python3 scripts/verify-legacy-repair-graph-fixtures.py` from the repository
root. `SHA256SUMS` records the checked-in payload file digests.
