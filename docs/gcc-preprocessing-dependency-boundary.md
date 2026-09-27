# GCC preprocessing and dependency boundary

[`preprocessing-dependency-boundary.json`](../oracle/gcc/16.2.0/preprocessing-dependency-boundary.json)
records the current qualification boundary for issue #52 from the checked GCC
corpus and evidence pair. The pair is authenticated to the recorded stripped
driver, GCC source lock, build record, and oracle manifest hashes.

The two existing preprocessing cases pass through `-B/workspace/tools/` to a
staged mock `cc1`; both produce the fixed `MOCK-PREPROCESSED` line. Their
`passed` observations therefore establish driver forwarding and sandboxed
execution only. Include search, macro definition and undefinition, language
selection, preprocessing diagnostics, dependency generation, and reconstructed
candidate comparison remain `unavailable`. Live reproduction against the
exact OCI profile remains `unresolved`; a profile mismatch is an unavailable
qualification result rather than a substitute success.

The production gap is real frontend/dependency evidence with independently
captured inputs, diagnostics, artifacts, tool/resource identities, and exact
provenance, followed by authenticated reconstructed-driver comparison. This
record does not claim issue #52 completion.
