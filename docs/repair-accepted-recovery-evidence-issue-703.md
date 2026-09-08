# Accepted revision recovery evidence boundary

Issue #703's current repository contract has two separate recovery lanes.

The generic repair graph writes candidate blobs and its pending journal before
source installation. On reopen, `ModuleRevisionGraph` restores the authorized
preimages, records one deterministic `crash-recovery` rejection, and only then
allows normal index and validation work. A provisional node is retained in
`provisionalHeadId`; only full retained behavior validation can promote a
detached candidate and advance `fullyAcceptedHeadId`. An interrupted or
validation-failed run therefore retains its last accepted commitment and does
not turn an in-flight candidate into accepted source.

The workflow projection carries the same boundary: provisional, rejected,
cancelled, interrupted, exhausted, and resource-exhausted observations do not
carry an accepted source commitment. An accepted observation requires the
commitment from the fully accepted graph head. The projection is an operator
view; the graph, journal, blobs, validation proof, and archive verifier remain
the authority.

The bundled GCC resume validator independently checks byte-identical retained
prefixes, resumed reuse, fresh-control output, and bounded model/plan equality.
Those assessments are explicitly non-authoritative byte assessments. The
prepared bundled operation supports same-owner in-process resume, while cold
restart recovery and release qualification remain unverified.

This is a contract/evidence slice from existing code and focused tests; it does
not claim #703's acceptance criterion. The missing production evidence is a
real production-shaped GCC-driver publication and validation interruption run
that proves byte-identical rollback and retained accepted-head recovery, with
exact independent resource accounting and archive provenance. The strict
contained generated-C validation provider remains behind its production
qualification guard, and #702's real-driver run is still open. Test fixtures,
caller-supplied oracle bytes, host-process fallback, external `GHIDRA_HOME`, or
`analyzeHeadless` do not discharge that gate. Bundled Ghidra isolation,
authenticated oracle boundaries, provenance, and unresolved outcomes remain in
force.

Source facts: `ModuleRevisionGraph.kt`, `TraceGuidedRepair.kt`,
`AgentWorkflowProgress.kt`, `GccCompilerEngineResumeEvidence.kt`,
`GccBundledPreparedOperations` documentation, and their focused tests.
