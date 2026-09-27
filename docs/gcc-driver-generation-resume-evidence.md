# Full-driver generation resume evidence

This is the narrow source-generation contract slice for issue #697. It records
existing repository evidence; it does not claim a completed GCC production run.

The focused test
`SourceTreeTest.interrupted generation preserves accepted module bytes and resumes at the unfinished module`
establishes these local facts:

- an interruption of the `parse` module raises
  `ModuleReconstructionInterruptedException` and leaves an interruption report;
- the already accepted `render` source is retained and its SHA-256 is captured
  before the interruption;
- the resumed request invokes the reconstructor only for `parse`, while the
  retained `render` source hash is unchanged;
- the resumed manifest has no unresolved implementation IDs and the temporary
  interruption report is removed.

The corresponding contract is source-hash-bound reuse: accepted module bytes
remain authoritative across an interrupted request, and remaining work is
attributable to the module that was not accepted. This fixture is local
generated-C coverage. It does not invoke Ghidra, access an oracle, or create a
production receipt, so it preserves the bundled-Ghidra isolation and the
authenticated-oracle boundary.

The following production gates remain unavailable for this slice:

- a complete authenticated GCC driver run through the configured reconstruction
  agent, with a production run identity and one bounded receipt for every
  planner-owned function/global, including unresolved outcomes (#696/#47);
- an interruption/restart demonstration against that complete driver run with
  unchanged accepted source hashes and attributable remaining work (#697);
- production clean-build, behavior, containment, and release qualification
  consumed by the downstream A8 gates.

Those gaps remain unresolved rather than inferred from the fixture. The focused
source-tree test is the evidence boundary for this record.
