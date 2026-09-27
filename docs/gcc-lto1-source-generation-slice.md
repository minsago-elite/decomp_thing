# lto1 source-generation slice (#1051)

This slice records the current authenticated handoff available for lto1. It is
evidence for follow-up implementation work; it does not qualify a complete
lto1 source tree.

`GccCompilerEnginePlanningService` authenticates the selected lto1 stripped
artifact through `GccCompilerEngineSuite`, requires the current program-model
schema, runs the bounded `DeterministicModulePlanner`, and checks that every
function, global, and type is owned exactly once. It publishes the canonical
`planning/module_plan.json` together with the program-model binding and the
planner assessment.

The assessment is intentionally marked `complete: false` and
`releaseEligible: false`. Its authority is
`non-authoritative-caller-supplied-analyzer-v1`; therefore it is a retained
planning diagnostic, not evidence that lto1 source was generated or accepted.
The existing source generator and ACP-backed module reconstructor remain
separate workflow components until a release-owned lto1 handoff binds them to
this plan.

## Qualification status

The following #1051 requirements remain unverified by this slice:

1. Every required lto1 implementation is reconstructed through configured ACP
   with bounded context and dependencies, while unresolved implementations and
   interfaces remain explicit.
2. Accepted source bytes are bound to the complete protocol, implementation,
   capability, session, turn, event, change, policy, sandbox, and validation
   receipt chain.
3. Missing required implementations block release of the lto1 source tree.

The next implementation slice must consume the authenticated completed plan,
provision the configured ACP workflow, and publish source and receipt evidence
that changes the assessment from planning-only evidence to a release-owned
qualification result.
