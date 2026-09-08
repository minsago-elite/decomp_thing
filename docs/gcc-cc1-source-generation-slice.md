# cc1 source-generation slice (#1050)

This slice records the current authenticated handoff available for cc1. It is
evidence for follow-up implementation work; it does not qualify a complete
cc1 source tree.

`GccCompilerEnginePlanningService` authenticates the selected cc1 stripped
artifact through `GccCompilerEngineSuite`, requires the current program-model
schema, runs the bounded `DeterministicModulePlanner`, and checks that every
function, global, and type is owned exactly once. It publishes the canonical
`planning/module_plan.json` together with the program-model binding and the
planner assessment:

```sh
build/install/llm_bin_patch/bin/llm_bin_patch gcc-engine-plan cc1 \
  /absolute/path/to/gcc-cc1.stripped \
  --profile oracle/gcc/16.2.0/compiler-engines.json \
  --ghidra-archive /absolute/path/to/ghidra_12.1.3_PUBLIC_20260817.zip \
  --output /absolute/path/to/cc1-plan
```

The assessment is intentionally marked `complete: false` and
`releaseEligible: false`. Its authority is
`non-authoritative-caller-supplied-analyzer-v1`; therefore it is a retained
planning diagnostic, not evidence that cc1 source was generated or accepted.
The existing source generator and ACP-backed module reconstructor remain
separate workflow components until a release-owned cc1 handoff binds them to
this plan. A clean archive/build result from the separate #1052 boundary
cannot supply that missing reconstruction or ACP evidence.

## Qualification status

The following #1050 requirements remain unverified by this slice:

1. The authenticated completed cc1 model/plan and exact ownership are consumed
   while explicit unresolved implementations and interfaces remain preserved.
2. Every required cc1 implementation is reconstructed through configured ACP
   with bounded module/dependency context; generic returns, monolithic collapse,
   undeclared shims, missing provisioning, and direct-provider fallback cannot
   count as accepted implementations.
3. Accepted source bytes are bound to the complete protocol, implementation,
   capability, session, turn, event, change, policy, sandbox, and validation
   receipt chain, and missing required implementations block release.

The next implementation slice must consume the authenticated completed plan,
provision the configured ACP workflow, and publish source and receipt evidence
that changes the assessment from planning-only evidence to a release-owned
qualification result.
