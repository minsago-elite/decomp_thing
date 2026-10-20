# Semantic planning budget evidence

This is the bounded evidence slice for issue #1058. It records the current
local behavior at the generated source-tree semantic-planning boundary.

`SourceTreeGenerator.generate` admits the immutable reconstruction profile
against `ReconstructionHostSafetyLimits` before selecting a planner, invoking
reconstruction callbacks, or creating source-tree files. The selected
`DeterministicModulePlanner` consumes the profile's entity, dependency-edge,
work-unit, module-size, and declared module-path limits. An explicitly supplied
planner is capped by those profile limits while retaining any tighter caller
limits.

The focused fixtures provide the following evidence:

- `ProfiledModulePlanningTest` rejects entity, dependency-edge, and work-unit
  exhaustion before a project or reconstruction callback exists, and checks
  profile-selected module sizes and paths.
- `SourceGenerationHostAdmissionTest` rejects each host ceiling before source
  generation and checks that the selected profile identity and budgets remain
  unchanged when a host explicitly admits them.

`reports/confidence.json` retains `semanticPlanningBudgetEvidence` with schema
version 1, the selected profile ID, digest and complete descriptor, independent
host safety limits, and effective planner limits after any tighter caller bounds.
Its outcome records the planned module count, function/global/type counts,
dependency-edge count and sparse-work count. The module plan remains separate
evidence. `ProfiledModulePlanningTest` checks the receipt's profile, effective
limits and observed outcome, including a caller limit tighter than the profile.
This implements the budget-accounting slice closed in issue #1058.

This is local fixture and logical-work evidence. The counters do not qualify
wall-clock or resident-memory enforcement, production Ghidra, authenticated
oracle execution, cgroup containment or release authority. Whole-operation
planner/publication resource enforcement remains open under #982. Parent #826
also remains open for the production behavior-validation boundary in #1061;
the planning receipt does not supply that boundary's missing evidence.
