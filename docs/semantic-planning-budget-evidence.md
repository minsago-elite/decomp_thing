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

This evidence is local fixture behavior. The semantic-planning boundary still
does not retain a separate structured planning receipt containing the complete
profile configuration, host ceiling, measured planner outcome, and exact plan
commitment. The deterministic planner's counters are logical work accounting;
they do not qualify wall-clock or resident-memory enforcement. No production
Ghidra, authenticated oracle, cgroup, or release-authority qualification is
claimed here. These are remaining gaps for issue #1058 and its parent #826.
