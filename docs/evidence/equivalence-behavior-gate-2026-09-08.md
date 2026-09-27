# Equivalence behavior gate — 2026-09-08

This slice records the current contract for issue #686. `ArchivalProjectAuditor`
now derives `equivalenceStatus` from the caller-selected `requiredCorpusSha256`
and the independently rechecked revision-bound behavior reports:

- `not-assessed` means no required behavior corpus was selected.
- `blocked` means the selected corpus is missing, stale, malformed, unresolved,
  unavailable, or has a mismatching exit/status/output observation.
- `passed` means every selected current corpus is observed and all selected
  behavior comparisons match. It is an evidence-gate result, not a universal
  equivalence or production-qualification claim.

The audit retains `equivalenceBlockers` as stable reason codes and keeps the
legacy `universalEquivalenceClaim` false. A report's self-computed corpus digest
does not select the required corpus; callers must provide that policy explicitly.

The repository facts still leave production qualification unavailable:

- `SandboxRunner` records local path-stability checks and explicitly does not
  provide production authority or a retained containment receipt.
- The audit records no observed network-isolation receipt, module execution
  coverage remains `not-observed`, and behavior reports are bound to the local
  project revision rather than an authenticated production candidate replay.
- The authenticated production structural replay and checked GCC interface,
  call, global, type score required by #40 are still absent; the production
  structural adapter registry remains empty.
- The independent behavior corpus in #41 is available as a versioned reference
  contract, but it does not by itself qualify a reconstructed production run.

Therefore this change supplies the evidence-state contract and conservative
blocking behavior. It does not claim merged production behavior or close the
remaining authenticated replay, containment, structural-oracle, calibration,
or release gates.
