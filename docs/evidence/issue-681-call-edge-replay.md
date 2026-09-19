# Issue #681 call-edge replay evidence

Recorded 2026-09-08 from the current repository contracts. This is one
fixture/contract evidence slice; it does not close #681.

## Existing evidence

- `oracle/full-tree-call-truth-v2.schema.json` requires a stable
  `call-edge-<sha256-prefix>` identity, explicit `scored` or `unobservable`
  population, caller/target identities, observation IDs, and closed target
  kinds for direct-internal, external, proven-indirect, unresolved-indirect,
  and virtual-unresolved calls.
- `docs/full-tree-call-coordinates-v4.md` keeps call-instruction and return
  coordinates separate. Missing coordinates remain missing; no coordinate is
  synthesized from the other coordinate, instruction length, tail-call status,
  or a recovered model.
- `FullTreeCallTruthAssessmentTest` exercises all five target kinds, stable
  cross-shard function identities, external calls without ELF evidence,
  ambiguous aliases, unresolved thunk semantics, and unproven virtual target
  sets. The corresponding facts remain explicitly unobservable where the
  source evidence is insufficient.
- `FullTreeCallBaselineSqliteTest` records the bounded fixture result as
  `exact=7`, `partial=2`, `excluded=2`, and `denominator=9`, with
  `missing=0` and `fabricated=0`. It also requires
  `downstreamScoringAuthorized=false`, `authoritativeReleaseEvidence=false`,
  and `recoveredModelScored=false`. These are raw observability counts, not
  recovered-model accuracy.
- `docs/structural-recovery-scoring.md` provides the generic outcome lattice:
  exact, ABI-equivalent, recovered-unknown, oracle-unobservable, contradicted,
  and fabricated. It requires stable identity mapping and keeps an unknown
  recovered fact in the oracle denominator.

## Production gap

The production structural replay registry remains intentionally empty in
`StructuralReplayAdapterRegistry.kt`; only a fixed test-only transcript can be
replayed. The repository therefore has no authenticated GCC production
call-edge exporter/model/identity-map replay, no retained production score,
and no production precision/recall evidence for internal, external, or
indirect calls. #679's authenticated production input admission is still
unresolved as well.

This note preserves the existing bundled-Ghidra and authenticated-oracle
boundary. It does not promote fixture transcripts, raw call observability, or
the historical function oracle into production authority, and it leaves
unknown, unobservable, contradicted, and fabricated findings unresolved until
the production replay adapter and retained evidence exist.
