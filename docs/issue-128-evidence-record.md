# #128 evidence record: raw call observability boundary

Recorded 2026-09-08 from the existing Kotlin fixture and contract tests. This is
one fixture-scale evidence record; it does not close #128 or authorize scoring.

The three-shard raw call fixture contains 12 observations that deterministically
collapse to 11 call edges. Its existing observability baseline reports:

| metric | value |
| --- | ---: |
| truth denominator | 9 |
| exact observable edges | 7 |
| partial observable edges | 2 |
| excluded/unobservable edges | 2 |
| missing candidate edges | 0 |
| fabricated candidate edges | 0 |

These values are asserted by
`FullTreeCallBaselineSqliteTest`. The two partial edges retain their raw truth
reason codes, and excluded edges remain outside the denominator. The baseline
receipt and the location-bearing `RecoveredCallSites` receipt keep
`downstreamScoringAuthorized`, `authoritativeReleaseEvidence`, and
`recoveredModelScored` false. The values therefore describe raw truth
observability and candidate input boundaries, not recovered-model accuracy.

The production gap is the missing authenticated join and scorer that would map
caller-local candidate sites to cross-shard truth identities and emit exact,
partial, missing, and fabricated outcomes. Relocation-bound external/PLT
identity, proven virtual target sets, normalized thunk semantics, decoder-backed
coordinate reconciliation where raw pairs are absent, all-shard scale, and the
contained bundled-Ghidra production/runtime gates remain unavailable. Any future
implementation must retain the raw input digests, candidate-only provenance,
unresolved states, and the bundled direct-API Ghidra boundary.
