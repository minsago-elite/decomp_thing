# Raw-derived Kotlin call observability baseline

This document records the policy-v3 checkpoint. Current generation binds
[policy-v4 typed call coordinates](full-tree-call-coordinates-v4.md) and its new
configuration digest; the original fixture's observability counts are unchanged.

`FullTreeCallBaselineSqlite` implements the policy-v3 observability report for
[raw-derived call truth](full-tree-call-truth-kotlin.md), tracked under
[issue #128](https://github.com/minsago-elite/decomp_thing/issues/128) and the Kotlin
migration in [issue #136](https://github.com/minsago-elite/decomp_thing/issues/136).
It is not a recovered-model scorer or release gate.

## Input boundary

Both `generateAndPublishFromRawInputs` and `loadAndValidateFromRawInputs` require
the authenticated scope, rich and stripped ELF artifacts, inventory, ELF function
index, function-observation run and expected digest, function-truth candidate,
call-observation run and expected digest, and call-truth candidate. They do not
accept a self-consistent candidate hash as evidence of truth.

The fixed call-baseline hook keeps the private raw-reconciled function and call
projections live throughout report derivation. It compares the supplied call
truth against the private projection before consumption and rechecks raw inputs
and exact candidate bytes before and after publication or validation. Call truth
and the report candidate are comparison inputs, never expected oracle facts.
Validation repeats this raw derivation and compares exact report-tree membership
and bytes without repairing the supplied candidate.

## Meaning of the report

The existing `full-tree-call-baseline` schema-v1 shape remains unchanged. Policy v3
binds that exact schema, live raw call-truth provenance, and the explicit
observability-only measurement. Its configuration SHA-256 is
`c1a9083c622e951ac7b4ea9b2f8524365b15b8928e2c66003679ae9dd1aa4ac2`.
Historical policy-v2 reports are not silently treated as raw policy-v3 evidence.

Each deduplicated truth edge contributes once:

| Metric | Interpretation |
|---|---|
| `exact` | Scored site with a resolved direct semantic target, external identity, or independently proven target set |
| `partial` | Scored site with an unresolved indirect or thunk semantic target |
| `excluded` | Unobservable site or target, preserving the truth exclusion policy |
| `denominator` | `exact + partial`; excluded edges do not enter this denominator |
| `missing`, `fabricated` | Always zero: no recovered candidate model is being scored |

Per-shard metrics cover the authenticated inventory, including zero-edge shards.
Each partial edge has a stable mismatch ID bound to its truth ID, shard and truth
reason. Metrics and mismatches are emitted in bytewise identifier order. The
report binds the exact call-truth index artifact digest; `reportSha256` hashes
canonical report bytes with only that self-hash field omitted. The publication
receipt separately records the complete report artifact digest and byte count.

The three-shard raw ELF/DWARF fixture produces 11 deduplicated edges from 12
observations: denominator 9, exact 7, partial 2 and excluded 2. The partial edges
are the unresolved physical-thunk semantic target and an observed indirect site.
These are fixture observability counts, not reconstruction accuracy percentages.

## Bounds and lifecycle

SQLite stores per-shard counters and partial-edge mismatches. Two bounded
canonical passes stream the report: the first computes the self-hash and the
second publishes the complete document. Neither pass materializes the complete
report. Indexed ordering is checked with `EXPLAIN QUERY PLAN`; temporary sorts
and automatic indexes are rejected. SQLite memory mapping and journaling are
disabled, with independent page-cache and maximum-page limits.

Entity count, bytes, nodes, strings and parser tokens have explicit ceilings.
Nested raw derivation must fit the admitted scratch ceiling before it starts.
The report database has an upfront reservation; output is charged against the
retained projections, reserved database and report byte ceiling before writing.
The call-truth parent deadline continues through SQLite work, report emission,
source rechecks, cleanup and terminal output verification. Releasing raw inputs
does not create a fresh deadline for terminal verification.

The output is one directory containing only `report.json`, with directory mode
0500 and single-link file mode 0400. Staging uses the destination's parent and
publishes with atomic no-replace rename and directory synchronization. An
occupied or overlapping destination is rejected. Ordinary failures remove only
recognized private staging and scratch; unexpected residue is not recursively
deleted. A live projection cannot be rechecked or accounted after release, and
consumer failures retain their original cause through cleanup.

## Evidence and limitations

Focused verification:

```bash
./gradlew test \
  --tests decompengine.oracle.fulltree.FullTreeCallBaselineSqliteTest \
  --tests decompengine.oracle.fulltree.FullTreeCallTruthSqliteTest
```

Regressions cover deterministic bytes across declared worker bounds, schema and
self-hash consistency, exact denominators without duplicate credit, rehashed
report and call-truth forgeries, changed raw bytes, missing/extra/linked/writable
candidates, protected destinations, resource bounds, interruption and projection
lifecycle. A separate zero-edge raw fixture verifies that all inventory shards
remain represented and empty mismatches remain canonical. Live-projection tests
also reject truth changes during consumption and retain interruption checks after
input release. No Python process supplies facts or validation decisions on this path.

Receipts fix `candidateLeaseRetained`, `downstreamScoringAuthorized`,
`authoritativeReleaseEvidence` and `recoveredModelScored` to false. Raw rederivation
and candidate matching describe this completed comparison boundary only.
Cooperative same-UID filesystem ownership remains assumed: read-only modes and
terminal rechecks are not kernel exclusion against previously open writers or
swap-and-restore attacks. Cooperative scratch/runtime accounting is not an ext4
quota lease or contained process-tree proof. The fixture does not establish
production full-tree coverage or scale. Actual recovered-model scoring,
relocation-bound PLT and normalized thunk/virtual evidence, retained containment
and recovery, complete source/build provenance, and release composition remain
separate requirements. ACP receives no oracle or scoring authority.
