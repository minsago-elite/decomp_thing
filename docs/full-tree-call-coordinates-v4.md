# Typed raw call coordinates, policy v4

`DW_AT_call_pc` names a call instruction; `DW_AT_call_return_pc` names a return
address. These are separate coordinates, not interchangeable spellings of one
address. The definitions are in [DWARF 5, section 3.4.1](https://dwarfstd.org/doc/DWARF5.pdf).
A return address can equal the next call's instruction address. Joining either
field to an untyped RVA can combine distinct calls or assign credit twice.

The Kotlin observer reads both attributes independently, never falls back from
return PC to call PC, and retains both in schema-v2 observations:

- `callPcRva` and `callerLocalCallOffset` describe the instruction coordinate.
- `returnPcRva` and `callerLocalReturnOffset` describe the return coordinate.
- Each missing coordinate and its corresponding local offset remain null.
- An observed site needs at least one emitted coordinate and an emitted caller.
  Each available coordinate reconciles with its caller-local offset without
  unsigned overflow. No coordinate is synthesized from instruction length,
  tail-call status, the other attribute, or a recovered model.
- Both coordinates, caller, compilation unit and DIE locator bind observation
  identity. Tail status remains independent: a tail-marked record can explicitly
  contain a return coordinate, and an ordinary call can have only an instruction
  coordinate.

## Raw reconciliation

The bounded SQLite composer first retains raw records and caller-scoped
instruction/return pairs observed together in authenticated DWARF. A pair must
map uniquely in both directions; conflicting mappings stop reconciliation before
publication. A second pass fills a missing coordinate only from an exact raw
pair. Grouping then uses caller plus a typed instruction coordinate when known,
or caller plus a typed return coordinate otherwise. Equal integers in different
coordinate kinds do not themselves establish equivalence.

Normalized duplicate signatures must still agree on targets, tail status and all
other retained facts. Original observation IDs remain attached to the one edge.
A first call ending at `0x105` stays separate from a second call starting at
`0x105`, while partial observations of the second call collapse when raw pair
evidence proves their relationship. No recovered name or candidate address
supplies this mapping.

The added raw-record table and coordinate indexes share the existing database,
scratch, entity, group, serialization and parent-deadline limits. The additional
pass checkpoints the deadline for every record. There is no whole-tree in-memory
map, larger resource allowance, new execution authority or relaxed publication.

## Version transition

Original schema files remain byte-for-byte unchanged. The catalog adds
`full-tree-call-observations-v2` and `full-tree-call-truth-v2` (schemaVersion 2),
bringing its entry count from 66 to 68. The call-truth index and baseline retain
their schema-1 shapes but bind new policy/configuration and new shard bytes.

| Artifact | Policy-v4 SHA-256 |
| --- | --- |
| Call observations | `ec32478cfea2b28fd284d2fbe7a66eb0bc5eaf27e1b3498c93e4e2082f7b2bab` |
| Call truth | `5a3549d94b691d70cc2ea98b919ac40127c8cd73f76b29df47c0c1b977f306f7` |
| Call observability baseline | `708bc81e3dad00944dbda89cda2e0282e2145b2d850155b2d8655fbede64399d` |

Tests preserve historical observation policy-v2 and policy-v3 configuration
digests. Old artifacts are not rewritten or silently upgraded: schema-v2 records
and policy-v4 input commitments require fresh raw generation. Historical diagnostic
assessments keep their original schemas and do not become current oracle evidence.

## Evidence and remaining scope

The three-shard raw fixture still has 11 edges from 12 observations. Its two
call-PC tail sites now have null return PCs rather than fabricated return values.
An extended fixture has 16 observations for the same 11 edges: paired and partial
observations merge while adjacent instruction/return coordinates remain distinct.
Reconciliation is compared across declared worker bounds 3 and 8; conflicting
mappings in either direction must leave no published candidate.

Verification: 82 focused tests passed with zero failures, errors or skips using
`./gradlew --offline test --tests 'decompengine.oracle.fulltree.FullTreeCall*' --tests decompengine.oracle.fulltree.FullTreeCrossShardCallFixtureTest --tests decompengine.oracle.core.OracleSchemasTest`.
This includes both historical policy-v2/v3 rejection cases and the schema catalog.
The subsequent `fc1b821` full-tree and schema regression ran 441 tests across
62 suites: 402 passed, 39 environment-dependent cases skipped, and none failed.
This broader local run does not qualify the unavailable hosted boundaries.

These are raw-coordinate and observability checks, **not recovered-model scores**.
The baseline remains denominator 9 / exact 7 / partial 2 / excluded 2 on the original
fixture. It still has no recovered-model, candidate-lease, downstream-scoring or
release authority. Without a raw pair or separately authenticated instruction
decoding, instruction-only and return-only observations at different addresses
cannot be assumed equivalent. Decoder-backed reconciliation, candidate joins,
relocation/PLT evidence, normalized thunk/virtual targets, all-shard containment and
actual exact/partial/missing/fabricated scoring remain required A-series work.
