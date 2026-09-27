# Full-tree ABI interface evidence v1

This is a small, fixture-backed evidence record for issue #110. It records
facts already present in the Kotlin/JVM full-tree data-truth fixtures; it does
not emit declarations or promote fixture data to production oracle authority.

## Record

```yaml
record: full-tree-abi-interface-evidence-v1
status: unresolved
scope: checked-in full-tree data-truth fixtures only
productionAuthority: false
candidateInterfaceEmission: false
interfaceProbeQualification: false
```

The three inputs and their exact bytes are:

| Input | SHA-256 |
| --- | --- |
| `src/test/resources/oracle/full-tree-data-observations-shard.json` | `b2974c3b5945c9e244cb83b67cf98e06fc4a5c1a8fd84372279ffe10031bb043` |
| `src/test/resources/oracle/full-tree-data-reconciliation-v1-frozen.json` | `cfcca6e636f058c9670b39495fb0d4516c1a287d54ec45b85560b5c4810bf5d4` |
| `src/test/resources/oracle/full-tree-data-baseline-v1-frozen.json` | `3ea992adf57a53677b76661ce5e0f8a81c70b1cdfb744a6276ae37f4543c9bfb` |

## Existing facts captured

The observation shard `shard-a` contains one `struct Sample` and one global
`sample_global`:

- `Sample` has `byteSize: 16`, `alignment: 8`, declaration `sample.c:4`, and
  three observed members: one field, one base, and one enumerator.
- `sample_global` has RVA `0x40`, size `8`, alignment `8`, is mutable and
  externally visible, and is declared at `sample.c:12`.
- The global's raw type reference records aggregate DIE `0x30` and the
  `DW_TAG_const_type` modifier. The record preserves that raw reference; it
  does not claim that a source declaration or ABI calling convention has been
  recovered.

The frozen reconciliation reports `dwarfTypes: 1`, `dwarfGlobals: 4`,
`matchedElfGlobals: 2`, `elfOnlyGlobals: 1`, `abiObjects: 2`, and
`unexplainedEntities: 0`. The frozen baseline reports one type denominator
with one exact result, four global denominator entries with two exact results,
one missing result, one partial result, and one excluded result, plus two ABI
object denominator entries that are both partial. These are fixture scoring
facts, not full-tree interface qualification.

## Required unresolved production gates

This record leaves the following states explicit:

- complete cross-module declaration and identity enumeration is unavailable;
- ABI sizes, alignments, bases, fields, calling conventions, linkage, and
  unique global ownership are not established for the production tree;
- no production full-tree declaration emitter exists here;
- no interface-only Clang probe has been run under the pinned strict profile;
- no visible production numerator/denominator score exists for emitted
  interfaces; and
- no clean full-tree build, runtime, or release claim follows from these
  fixtures.

Production fact acquisition must remain isolated through the bundled Ghidra
Java APIs and an authenticated oracle boundary. It must not require
`GHIDRA_HOME` or delegate to an external `analyzeHeadless` installation.
Candidate or ACP data may be consumed read-only after authentication and may
not author oracle facts, validation, scoring, certification, or release
authority. Unknown, unsupported, and unobservable ABI facts remain unresolved
until those gates produce bounded evidence.
