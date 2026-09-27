# Full-tree data truth evidence contract v1

This is a small fixture-scoped evidence record for [#129](https://github.com/minsago-elite/decomp_thing/issues/129). It records facts already present in the repository; it is not a production release certificate.

```yaml
record: full-tree-data/global-layout-abi-reconciliation-v1
status: partial
authority: fixture-contract
authoritativeReleaseEvidence: false
sourceCommit: bf2501568f39ab52b23492dfc37839bb81895587
inputs:
  observationShard:
    path: src/test/resources/oracle/full-tree-data-observations-shard.json
    sha256: b2974c3b5945c9e244cb83b67cf98e06fc4a5c1a8fd84372279ffe10031bb043
    shard: shard-a
    counts: {globals: 1, types: 1, fields: 1, bases: 1, enumerators: 1}
  baseline:
    path: src/test/resources/oracle/full-tree-data-baseline-v1-frozen.json
    sha256: 3ea992adf57a53677b76661ce5e0f8a81c70b1cdfb744a6276ae37f4543c9bfb
    reportSha256: d3203e8b4c0b7bba1563e25d080ebf7ed73616d996111e931a28fa625585ae11
  reconciliation:
    path: src/test/resources/oracle/full-tree-data-reconciliation-v1-frozen.json
    sha256: cfcca6e636f058c9670b39495fb0d4516c1a287d54ec45b85560b5c4810bf5d4
    reportSha256: 5c6e42381fdc2977928ff534438455f19e19c385d21cae78c3c47f70968899e3
observed:
  aggregate:
    name: Sample
    tag: struct
    byteSize: 16
    alignment: 8
    memberFacts: [field:value@byte0, base@byte0, enumerator:choice=value1]
  global:
    name: sample_global
    addressRva: 0x40
    size: 8
    alignment: 8
    external: true
    visibility: default
    mutability: mutable
    tls: false
  reconciliationCounts:
    dwarfGlobals: 4
    dwarfTypes: 1
    elfGlobals: 3
    matchedElfGlobals: 2
    elfOnlyGlobals: 1
    dwarfOnlyScoredGlobals: 1
    abiObjects: 2
    abiSlots: 4
    abiResolvedSlots: 2
  baselineCounts:
    globals: {denominator: 4, exact: 2, partial: 1, missing: 1, excluded: 1}
    types: {denominator: 1, exact: 1, partial: 0, missing: 0, excluded: 0}
    abiObjects: {denominator: 2, exact: 0, partial: 2, missing: 0, excluded: 0}
  unresolvedReasons:
    - dwarf-address-without-elf-object
    - elf-object-without-dwarf-owner
    - abi-object-has-unresolved-slot-words
contract:
  - Keep exact, partial, missing, and excluded outcomes and their reason codes visible.
  - Count a global exact only for an authenticated DWARF/ELF reconciliation; an ELF-only object remains partial.
  - Count an ABI object exact only when resolvedSlots equals slots; unresolved slots remain partial.
  - Treat the fixture's ownerMangledName and vtable kind as observed fields, not independent proof of complete vtable, VTT, RTTI, or ABI ownership truth.
provenance:
  semantics: src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataTruthSemantics.kt
  reconciliation: src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataReconciliationSqlite.kt
  baseline: src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataBaselineSqlite.kt
  schemas:
    - oracle/full-tree-data-reconciliation.schema.json
    - oracle/full-tree-data-baseline.schema.json
  oracleBoundary: docs/oracle-acp-trust-boundary.md
  ghidraBoundary: docs/bundled-ghidra.md
```

The frozen reconciliation proves bounded, ordered fixture behavior: two image/TLS globals match authenticated DWARF facts, one ELF global is ELF-only, one scored DWARF global has no ELF object, and two ABI aliases expose one resolved slot out of two each. The baseline denominator intentionally excludes the one unobservable global while retaining it as `excluded`; omission would hide an unresolved population.

The production gap remains open. This record does not provide complete all-shard raw evidence for globals, TLS, constants, aggregate layouts, bases, fields, bitfields, unions, vtables, VTTs, or RTTI; independently evidenced owning-type and slot relationships; complete ODR contradiction and mutation coverage; or a retained, byte-identical production regeneration with source, build, artifact, and runtime provenance. The current issue audit also leaves hosted Kotlin-only production qualification and release authority unproven. These are required before #129 can close.

No Ghidra analysis is performed here. Any future analysis must use the bundled Java API worker, without `GHIDRA_HOME` or an external `analyzeHeadless` installation. ACP or recovered-model output cannot supply or certify oracle facts, and the unresolved states above must not be cleared by candidate claims.
