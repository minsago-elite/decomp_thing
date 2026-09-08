# Itanium C++ ABI evidence contract v1

This is one small, non-authoritative evidence record for #127. It preserves an
existing ABI-object observation without turning it into a vtable, RTTI, or
runtime claim.

```yaml
record: itanium-cxx-abi/abi-object-slot-resolution-v1
status: partial
authority: non-authoritative-migration-evidence
authoritativeReleaseEvidence: false
sourceCommit: bf2501568f39ab52b23492dfc37839bb81895587
observed:
  source: src/test/resources/oracle/full-tree-data-baseline-v1-frozen.json
  schemaVersion: 1
  dimension: abiObjects
  denominator: 2
  exact: 0
  partial: 2
  unresolvedReason: abi-object-has-unresolved-slot-words
  shard: elf-only
  truthIds:
    - global-rva-0x20:😀-object
    - global-rva-0x20:-object
  reportSha256: d3203e8b4c0b7bba1563e25d080ebf7ed73616d996111e931a28fa625585ae11
  reconciliationReportSha256: cfcca6e636f058c9670b39495fb0d4516c1a287d54ec45b85560b5c4810bf5d4
contract:
  - Keep both objects in the denominator and retain the partial reason.
  - Count a reconciled object exact only when resolvedSlots equals slots.
  - Do not infer owner type, vtable group, address point, RTTI, thunk adjustment, or exception behavior from this record.
provenance:
  baselinePolicy: src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataBaselineSqlite.kt
  rawAbiIngestion: src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataReconciliationSqlite.kt
  oracleBoundary: docs/oracle-acp-trust-boundary.md
  ghidraBoundary: docs/bundled-ghidra.md
```

The checked-in baseline records the two objects as `partial`, with zero exact
objects. The baseline implementation derives that state from `resolvedSlots !=
slots` and emits the fixed reason `abi-object-has-unresolved-slot-words`.
The reconciliation path accepts ABI evidence only as a bounded object with
bounded slots and counts a slot as resolved only when its `targetRva` is
present. These facts support the contract above; they do not establish the
full Linux x86-64 Itanium object model.

The production gap remains open. No accepted adapter or emitter currently
proves aggregate layout and constructor/destructor variants, vtable/VTT groups
and thunk adjustments, RTTI `typeid`/`dynamic_cast`, or cross-module
throw/catch/rethrow/destruction unwinding. The pinned-compiler ABI probe,
strict-diagnostic, sanitizer, clean-link, and executable-runtime gates are also
unavailable in this slice. Those requirements remain in #127's open children
[#898](https://github.com/minsago-elite/decomp_thing/issues/898),
[#899](https://github.com/minsago-elite/decomp_thing/issues/899),
[#901](https://github.com/minsago-elite/decomp_thing/issues/901),
[#902](https://github.com/minsago-elite/decomp_thing/issues/902), and
[#903](https://github.com/minsago-elite/decomp_thing/issues/903), with the
full-tree data truth and Kotlin authority gaps retained by #129 and #136.

This record does not invoke Ghidra. Any future analysis must use the bundled
Java API worker described in [bundled-ghidra.md](bundled-ghidra.md), without
`GHIDRA_HOME` or an external `analyzeHeadless` installation. The record is
read-only oracle context: ACP output cannot supply or certify its facts, and
the unresolved state cannot be cleared by a candidate model.
