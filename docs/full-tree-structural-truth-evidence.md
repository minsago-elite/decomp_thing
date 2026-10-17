# Full-tree structural truth: authenticated control-plane slice

Evidence record: `full-tree-structural-truth-control-v1`

This is one narrow repository-backed slice of issue [#119](https://github.com/minsago-elite/decomp_thing/issues/119). It records the authenticated control-plane boundary that already exists; it does not close the full-tree structural-truth tracker.

## Existing contract

- `FullTreeScopeControl` reads canonical scope, source-lock, and oracle-manifest objects, records their SHA-256 identities, and verifies the manifest and scope bindings for the source lock and rich/stripped artifacts.
- `FullTreeInventoryControl` validates canonical unit order, the inventory index digest, unique source identities, and deterministic shard ownership. Its oracle bindings must match the authenticated scope.
- `FullTreeDataTruthSqlite` validates those controls and the observation tree before bounded SQLite ingestion and canonical partition publication. Publication uses private staging and an atomic no-replace destination; ordinary failure does not replace an existing destination.
- The data-truth path keeps provenance in the scope, inventory, observation-index, and artifact digests. Candidate bytes and ACP output are inputs to comparison or reconstruction only; they cannot authorize oracle facts or release evidence.
- A `complete` observation/index state means that the authenticated inventory population is represented by that state. It is not a full-tree release-completeness or scoring claim. Missing, contradictory, dangling, or otherwise unresolved records remain failures or explicit unresolved evidence.

The primary implementation and focused contract tests are [FullTreeScopeControl.kt](../src/main/kotlin/decompengine/oracle/fulltree/FullTreeScopeControl.kt), [FullTreeInventoryControl.kt](../src/main/kotlin/decompengine/oracle/fulltree/FullTreeInventoryControl.kt), [FullTreeDataTruthSqlite.kt](../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDataTruthSqlite.kt), and [FullTreeDataTruthSqliteTest.kt](../src/test/kotlin/decompengine/oracle/fulltree/FullTreeDataTruthSqliteTest.kt).

## Production gap

This record does not provide the unavailable production gates for #119: a fresh authenticated all-shard function/call/data/ABI regeneration, independent completeness reconciliation, two byte-identical production runs, and retained interruption/resource/recovery evidence. The tracker still depends on open issues [#120](https://github.com/minsago-elite/decomp_thing/issues/120), [#123](https://github.com/minsago-elite/decomp_thing/issues/123), [#128](https://github.com/minsago-elite/decomp_thing/issues/128), [#129](https://github.com/minsago-elite/decomp_thing/issues/129), and [#862](https://github.com/minsago-elite/decomp_thing/issues/862), with execution and Kotlin-authority gaps tracked by [#116](https://github.com/minsago-elite/decomp_thing/issues/116), [#136](https://github.com/minsago-elite/decomp_thing/issues/136), and [#138](https://github.com/minsago-elite/decomp_thing/issues/138).

No production regeneration or release gate is claimed by this documentation change. It introduces no external `GHIDRA_HOME` or `analyzeHeadless` dependency; bundled Ghidra isolation and the authenticated oracle boundary remain unchanged.

## Raw relocatable section-group evidence

`FullTreeElfLayout.scanRelocatableGroups` reads the raw `SHT_GROUP` evidence specified by
[GABI section 3.9](https://gabi.xinuos.com/elf/03-sheader.html#section-groups). This entry point
requires `ET_REL`; the existing linked layout/function/object readers still require `ET_EXEC`
or `ET_DYN` and their bounded program-header table. Both ELF classes and byte orders use
four-byte group words.

The observation retains each group's section index/name, flag word, exact signature-table
and symbol indices, raw signature attributes, and member section headers. Member indices
must follow their group, have `SHF_GROUP`, and belong to exactly one group. Orphan, duplicate,
missing, malformed and over-budget evidence refuses before an observation is returned.
Processor/OS group flag bits remain uninterpreted; reserved bits refuse. Empty signature
names remain empty rather than acquiring a guessed name from the group section.

The existing file, header, symbol, string and parse-work bounds still apply. Separate defaults
bound groups to 16,384, memberships to 131,072 and unique signature-name bytes to 8 MiB.
Group work invokes the caller's checkpoint and verifies the pinned source identity before
returning immutable lists. These are parser bounds, not measured RSS or interruption of
arbitrarily blocked native I/O. Source group/member order and raw object-relative symbol
values are retained; they are not linked RVAs or a canonical semantic truth record.

This reader performs no compiler, linker or generated-program launch and publishes no files.
Its caller still needs independently authenticated object bytes, build/input membership,
linker selection/discard evidence and output/entity witnesses. A COMDAT flag, matching
signature, missing group in a final executable, or current ownership/alias category does
not identify a linker selection. Existing frozen function/call truth and scoring authority
are unchanged. The complete COMDAT selection/discard outcome remains open.
