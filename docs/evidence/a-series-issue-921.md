# Kotlin oracle schema and artifact capability — draft evidence

This records the bounded schema/artifact slice for issue #921. The source issue remains open; this draft does not establish the remaining producer, scoring, release, or production gates in #136.

## Baseline and reused checkpoints

The inspected source baseline is `origin/master` at `89b26c6cc498c6fa8ac3879e844a9badd140ccb1` (2026-09-30). Reused #136 checkpoints are `1111e199d17888f3fa36b4c8b754d393bc909237` (bounded Kotlin oracle artifact core) and `8062207ef43d18525732c76cb3f874855081b5c6` (Kotlin data-truth semantics). The earlier [cutover evidence note](../oracle-cutover-evidence-136.md), recorded at `bf2501568f39ab52b23492dfc37839bb81895587`, documents the existing strict parser, schema loader, and atomic file layer.

The merged [#1362 boundary-record PR](https://github.com/minsago-elite/decomp_thing/pull/1362) changed only this evidence file. The remaining #921 gap on the pinned current baseline was that schema files existed outside the 69-name `OracleSchemas` catalog with no complete versioned inventory, and the file API had no operation that composed canonical JSON validation with authenticated atomic publication. This implementation closes that scoped gap while retaining the previous layer's format and trust boundaries.

## Versioned schema inventory

[`oracle/kotlin-schema-inventory-v1.json`](../../oracle/kotlin-schema-inventory-v1.json) records every repository `oracle/**/*.schema.json` file by logical name, exact path, declared document-format versions, registration disposition, and SHA-256 of the exact schema bytes. Its own bytes are canonical bounded JSON and the inventory is packaged alongside the schemas.

The historical count of 43 is retained as the starting point, not an inventory cap. At this master snapshot the inventory contains 73 schema files: 69 are registered through `OracleSchemas`; three are retained outside that shared catalog without a current Kotlin `OracleSchemas` consumer; the native-helper policy has its own explicitly non-authoritative validator. The four dispositions are explicit in the inventory and tested by name. New schemas must be inventoried and assigned a reviewed disposition.

The canonical inventory bytes have SHA-256 `d8039cf628287fbaa1807dc3cc6d9a5d6d2624e113655e3a7d377cdbdf1e141a`. A static audit passed for canonical JSON encoding, duplicate-free parsing, complete source-file coverage, all 73 exact schema hashes and version declarations, and equality between the 69 shared registrations and `OracleSchemas`.

No `.schema.json` payload or existing artifact format is changed in this slice. Existing format-version declarations and exact schema-byte digests are pinned. Intentional future document-format changes must update the format version and include an old-to-new migration test; schema-byte or policy-digest changes must update the exact inventory/configuration digest evidence and document their migration. Existing canonical JSON and schema-configuration vectors remain unchanged.

At runtime `OracleSchemas` reads the inventory only from the bundled classpath, rejects duplicate, malformed, noncanonical, over-depth/count/byte inventory JSON, checks the full registered-name set, and checks a loaded registered schema's exact digest before compiling it. `configurationSha256` continues to hash canonical policy bytes followed by exact schema bytes in caller order.

## Shared canonical artifact handoff

The reusable implementation is `OracleJson`, `OracleSchemas`, and `OracleArtifacts`:

- `OracleJson.parse` is strict UTF-8 JSON and rejects duplicate decoded keys, malformed strings/numbers, excess depth/count/bytes, and trailing data. `parseCanonical` additionally requires byte-for-byte equality with the canonical encoding. The compatibility fixture locks key ordering, indentation, numeric spelling, Unicode, and the trailing newline against the existing Python artifact format.
- Default JSON bounds are 4 MiB input and canonical output, depth 64, 100,000 nodes, 1 MiB per string, 2 MiB total string bytes, and 256 number characters. Hard bounds are 64 MiB, depth 256, 1,000,000 nodes, and 4,096 number characters.
- Schema and inventory resources are bounded to 1 MiB, depth 96, 200,000 nodes, 256 KiB per string, and 768 KiB total string bytes; the versioned inventory accepts at most 1,024 entries. Schema-validation errors are capped at 64 items, 512 characters per item, and 8 KiB of combined detail.
- `OracleArtifacts.readCanonical` and `publishCanonical` compose strict canonical validation with the existing bounded authenticated file read and durable same-directory atomic publication. They hash the exact canonical bytes. Default artifact size is 4 MiB, with a 64 MiB hard ceiling. Invalid JSON is rejected before publication, leaving an existing destination unchanged.
- File and immediate-parent permissions, path identity, symlink rejection, post-read identity/metadata, private temporary files, file and directory synchronization, and atomic replacement remain enforced by the existing artifact layer. Authentication relies on the protected cooperating file/directory owner boundary. SHA-256 commits to the exact artifact bytes; this layer issues no external signature.

This gives #116/#119/#120/#123/#128/#129 a reusable canonical schema/artifact capability and its bounds. Consumers still need to bind their own authenticated inputs/outputs, policy/schema identities, negative cases, determinism evidence, and authority limits. This handoff does not qualify any producer stage, validator/reconciler, scorer, full-tree run, release builder, or Python-free production graph.

## Focused checks and current evidence status

The focused JUnit command is:

```text
./gradlew --offline test --tests decompengine.oracle.core.OracleJsonTest --tests decompengine.oracle.core.OracleArtifactsTest --tests decompengine.oracle.core.OracleSchemasTest
```

It was attempted but did not reach Gradle or Kotlin compilation: this environment has no cached Gradle 9.6.1 wrapper distribution. The wrapper's repository-local cache attempt also stopped at DNS resolution for `services.gradle.org` (`UnknownHostException`). No JUnit result is claimed. Required GitHub Actions on the dedicated draft PR and independent review are still pending.

The existing test sources retain the canonical compatibility vector, strict parser negative cases, resource-limit cases, schema configuration digest vectors, schema compilation, and atomic publication/path/permission checks. This slice adds canonical publish/read integration negatives and exhaustive inventory/file/hash/version/disposition checks. Draft code and documentation are not merged behavior or production qualification.
