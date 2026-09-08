# `llvm-lib-codegen` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1025. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `llvm-lib-codegen` to 306 linked, handwritten
compilation units. The exact `unitIds` array for this shard in
`full-tree-inventory.json`, serialized as compact JSON in inventory order, has
SHA-256
`56edab4527be6253e4694ccc0dbc8c89b4ee258a123a18709dc70a29408008d9`.

| Field | Value |
| --- | --- |
| shard | `llvm-lib-codegen` |
| linked source modules | `306` |
| source kind | `306 handwritten`, `0 generated` |
| source paths | `source/llvm/lib/CodeGen/...` |
| planning selection SHA-256 | `56ffd3c775f389ee409a6fd6c9ea0111958c42e685b4b66a5028c90b93948c08` |
| linked source-record SHA-256 | `b62ae8fc384735aa960f8c9c3c24271cd81b3792734b10793a89777c9238b176` |
| rich artifact identity | `c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a` |

The planning selection hash is over the 306 matching records from
`full-tree-planning-inventory.json`, serialized as compact JSON in artifact
order. The linked source-record hash is over the 306 `linked` records from
`full-tree-source-inventory.json`, serialized the same way. Together with the
unit-ID hash, these bind the module IDs, source paths, source kinds, and shard
ownership without substituting a planning count for an emitted-function count.

The source inventory also retains 17 `source-only` paths in this shard. They
have no compilation-unit ID and are marked
`not-selected-by-authenticated-build-graph`; they remain explicit source
records and must not be silently counted as linked emitted units:

| Path | Classification |
| --- | --- |
| `source/llvm/lib/CodeGen/AsmPrinter/ErlangGCPrinter.cpp` | source-only |
| `source/llvm/lib/CodeGen/AsmPrinter/OcamlGCPrinter.cpp` | source-only |
| `source/llvm/lib/CodeGen/CommandFlags.cpp` | source-only |
| `source/llvm/lib/CodeGen/GlobalISel/CombinerHelperArtifacts.cpp` | source-only |
| `source/llvm/lib/CodeGen/GlobalISel/CombinerHelperCasts.cpp` | source-only |
| `source/llvm/lib/CodeGen/GlobalISel/CombinerHelperCompares.cpp` | source-only |
| `source/llvm/lib/CodeGen/GlobalISel/CombinerHelperVectorOps.cpp` | source-only |
| `source/llvm/lib/CodeGen/IntrinsicLowering.cpp` | source-only |
| `source/llvm/lib/CodeGen/MIRParser/MILexer.cpp` | source-only |
| `source/llvm/lib/CodeGen/MIRParser/MIParser.cpp` | source-only |
| `source/llvm/lib/CodeGen/MIRParser/MIRParser.cpp` | source-only |
| `source/llvm/lib/CodeGen/MIRYamlMapping.cpp` | source-only |
| `source/llvm/lib/CodeGen/MultiHazardRecognizer.cpp` | source-only |
| `source/llvm/lib/CodeGen/NonRelocatableStringpool.cpp` | source-only |
| `source/llvm/lib/CodeGen/RegAllocPBQP.cpp` | source-only |
| `source/llvm/lib/CodeGen/RegAllocScore.cpp` | source-only |
| `source/llvm/lib/CodeGen/VLIWMachineScheduler.cpp` | source-only |

The compact JSON array of those 17 source-only paths has SHA-256
`61e9eac689f82c694a5e32eef9564d0002784430bcf0b3b1490d49b426c6198d`.

The planning inventory records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. Those
planning counts are context for module ownership, not an emitted-function or
accepted-implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler receipt, validation receipt, behavioral
receipt, or retained accepted checkpoint is present in this slice. The 306
linked units therefore remain unresolved and release-blocking under #1025. The
17 source-only records remain explicit non-owning evidence. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for these exact units, run the qualified isolated
generation workflow through the existing bundled Ghidra/API and authenticated
oracle boundaries, and retain one source plus ACP/validation receipt per
required entity. Any unresolved entity must remain an explicit blocker;
changes to cross-shard interfaces require the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The inventory binds to scope index
`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, source
inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`, and
source lock
`179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306`.

Refs #1025
