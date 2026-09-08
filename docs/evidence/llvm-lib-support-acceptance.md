# `llvm-lib-support` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1044. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventory binds `llvm-lib-support` to 148 linked, handwritten
compilation units. The exact `unitIds` array for this shard in
`full-tree-inventory.json`, serialized as compact JSON in inventory order, has
SHA-256
`6f1d35cb68453c3612492ed93322193b57285b9b0cbf059fd0966b897c528b72`.

| Field | Value |
| --- | --- |
| shard | `llvm-lib-support` |
| linked source modules | `148` |
| source kind | `148 handwritten`, `0 generated` |
| source paths | `source/llvm/lib/Support/...` |
| planning selection SHA-256 | `d9932d2101693626f0564f102524de8721fe73e23e00ea312b1c31e7128e7269` |
| linked source-record SHA-256 | `7ba218973ea47596a55ea6af4b1fbc978671564ae799dab5d70616e6b731eee1` |
| rich artifact identity | `c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a` |

The planning selection hash is over the 148 matching records from
`full-tree-planning-inventory.json`, serialized as compact JSON in artifact
order. The linked source-record hash is over the 148 matching records from
`full-tree-source-inventory.json`, serialized the same way. Together with the
unit-ID hash, these bind the module IDs, source paths, source kinds, and shard
ownership without substituting a planning count for an emitted-function count.

The source inventory also retains 44 `source-only` paths in this shard. They
have no compilation-unit ID and are marked
`not-selected-by-authenticated-build-graph`; they remain explicit source
records and must not be silently counted as linked emitted units:

| Path | Classification |
| --- | --- |
| `source/llvm/lib/Support/AArch64AttributeParser.cpp` | source-only |
| `source/llvm/lib/Support/AArch64BuildAttributes.cpp` | source-only |
| `source/llvm/lib/Support/AMDGPUMetadata.cpp` | source-only |
| `source/llvm/lib/Support/ARMWinEH.cpp` | source-only |
| `source/llvm/lib/Support/Atomic.cpp` | source-only |
| `source/llvm/lib/Support/AutoConvert.cpp` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_avx2.c` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_avx2_x86-64_windows_gnu.S` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_avx512.c` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_avx512_x86-64_windows_gnu.S` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_neon.c` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_sse2.c` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_sse2_x86-64_windows_gnu.S` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_sse41.c` | source-only |
| `source/llvm/lib/Support/BLAKE3/blake3_sse41_x86-64_windows_gnu.S` | source-only |
| `source/llvm/lib/Support/BalancedPartitioning.cpp` | source-only |
| `source/llvm/lib/Support/COM.cpp` | source-only |
| `source/llvm/lib/Support/CSKYAttributeParser.cpp` | source-only |
| `source/llvm/lib/Support/CSKYAttributes.cpp` | source-only |
| `source/llvm/lib/Support/CachePruning.cpp` | source-only |
| `source/llvm/lib/Support/DAGDeltaAlgorithm.cpp` | source-only |
| `source/llvm/lib/Support/DeltaAlgorithm.cpp` | source-only |
| `source/llvm/lib/Support/DynamicAPInt.cpp` | source-only |
| `source/llvm/lib/Support/ELFAttrParserExtended.cpp` | source-only |
| `source/llvm/lib/Support/FileOutputBuffer.cpp` | source-only |
| `source/llvm/lib/Support/FileUtilities.cpp` | source-only |
| `source/llvm/lib/Support/LSP/Logging.cpp` | source-only |
| `source/llvm/lib/Support/LSP/Protocol.cpp` | source-only |
| `source/llvm/lib/Support/LSP/Transport.cpp` | source-only |
| `source/llvm/lib/Support/MSP430AttributeParser.cpp` | source-only |
| `source/llvm/lib/Support/MSP430Attributes.cpp` | source-only |
| `source/llvm/lib/Support/Memory.cpp` | source-only |
| `source/llvm/lib/Support/Mustache.cpp` | source-only |
| `source/llvm/lib/Support/PluginLoader.cpp` | source-only |
| `source/llvm/lib/Support/RWMutex.cpp` | source-only |
| `source/llvm/lib/Support/SystemUtils.cpp` | source-only |
| `source/llvm/lib/Support/TarWriter.cpp` | source-only |
| `source/llvm/lib/Support/TextEncoding.cpp` | source-only |
| `source/llvm/lib/Support/TrieRawHashMap.cpp` | source-only |
| `source/llvm/lib/Support/circular_raw_ostream.cpp` | source-only |
| `source/llvm/lib/Support/raw_socket_stream.cpp` | source-only |
| `source/llvm/lib/Support/rpmalloc/malloc.c` | source-only |
| `source/llvm/lib/Support/rpmalloc/rpmalloc.c` | source-only |
| `source/llvm/lib/Support/zOSLibFunctions.cpp` | source-only |

The compact JSON array of those 44 source-only paths has SHA-256
`b3fd2bbc938667b365177aa365aa7d93e02e8ba15a0273835a6e1105970518be`.

The planning inventory records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. Those
planning counts are context for module ownership, not an emitted-function or
accepted-implementation denominator.

## Acceptance state

No shard-specific generated source, authenticated emitted-function population,
ACP invocation receipt, compiler receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. The 148 linked units therefore
remain unresolved and release-blocking under #1044. The 44 source-only records
also remain explicit until the authenticated workflow records their required
disposition. A placeholder, abort/no-op body, undeclared shim, or reduced
denominator must not be recorded as an accepted implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for these exact units, run the qualified isolated
generation workflow through the existing bundled Ghidra/API and authenticated
oracle boundaries, and retain one source plus ACP/validation receipt per
required entity. Any unresolved entity must remain an explicit blocker; changes
to cross-shard interfaces require the existing invalidation authority.

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
