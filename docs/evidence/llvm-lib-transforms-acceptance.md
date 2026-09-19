# `llvm-lib-transforms` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1048. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The checked A14 inventories bind `llvm-lib-transforms` to 309 linked,
handwritten compilation units. The exact unit IDs are the `unitIds` array for
this shard in `full-tree-inventory.json`; its SHA-256, computed over that
compact JSON array in inventory order, is
`8f95298fa0a6a44e732d88db96c3b5f36e32c63bfde43d134f1d8c0242d544d7`.

| Field | Value |
| --- | --- |
| shard | `llvm-lib-transforms` |
| linked source modules | `309` |
| source kind | `309 handwritten`, `0 generated` |
| source paths | `source/llvm/lib/Transforms/...` |
| rich artifact identity | `c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a` |

The source inventory also retains ten `source-only` paths in this shard. They
have no compilation-unit ID and are marked
`not-selected-by-authenticated-build-graph`; they remain explicit source
records and must not be silently counted as linked emitted units:

| Path | Classification |
| --- | --- |
| `source/llvm/lib/Transforms/IPO/BarrierNoopPass.cpp` | source-only |
| `source/llvm/lib/Transforms/IPO/ExtractGV.cpp` | source-only |
| `source/llvm/lib/Transforms/IPO/IPO.cpp` | source-only |
| `source/llvm/lib/Transforms/Scalar/Scalar.cpp` | source-only |
| `source/llvm/lib/Transforms/Utils/DebugSSAUpdater.cpp` | source-only |
| `source/llvm/lib/Transforms/Utils/SplitModuleByCategory.cpp` | source-only |
| `source/llvm/lib/Transforms/Utils/Utils.cpp` | source-only |
| `source/llvm/lib/Transforms/Vectorize/SandboxVectorizer/InstrMaps.cpp` | source-only |
| `source/llvm/lib/Transforms/Vectorize/VPlanSLP.cpp` | source-only |
| `source/llvm/lib/Transforms/Vectorize/Vectorize.cpp` | source-only |

The planning inventory records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`.
Those planning counts are context for module ownership, not an emitted-function
or accepted-implementation denominator.

## Acceptance state

No shard-specific generated source, authenticated emitted-function population,
ACP invocation receipt, compiler receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. The 309 linked units therefore
remain unresolved and release-blocking under #1048. The ten source-only records
also remain explicit until the authenticated workflow records their required
disposition. A placeholder, abort/no-op body, undeclared shim, or reduced
denominator must not be recorded as an accepted implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for these exact units, run the qualified isolated
generation workflow through the existing bundled Ghidra/API and authenticated
oracle boundaries, and retain one source plus ACP/validation receipt per
required entity. Any unresolved entity must remain an explicit blocker.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The inventory binds to scope index
`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, source
inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`, and
source lock
`179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306`.
