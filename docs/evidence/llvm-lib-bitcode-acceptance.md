# `llvm-lib-bitcode` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1022. It is bounded planning evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly six linked handwritten compilation units:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-1f1a619e663e4400cb785843a0c33576` | `source/llvm/lib/Bitcode/Reader/BitcodeReader.cpp` | `27a4b2ed030d5f3a8d0373ddd56cd7f09b622e374c4481ac6df00fd8a23ecd7f` |
| `cu-b5989cf11149be617585b90d296c4709` | `source/llvm/lib/Bitcode/Reader/MetadataLoader.cpp` | `9ae77f1af3793f3244a248e586e1c7a72a4a2c9aef5a63100a7997032e574c64` |
| `cu-81876fe9b2ce43cca8534d1166f9cea2` | `source/llvm/lib/Bitcode/Reader/ValueList.cpp` | `7c9af5e68df838d354226fcf8750e87ec8ad40d6a85f662065582c8bde33d790` |
| `cu-a4c33d59d773fefc509534f98e615dff` | `source/llvm/lib/Bitcode/Writer/BitcodeWriter.cpp` | `e9a65128cd43577e604bcd1b40f9f754aa4fc49c7722b1522672c207d2d8d5a5` |
| `cu-da44b1700533d7b287bc03fe2a438b4a` | `source/llvm/lib/Bitcode/Writer/BitcodeWriterPass.cpp` | `e944c56c157832ccf3fa04d8c83d5af4077428ef88fccc319c64b19919c45b8e` |
| `cu-4fad6a668fd5d6c02e23b5e4c509567d` | `source/llvm/lib/Bitcode/Writer/ValueEnumerator.cpp` | `ac706a83e117e16e0893ac4ce03b5b2c1e377f387c92bcd533eef8c99ba3c268` |

The source inventory also retains three source-only records, each excluded by
the authenticated build graph with reason
`not-selected-by-authenticated-build-graph`:

| Source-only path |
| --- |
| `source/llvm/lib/Bitcode/Reader/BitReader.cpp` |
| `source/llvm/lib/Bitcode/Reader/BitcodeAnalyzer.cpp` |
| `source/llvm/lib/Bitcode/Writer/BitWriter.cpp` |

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Those planning counts
establish module ownership context; they are not an emitted-function or
accepted-implementation denominator. The three source-only records are
non-owning evidence and do not reduce the six linked owners above.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The six linked units
therefore remain unresolved and release-blocking under #1022. Placeholder
returns, abort/no-op bodies, undeclared shims, and reduced denominators cannot
count as accepted implementations.

The remaining bounded work must bind the current emitted population for these
exact owners, generate every required implementation through the qualified
isolated ACP workflow while preserving ABI, call, global, name, and ownership
interfaces, and retain per-module source plus ACP and validation receipts for
each required entity. Every unresolved entity remains an explicit blocker;
cross-shard interface changes require the existing invalidation authority.

## Artifact provenance

The evidence is bound to these repository-controlled LLVM 22.1.6 profile
artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |

The linked population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1022
