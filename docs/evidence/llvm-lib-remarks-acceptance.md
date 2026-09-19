# `llvm-lib-remarks` acceptance evidence

This checkpoint records the authenticated source and compilation-unit boundary
for issue #1042. It is evidence for the bounded planning slice only; it does
not claim that an implementation has been generated, accepted, merged, or
qualified for production.

## Authenticated population

The checked planning inventory binds exactly nine handwritten source modules to
this shard. The rich compilation-unit inventory and source inventory agree
that all nine are linked units with the following ownership:

| Module/unit ID | Source path |
| --- | --- |
| `cu-d8865e845ef72543b3e35fdb90f0dd6a` | `source/llvm/lib/Remarks/BitstreamRemarkParser.cpp` |
| `cu-655d937b8ca05ca953066ba3d068fb7e` | `source/llvm/lib/Remarks/BitstreamRemarkSerializer.cpp` |
| `cu-e77b30cd649526662909d8e120e83f88` | `source/llvm/lib/Remarks/RemarkFormat.cpp` |
| `cu-b82a125dca6b3bd9a62f08ec454c3826` | `source/llvm/lib/Remarks/RemarkParser.cpp` |
| `cu-560ead0d0032f69222b8835fb0c324ad` | `source/llvm/lib/Remarks/RemarkSerializer.cpp` |
| `cu-d87163e5254a9069d053196cf273b9b9` | `source/llvm/lib/Remarks/RemarkStreamer.cpp` |
| `cu-078a630272365b5a4d6cc8305c89fbe0` | `source/llvm/lib/Remarks/RemarkStringTable.cpp` |
| `cu-6b633b4bec54d9e20d1bb29a83f71da1` | `source/llvm/lib/Remarks/YAMLRemarkParser.cpp` |
| `cu-32577b644c611bf90dcf392e9c5b7a30` | `source/llvm/lib/Remarks/YAMLRemarkSerializer.cpp` |

The source inventory also records two source-only files in this exact shard:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/Remarks/Remark.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Remarks/RemarkLinker.cpp` | `not-selected-by-authenticated-build-graph` |

These records establish the current module and linked compilation-unit
population before dispatch. The nine-module planning count is source ownership
context; it is not an emitted-function or accepted-implementation denominator.

## Acceptance state

No shard-specific generated source, emitted-function population, ACP invocation
receipt, compiler or validation receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. Therefore implementation
coverage remains unresolved and release-blocking under #1042. The two
source-only records remain explicit until the authenticated workflow records
their required disposition. A placeholder, abort/no-op body, undeclared shim,
or reduced denominator must not be recorded as an accepted implementation.

The next bounded work item must derive the emitted function population from the
authenticated rich artifact for these exact linked units, run the qualified
isolated generation workflow with the existing bundled Ghidra/API and
authenticated oracle boundaries, and retain one source plus ACP/validation
receipt per required entity. Any unresolved entity must remain an explicit
blocker; changes to cross-shard interfaces require the existing invalidation
authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The linked compilation-unit population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`; the
inventory index is
`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and the
source-inventory report is
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.
