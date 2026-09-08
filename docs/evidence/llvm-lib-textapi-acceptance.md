# `llvm-lib-textapi` acceptance evidence

This checkpoint records the authenticated source and compilation-unit boundary
for issue #1047. It is evidence for the bounded planning slice only; it does
not claim that an implementation has been generated, accepted, merged, or
qualified for production.

## Authenticated population

The checked planning inventory binds exactly 13 handwritten source modules to
this shard. The rich compilation-unit inventory and source inventory agree that
all 13 are linked units with the following module ownership:

| Module/unit ID | Source path |
| --- | --- |
| `cu-e36018fdfc24e4a1eb77294ee714328e` | `source/llvm/lib/TextAPI/Architecture.cpp` |
| `cu-cc4dc2a5f26fa900f597f752f106e2d4` | `source/llvm/lib/TextAPI/ArchitectureSet.cpp` |
| `cu-168076a232dbe2034e2d058aaadf3419` | `source/llvm/lib/TextAPI/InterfaceFile.cpp` |
| `cu-618abd5d9fd6310c3f92271701efd851` | `source/llvm/lib/TextAPI/PackedVersion.cpp` |
| `cu-b02be8799e7af1611b4bb845c6095f9b` | `source/llvm/lib/TextAPI/Platform.cpp` |
| `cu-9863c8edc32b5c90f6038e08e0d2f7f7` | `source/llvm/lib/TextAPI/Symbol.cpp` |
| `cu-5b1a9bc56183d0d56b1ce7dac59491e3` | `source/llvm/lib/TextAPI/SymbolSet.cpp` |
| `cu-a2de346698dae9b474a1cf18f0a74dd2` | `source/llvm/lib/TextAPI/Target.cpp` |
| `cu-75c674c2ac2b83d775c7f841367fc5ca` | `source/llvm/lib/TextAPI/TextAPIError.cpp` |
| `cu-d91a3cf2e5b2d5c9ae04533a0063456e` | `source/llvm/lib/TextAPI/TextStub.cpp` |
| `cu-32ae07c98a0253dbed3d2422d44b3e63` | `source/llvm/lib/TextAPI/TextStubCommon.cpp` |
| `cu-2c45eedb910aa3eee81a0b401e83aa84` | `source/llvm/lib/TextAPI/TextStubV5.cpp` |
| `cu-33cea930c93f019c983231fce52e575c` | `source/llvm/lib/TextAPI/Utils.cpp` |

The source inventory also records three source-only files in this exact shard:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/TextAPI/BinaryReader/DylibReader.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/TextAPI/RecordVisitor.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/TextAPI/RecordsSlice.cpp` | `not-selected-by-authenticated-build-graph` |

These bindings establish the current module and linked compilation-unit
population before dispatch. The planning count is source-module context; it is
not an emitted-function or accepted-implementation denominator.

## Acceptance state

No shard-specific generated source, emitted-function population, ACP invocation
receipt, compiler or validation receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. Therefore implementation
coverage remains unresolved and release-blocking under #1047. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the emitted function population from the
authenticated rich artifact for these exact linked units, run the qualified
isolated generation workflow with the existing bundled Ghidra/API and
authenticated oracle boundaries, and retain one source plus ACP/validation
receipt per required entity. Any unresolved entity must remain an explicit
blocker.

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
