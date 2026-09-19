# `llvm-lib-object` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1036. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, source inventory, and planning inventory agree
on 27 linked handwritten compilation units owned by this shard:

| Module/unit ID | Source path |
| --- | --- |
| `cu-0976ad48f5610f85bd0d55c26122de1f` | `source/llvm/lib/Object/Archive.cpp` |
| `cu-c78200b85f605ce133809d1ad42735e9` | `source/llvm/lib/Object/ArchiveWriter.cpp` |
| `cu-7a82e008b00d3ae1107b30ea760417ee` | `source/llvm/lib/Object/Binary.cpp` |
| `cu-d99182975386859227d08afd96b40704` | `source/llvm/lib/Object/BuildID.cpp` |
| `cu-f32c4cce57c33403b0bd4557fb78b75f` | `source/llvm/lib/Object/COFFImportFile.cpp` |
| `cu-afd9eb00a8f03cfd743b26523873885b` | `source/llvm/lib/Object/COFFObjectFile.cpp` |
| `cu-6348d5b2c066ce106b18d19b27002956` | `source/llvm/lib/Object/DXContainer.cpp` |
| `cu-2af8a5aeea3d645b68e6a449b1c0de67` | `source/llvm/lib/Object/Decompressor.cpp` |
| `cu-150d3e7a997267e0150c8076cf15d1c3` | `source/llvm/lib/Object/ELF.cpp` |
| `cu-b538aba43f994f8741ce7bbd590858d9` | `source/llvm/lib/Object/ELFObjectFile.cpp` |
| `cu-0ed02391e721306cc3c6717699f698a0` | `source/llvm/lib/Object/Error.cpp` |
| `cu-0df7455bf0414003792b56930c61c8cd` | `source/llvm/lib/Object/IRObjectFile.cpp` |
| `cu-f89b7222eea09f95f4264abc30a43593` | `source/llvm/lib/Object/IRSymtab.cpp` |
| `cu-4921040647ec19241c2fc4721a3f9ea8` | `source/llvm/lib/Object/MachOObjectFile.cpp` |
| `cu-d1dcc8952cd6ff3bb15183df15e45608` | `source/llvm/lib/Object/MachOUniversal.cpp` |
| `cu-aa4138bb3eb6530bb6e39756aef78764` | `source/llvm/lib/Object/Minidump.cpp` |
| `cu-ec6363340cac7b34d854ecd7d8ba985a` | `source/llvm/lib/Object/ModuleSymbolTable.cpp` |
| `cu-8390377cbc38469b2e63db92ac687618` | `source/llvm/lib/Object/ObjectFile.cpp` |
| `cu-eb42c9085871b71c40b1b08c15bed6f2` | `source/llvm/lib/Object/OffloadBinary.cpp` |
| `cu-bc27d4560d8e59fe3ab57dce28c9a707` | `source/llvm/lib/Object/RecordStreamer.cpp` |
| `cu-83261a181c9a6241d0c3649389a741e9` | `source/llvm/lib/Object/RelocationResolver.cpp` |
| `cu-29b14ebe3e57be78dbfa8826817cf71a` | `source/llvm/lib/Object/SymbolicFile.cpp` |
| `cu-7b6cc53593e4ad4cedd51a0b2e8214f8` | `source/llvm/lib/Object/TapiFile.cpp` |
| `cu-9f40c3bb25d3f90b93347337d13bd439` | `source/llvm/lib/Object/TapiUniversal.cpp` |
| `cu-272898e0daa85800d0c0d83e893c2c07` | `source/llvm/lib/Object/WasmObjectFile.cpp` |
| `cu-4145dbd25beca415c4b5c9e0f08b83cd` | `source/llvm/lib/Object/WindowsResource.cpp` |
| `cu-1e8c8b678831f5badea382624bf6d41f` | `source/llvm/lib/Object/XCOFFObjectFile.cpp` |

The source inventory retains these nine source-only records, each excluded by
the authenticated build graph with reason `not-selected-by-authenticated-build-graph`:

`COFFModuleDefinition.cpp`, `FaultMapParser.cpp`, `GOFFObjectFile.cpp`,
`MachOUniversalWriter.cpp`, `Object.cpp`, `OffloadBundle.cpp`,
`SFrameParser.cpp`, `SymbolSize.cpp`, and `WindowsMachineFlag.cpp`.

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Its planning count is
module ownership context, not an emitted-function or accepted-implementation
denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 27 linked units
therefore remain unresolved and release-blocking under #1036. The nine
source-only records remain explicit non-owning exclusions. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must bind the current emitted population for these
exact owners, run the qualified isolated generation workflow through the
existing bundled Ghidra/API and authenticated oracle boundaries, and retain
one source plus ACP/validation receipt per required entity. Every unresolved
entity must remain an explicit blocker; cross-shard interface changes require
the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The linked population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1036
