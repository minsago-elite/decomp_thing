# `clang-lib-serialization` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1012. It is bounded planning evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly these 17 linked handwritten compilation units:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-0a9a292091e14a3b126ec76f90a344f4` | `source/clang/lib/Serialization/ASTCommon.cpp` | `b84f2e79dfdc541ffad29f42b9b3590fa27daf7f9d91cfd3d8485a4cb72ce8c8` |
| `cu-e6917c83429401f509ae35a4f4eaf8e4` | `source/clang/lib/Serialization/ASTReader.cpp` | `1ec6c86048e5390622f05baf4c987fde35a84f1073b88483a87beaf222dc731a` |
| `cu-259fdd0d07f0ca0815e16fcf61c8281a` | `source/clang/lib/Serialization/ASTReaderDecl.cpp` | `6e790b4951c728718b3f5c24d77b2264162cab8bd7d1188f6ce5da086f01abf3` |
| `cu-0ba084f65cabf714f8cb5eb9df77cb4c` | `source/clang/lib/Serialization/ASTReaderStmt.cpp` | `966476f2d096e82ceea1c349fa771e7b8e0bd53ed4b69a5ef95e5586a46ed989` |
| `cu-8e14d92284312caddc401a8851333b2a` | `source/clang/lib/Serialization/ASTWriter.cpp` | `9be9efb83e710efdd3930c84d4c648ce7ecde5f9a28bd7cd5485ae39cb1ee22b` |
| `cu-ece531da3e9dbaf44e7ee5268b88df70` | `source/clang/lib/Serialization/ASTWriterDecl.cpp` | `814040a4dfc1f484dfcf86de1f6d95d23c4e08d0800e9daa70cdbcba77bd5493` |
| `cu-4b20bfda4f32c224fa0d603e5d257230` | `source/clang/lib/Serialization/ASTWriterStmt.cpp` | `948a9872d4d9e35f3ae8e54e1b511181e9232324da5c3eec0d35649d35d03895` |
| `cu-5123521570c5bed40a438c7c05deff9c` | `source/clang/lib/Serialization/GeneratePCH.cpp` | `95f336ffcc25510facc4a3e48dffee54cde77b9628349b152f5bc1400f35bc62` |
| `cu-b67c87ad72ba0661604ef2183061b9f7` | `source/clang/lib/Serialization/GlobalModuleIndex.cpp` | `d3fb2e8e8c3930f5d3c31104cb3565966b89435cd0e05a66d9206be657baea37` |
| `cu-54b2289ecc2cefcdeeb9e7e11ed4e92b` | `source/clang/lib/Serialization/InMemoryModuleCache.cpp` | `c2bf88a00126947c426c48ba70371d838cd4e6a41654488a06c78b2287ea4ad5` |
| `cu-2260128d26855120cb7bd20db43dae78` | `source/clang/lib/Serialization/ModuleCache.cpp` | `e2b206c277c1b6b0f9b88ddc74ddf62e243297a7630cdd0bf34c59343abcede3` |
| `cu-243d6323bcd78cd457ec8fefc47d354b` | `source/clang/lib/Serialization/ModuleFile.cpp` | `b42af89439827a9ead15b3273a6d449606e4b94383d17ee639657551bb6a343c` |
| `cu-3f47b252b27818b09d95da35cdd5f03f` | `source/clang/lib/Serialization/ModuleFileExtension.cpp` | `2b9f4d42431cd7a6dd2c4a0a9884fb3ff198f09bc33f5b90bab559a31ba097e8` |
| `cu-deb209acc96d4e300599877834b9f0c2` | `source/clang/lib/Serialization/ModuleManager.cpp` | `c637763b99a0c0e032901ab191d420f735bfd8b2b3bec46887fb6082b93eafae` |
| `cu-6b47df8a590e3d0a155ad60c9895b60e` | `source/clang/lib/Serialization/ObjectFilePCHContainerReader.cpp` | `5be2e37e09e30c4e63f22b3adfb9c2e75b99160de3fa702bb6520bf207b34221` |
| `cu-fd27f4fa52e9ab283a46b01ab6719204` | `source/clang/lib/Serialization/PCHContainerOperations.cpp` | `b529a1b432a8eafb599864293d228ae576062533c416307780250d873387255f` |
| `cu-2c7598226911f27f66b8eccf805df409` | `source/clang/lib/Serialization/TemplateArgumentHasher.cpp` | `dd0f70a1540e585486170157fc84bd0ea86f90a235ec7b6353ac90b7d2f3e217` |

The authenticated source inventory contains no source-only record for this
shard. These 17 linked units establish planning ownership context; they are
not an emitted-function or accepted-implementation denominator.

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Those planning counts
establish repository-wide ownership context; they are not an emitted-function
or accepted-implementation denominator.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 17 linked units
therefore remain unresolved and release-blocking under #1012.

The remaining bounded work must bind the current emitted population before
dispatch, generate every required implementation through the qualified bounded
ACP workflow, and retain per-module source plus ACP/validation receipts. Every
unresolved entity must remain an explicit blocker; ABI, calls, globals, names,
and cross-shard ownership interfaces require the existing validation and
invalidation authorities. Placeholder returns, abort/no-op bodies, undeclared
shims, and reduced denominators cannot count as accepted implementations.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |

The profile binds the linked units to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1012
