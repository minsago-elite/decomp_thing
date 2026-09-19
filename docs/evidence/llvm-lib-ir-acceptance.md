# `llvm-lib-ir` acceptance evidence

This record is the bounded source-ownership checkpoint for issue #1030. It
binds the exact authenticated `llvm-lib-ir` population from the repository
controlled LLVM 22.1.6 profile. It does not claim that an implementation has
been generated, accepted, merged, or qualified for production.

## Authenticated owner population

The planning, rich compilation-unit, and source inventories agree on exactly
78 linked handwritten modules. Each planning `moduleId` equals its
authenticated compilation-unit `unitId`; no catch-all owner is introduced.

| Module/unit ID | Source path |
| --- | --- |
| `cu-f8418b56ec6ee102d07397d28d5800d4` | `source/llvm/lib/IR/AbstractCallSite.cpp` |
| `cu-0a15b369d4a858f205b0b94ceba2f02d` | `source/llvm/lib/IR/AsmWriter.cpp` |
| `cu-9d04eeb6f4d8282aa2fd75304b2b7838` | `source/llvm/lib/IR/Assumptions.cpp` |
| `cu-39927e15dd033c67518f480a4e709a1a` | `source/llvm/lib/IR/Attributes.cpp` |
| `cu-e1cbeaddf6a1eb3e9c906e4a086af776` | `source/llvm/lib/IR/AutoUpgrade.cpp` |
| `cu-58262aafa91d89ff8c1d200a82fbcb1e` | `source/llvm/lib/IR/BasicBlock.cpp` |
| `cu-65faaddc6694e1063a98086c8e533915` | `source/llvm/lib/IR/BuiltinGCs.cpp` |
| `cu-df4f7f8f96f934e547067be833772f11` | `source/llvm/lib/IR/Comdat.cpp` |
| `cu-a90305b5c5b524344cc1ad82a64fd800` | `source/llvm/lib/IR/ConstantFPRange.cpp` |
| `cu-dcedbde4259ad2a3262f1bb1cd58af54` | `source/llvm/lib/IR/ConstantFold.cpp` |
| `cu-69d99556e3f28761f9c34b176300a088` | `source/llvm/lib/IR/ConstantRange.cpp` |
| `cu-34edd877738df813daf31fdd044e78c2` | `source/llvm/lib/IR/ConstantRangeList.cpp` |
| `cu-1063ccf366ef05f2bd2479de2e75c46c` | `source/llvm/lib/IR/Constants.cpp` |
| `cu-30c1946d04cb88e865cc63ad6d1fc586` | `source/llvm/lib/IR/ConvergenceVerifier.cpp` |
| `cu-b347393f1984296f47263dcc9e2a8cb4` | `source/llvm/lib/IR/CycleInfo.cpp` |
| `cu-3d578263a205c5da40313282358205ed` | `source/llvm/lib/IR/DIBuilder.cpp` |
| `cu-d2f868537df0ca9636326bee9ac256b4` | `source/llvm/lib/IR/DIExpressionOptimizer.cpp` |
| `cu-42710d60c638cc8c06a2113ae8f7f997` | `source/llvm/lib/IR/DataLayout.cpp` |
| `cu-b528c2676d63f0e60cced583526c32bb` | `source/llvm/lib/IR/DebugInfo.cpp` |
| `cu-be0355e851c0015097ec62483346d26a` | `source/llvm/lib/IR/DebugInfoMetadata.cpp` |
| `cu-ecd64417ba6af5dd9a7db656c82c566b` | `source/llvm/lib/IR/DebugLoc.cpp` |
| `cu-0786e821980a0fe0391286392f9b6ffc` | `source/llvm/lib/IR/DebugProgramInstruction.cpp` |
| `cu-673df6e9db0842eb0a31c4ed0af2cdac` | `source/llvm/lib/IR/DiagnosticHandler.cpp` |
| `cu-746cfae72e4db7592cf5069f1e467a60` | `source/llvm/lib/IR/DiagnosticInfo.cpp` |
| `cu-5748678375a20daf42706e6f3ab0559f` | `source/llvm/lib/IR/DiagnosticPrinter.cpp` |
| `cu-30b3891a02fd411e3977ab4b0a9d6c23` | `source/llvm/lib/IR/Dominators.cpp` |
| `cu-eed594d96973125ac99a6d63f567f76a` | `source/llvm/lib/IR/DroppedVariableStats.cpp` |
| `cu-97018d2c302cf66c82b6744dc82a4069` | `source/llvm/lib/IR/DroppedVariableStatsIR.cpp` |
| `cu-22353d2030ffd228e4a5600fcdfe22ed` | `source/llvm/lib/IR/EHPersonalities.cpp` |
| `cu-d0d0fe7953798fe5226f4e43c8fc7a8f` | `source/llvm/lib/IR/FPEnv.cpp` |
| `cu-3d6d0d371924a300b55ea2f78c765e73` | `source/llvm/lib/IR/Function.cpp` |
| `cu-b33d1cb7843bc8e6c45eefd3730ad7c0` | `source/llvm/lib/IR/GCStrategy.cpp` |
| `cu-4943af332fe97ccf76cae5da1074e06e` | `source/llvm/lib/IR/GVMaterializer.cpp` |
| `cu-8873c58521cf38e9e1cf1e308b870e27` | `source/llvm/lib/IR/Globals.cpp` |
| `cu-34ae3c33f0d071040e778c7281780728` | `source/llvm/lib/IR/IRBuilder.cpp` |
| `cu-34d6a8eccd75064bb6bda057507ca661` | `source/llvm/lib/IR/IRPrintingPasses.cpp` |
| `cu-e512096ca5236ba109cd8d2e8a7153db` | `source/llvm/lib/IR/InlineAsm.cpp` |
| `cu-58c00f63da36067ecbbfcc793fc5fc5e` | `source/llvm/lib/IR/Instruction.cpp` |
| `cu-09d3fbaab59760349ff9eea0c2f750aa` | `source/llvm/lib/IR/Instructions.cpp` |
| `cu-20cf7707ed4da8f56ad46a8205cb99e8` | `source/llvm/lib/IR/IntrinsicInst.cpp` |
| `cu-ee9fb6c4e4daad3e29b82cd89f464a62` | `source/llvm/lib/IR/Intrinsics.cpp` |
| `cu-8a516faab74093a154b2d10b00b16124` | `source/llvm/lib/IR/LLVMContext.cpp` |
| `cu-9df0bfa42e3f00c84bf3f7dd7a4c7929` | `source/llvm/lib/IR/LLVMContextImpl.cpp` |
| `cu-0ed1d3c79a3f7bcdabaa69a37d20f85a` | `source/llvm/lib/IR/LLVMRemarkStreamer.cpp` |
| `cu-b2f0045d8c1565b59909a5f6f4602fda` | `source/llvm/lib/IR/LegacyPassManager.cpp` |
| `cu-e2bd3b6e042fe34f8096de5c3e054223` | `source/llvm/lib/IR/MDBuilder.cpp` |
| `cu-cc9327037b3c94004dd66ec404ba677e` | `source/llvm/lib/IR/Mangler.cpp` |
| `cu-5c44726f4b2da59085aa8aa4e5f8820d` | `source/llvm/lib/IR/MemoryModelRelaxationAnnotations.cpp` |
| `cu-6fa0d871159e65e4f6202bc97034e6d6` | `source/llvm/lib/IR/Metadata.cpp` |
| `cu-098fe453b389c0ad7c1539fbddebd7e8` | `source/llvm/lib/IR/Module.cpp` |
| `cu-675878b5d35f6aa37b4bc9460539ccf6` | `source/llvm/lib/IR/ModuleSummaryIndex.cpp` |
| `cu-c08b174814a30786b496a4ef5fda3f62` | `source/llvm/lib/IR/NVVMIntrinsicUtils.cpp` |
| `cu-e94ecf9820ef9700be40468a1156716f` | `source/llvm/lib/IR/Operator.cpp` |
| `cu-11bb695e7ec1bccd7f24346960fb9a6b` | `source/llvm/lib/IR/OptBisect.cpp` |
| `cu-a37f5ed947a487b0735c6f95d1594679` | `source/llvm/lib/IR/Pass.cpp` |
| `cu-c9acc175e9b4504afce66d416e195335` | `source/llvm/lib/IR/PassInstrumentation.cpp` |
| `cu-63767035f5e0eb496a4530baccadd342` | `source/llvm/lib/IR/PassManager.cpp` |
| `cu-62a31ffa3391179d9d2bad52a1310ec4` | `source/llvm/lib/IR/PassRegistry.cpp` |
| `cu-c1ad21e250c51415997abaa055f11dae` | `source/llvm/lib/IR/PassTimingInfo.cpp` |
| `cu-560d15c6f913aacf51527c608003f3de` | `source/llvm/lib/IR/PrintPasses.cpp` |
| `cu-765b878e74a9b5d47eaa54744ba0517a` | `source/llvm/lib/IR/ProfDataUtils.cpp` |
| `cu-189c6fb940816ab7520fc645d0e6b656` | `source/llvm/lib/IR/ProfileSummary.cpp` |
| `cu-47383e08f2387035b2d6591775fcaac0` | `source/llvm/lib/IR/PseudoProbe.cpp` |
| `cu-0d31bd68c9d725aa372b04481ec9cf89` | `source/llvm/lib/IR/ReplaceConstant.cpp` |
| `cu-cf5d6c365951d2a3f34687915c4e227f` | `source/llvm/lib/IR/RuntimeLibcalls.cpp` |
| `cu-7bba2d425fefa57c68b059e5369f2368` | `source/llvm/lib/IR/SSAContext.cpp` |
| `cu-9952f5d804f595b7ea34381bf4de7467` | `source/llvm/lib/IR/SafepointIRVerifier.cpp` |
| `cu-ef5fd8b0f7fb1dba6e672e42ce154c43` | `source/llvm/lib/IR/Statepoint.cpp` |
| `cu-8e9ea74d98ca08a1f2bdc88c2e3fcfc9` | `source/llvm/lib/IR/StructuralHash.cpp` |
| `cu-30070c74a3c5bb4fe3aaa333f1df7b79` | `source/llvm/lib/IR/Type.cpp` |
| `cu-dbab9f128b9c5e69f6262596696d729c` | `source/llvm/lib/IR/TypeFinder.cpp` |
| `cu-82567a50d0cc8347048631dc06a3bc05` | `source/llvm/lib/IR/Use.cpp` |
| `cu-4972d2f85b977e6ae5d9ea69d3942124` | `source/llvm/lib/IR/User.cpp` |
| `cu-409620f2aadf8673e5deb98b91e8bc28` | `source/llvm/lib/IR/VFABIDemangler.cpp` |
| `cu-1ff9171b2b7910995321e275cd5a1af9` | `source/llvm/lib/IR/Value.cpp` |
| `cu-c3de96d6274f43af549a99d2882b21a4` | `source/llvm/lib/IR/ValueSymbolTable.cpp` |
| `cu-fbe30d3ee93545999c0ee285b31afbaa` | `source/llvm/lib/IR/VectorTypeUtils.cpp` |
| `cu-c40d0331b1b6399dba38e2438fe2a4ac` | `source/llvm/lib/IR/Verifier.cpp` |

The source inventory separately records these source-only paths, excluded by
the authenticated build graph and therefore not owner modules:

| Source path | Reason |
| --- | --- |
| `source/llvm/lib/IR/Core.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/IR/TypedPointerType.cpp` | `not-selected-by-authenticated-build-graph` |

The checked planning inventory contains 2,150 source modules across 57 shards.
That planning count and the 78 module rows above establish ownership
context; neither is an emitted-function or accepted-implementation denominator.
The current authenticated emitted-function population for these owners has not
yet been retained, so dispatch and implementation acceptance remain unresolved.

## Acceptance state and remaining gaps

All 78 linked modules remain release-blocking for #1030. This slice
contains no shard-specific generated source, authenticated emitted-function
population, ACP invocation receipt, compiler or validation receipt, behavioral
receipt, or retained accepted checkpoint. Required implementations still need
to be generated through the qualified bounded ACP workflow while preserving
ABI, call, global, name, and ownership interfaces. Per-module source and
ACP/validation receipts must be retained and reconciled; unresolved entities
remain blockers, and cross-shard interface changes require the existing
invalidation authority.

Placeholder returns, abort/no-op stubs, undeclared shims, and reduced
denominators cannot count as accepted implementations. Issue #1030 remains
open.

## Artifact provenance

The evidence is bound to these repository-controlled profile artifacts:

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

Refs #1030
