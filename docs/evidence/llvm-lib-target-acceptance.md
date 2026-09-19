# `llvm-lib-target` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1045. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The checked planning inventory, full-tree compilation-unit inventory, and
source inventory agree on exactly 87 linked handwritten modules for
`llvm-lib-target`. The module ID below is also the inventory unit ID; both are
the source-path-derived identity retained by the checked artifacts.

| Module/unit ID | Source path |
| --- | --- |
| `cu-6f604da6c3857f24a6924d0a301a568e` | `source/llvm/lib/Target/RegisterTargetPassConfigCallback.cpp` |
| `cu-a9683b6b50efc2fbf8c4741474c0a007` | `source/llvm/lib/Target/TargetLoweringObjectFile.cpp` |
| `cu-820cb8821acea151418921a4b5660d78` | `source/llvm/lib/Target/TargetMachine.cpp` |
| `cu-d35fc955cf78bb67b254834c82e773a8` | `source/llvm/lib/Target/X86/AsmParser/X86AsmParser.cpp` |
| `cu-b3cd5b93a04b566ab31a51685ff54735` | `source/llvm/lib/Target/X86/GISel/X86CallLowering.cpp` |
| `cu-ffffa258f71630f9ff60c8f5f1a9a262` | `source/llvm/lib/Target/X86/GISel/X86InstructionSelector.cpp` |
| `cu-6e3e1c9da42cb609df4d45e7610d35f9` | `source/llvm/lib/Target/X86/GISel/X86LegalizerInfo.cpp` |
| `cu-4a48e82bdaacec696f27e24eab0824e1` | `source/llvm/lib/Target/X86/GISel/X86PreLegalizerCombiner.cpp` |
| `cu-31df04ddaff1dfdb1013b48f7ab9cbc0` | `source/llvm/lib/Target/X86/GISel/X86RegisterBankInfo.cpp` |
| `cu-c173ad0a295e9663f52c05da763e5861` | `source/llvm/lib/Target/X86/MCTargetDesc/X86ATTInstPrinter.cpp` |
| `cu-1542b8bbf6b02c4191a54c3855feff74` | `source/llvm/lib/Target/X86/MCTargetDesc/X86AsmBackend.cpp` |
| `cu-c87eeef307ecf1d16ad147ae85d25af5` | `source/llvm/lib/Target/X86/MCTargetDesc/X86ELFObjectWriter.cpp` |
| `cu-41d4fe35a459280cb94fc176b51948c2` | `source/llvm/lib/Target/X86/MCTargetDesc/X86EncodingOptimization.cpp` |
| `cu-9bd0d5e2dd0b6d74a2ada92ef1ed8d51` | `source/llvm/lib/Target/X86/MCTargetDesc/X86InstComments.cpp` |
| `cu-7b416d8071ad8d314cc90274e798759f` | `source/llvm/lib/Target/X86/MCTargetDesc/X86InstPrinterCommon.cpp` |
| `cu-d9e0c96a7cac9bb39afacb7a8c7e657d` | `source/llvm/lib/Target/X86/MCTargetDesc/X86IntelInstPrinter.cpp` |
| `cu-ec7d62bf2b9ae5dbfe8b637e34bb893d` | `source/llvm/lib/Target/X86/MCTargetDesc/X86MCAsmInfo.cpp` |
| `cu-b5630d03be7079660db63e7e6828624b` | `source/llvm/lib/Target/X86/MCTargetDesc/X86MCCodeEmitter.cpp` |
| `cu-ed9c74a137c5620450541136513b1166` | `source/llvm/lib/Target/X86/MCTargetDesc/X86MCTargetDesc.cpp` |
| `cu-f622adaa967c961971ead432e7962015` | `source/llvm/lib/Target/X86/MCTargetDesc/X86MachObjectWriter.cpp` |
| `cu-b14961b1419afd80d6b6d8cdf7046b1a` | `source/llvm/lib/Target/X86/MCTargetDesc/X86MnemonicTables.cpp` |
| `cu-bbe7fb4a6f02b6505477afc52ecf70a4` | `source/llvm/lib/Target/X86/MCTargetDesc/X86ShuffleDecode.cpp` |
| `cu-84ea9eb452fc7b44654adac094483588` | `source/llvm/lib/Target/X86/MCTargetDesc/X86WinCOFFObjectWriter.cpp` |
| `cu-f8e4db0c7d0f38ef3fc98c9387cb6f67` | `source/llvm/lib/Target/X86/MCTargetDesc/X86WinCOFFStreamer.cpp` |
| `cu-5395274b95260a123db982af045493df` | `source/llvm/lib/Target/X86/MCTargetDesc/X86WinCOFFTargetStreamer.cpp` |
| `cu-bb2b3f4a7735e0cab0aa0f0ee69beaed` | `source/llvm/lib/Target/X86/TargetInfo/X86TargetInfo.cpp` |
| `cu-17d3abfd2c6dba6e5f62adc647afcec1` | `source/llvm/lib/Target/X86/X86ArgumentStackSlotRebase.cpp` |
| `cu-a69571addba822f0cf07cd2e3ba8f358` | `source/llvm/lib/Target/X86/X86AsmPrinter.cpp` |
| `cu-3af896d94f3a2af74c85cf3ccac95257` | `source/llvm/lib/Target/X86/X86AvoidStoreForwardingBlocks.cpp` |
| `cu-554f6cdb2680bd7daa05e8f63475a13b` | `source/llvm/lib/Target/X86/X86AvoidTrailingCall.cpp` |
| `cu-9998c3e91c14cce64c8a25efb28e37a1` | `source/llvm/lib/Target/X86/X86CallFrameOptimization.cpp` |
| `cu-b268da2e051339e021d4e82d69bd8218` | `source/llvm/lib/Target/X86/X86CallingConv.cpp` |
| `cu-42b8683c57455a60f78a0bfa91979601` | `source/llvm/lib/Target/X86/X86CmovConversion.cpp` |
| `cu-57cf83fa40f09141c0a22bfd41ac2119` | `source/llvm/lib/Target/X86/X86CodeGenPassBuilder.cpp` |
| `cu-46aab28fdbcdc9fc21cc9f0c0edd4881` | `source/llvm/lib/Target/X86/X86CompressEVEX.cpp` |
| `cu-6c11b4d12c0f87406a087100195eb5c9` | `source/llvm/lib/Target/X86/X86DomainReassignment.cpp` |
| `cu-69f0a6f287f77380f4bd65646c0499a4` | `source/llvm/lib/Target/X86/X86DynAllocaExpander.cpp` |
| `cu-b3c2e717813292bf989337dce60c2030` | `source/llvm/lib/Target/X86/X86ExpandPseudo.cpp` |
| `cu-c5f39b052ad2ccfaff40f9df1d2ded7f` | `source/llvm/lib/Target/X86/X86FastISel.cpp` |
| `cu-af02ae9dcf1597ba28575df1d5e367ae` | `source/llvm/lib/Target/X86/X86FastPreTileConfig.cpp` |
| `cu-dd4a412d1828d6b064316f70e66561a8` | `source/llvm/lib/Target/X86/X86FastTileConfig.cpp` |
| `cu-5bd0a28aa1d76e44744725865afe70ff` | `source/llvm/lib/Target/X86/X86FixupBWInsts.cpp` |
| `cu-c815a995ba6da3417a800c03ee9572a4` | `source/llvm/lib/Target/X86/X86FixupInstTuning.cpp` |
| `cu-278f70fe4a2aee15569e640a8e9fee49` | `source/llvm/lib/Target/X86/X86FixupLEAs.cpp` |
| `cu-f414da5fa5e350f1952646e572712952` | `source/llvm/lib/Target/X86/X86FixupSetCC.cpp` |
| `cu-3baf113dbc587dfeea3c25c239e5d290` | `source/llvm/lib/Target/X86/X86FixupVectorConstants.cpp` |
| `cu-fc647c13931e4391ad58f222e44f8100` | `source/llvm/lib/Target/X86/X86FlagsCopyLowering.cpp` |
| `cu-3bd893c8f3faf2fe546e0bb20d86015a` | `source/llvm/lib/Target/X86/X86FloatingPoint.cpp` |
| `cu-ecc91582e350e485c9dda051561932e0` | `source/llvm/lib/Target/X86/X86FrameLowering.cpp` |
| `cu-fbbb3cb1e3867c39eafc49373458a380` | `source/llvm/lib/Target/X86/X86ISelDAGToDAG.cpp` |
| `cu-24b76e4db220375910c9d4bb54c790f4` | `source/llvm/lib/Target/X86/X86ISelLowering.cpp` |
| `cu-3c186a3afcad33c19794fec21e653838` | `source/llvm/lib/Target/X86/X86ISelLoweringCall.cpp` |
| `cu-a96428c7e1c2af19d66a7e7b1edb582b` | `source/llvm/lib/Target/X86/X86IndirectBranchTracking.cpp` |
| `cu-3edf0bead715a20d7a659f237ef83996` | `source/llvm/lib/Target/X86/X86IndirectThunks.cpp` |
| `cu-689c2a4f74d6003f21a423d73ecfdbc6` | `source/llvm/lib/Target/X86/X86InsertWait.cpp` |
| `cu-4a0f042e54370248525d79b21c6b0362` | `source/llvm/lib/Target/X86/X86InstCombineIntrinsic.cpp` |
| `cu-e2781d6f5c48446d2d66af6a9b2b538f` | `source/llvm/lib/Target/X86/X86InstrFMA3Info.cpp` |
| `cu-0eb69a7cb8d3404a3670e16eb91f1beb` | `source/llvm/lib/Target/X86/X86InstrFoldTables.cpp` |
| `cu-1e13860efa5135d8255c2b8a1c1cbda0` | `source/llvm/lib/Target/X86/X86InstrInfo.cpp` |
| `cu-647825dbf6044e56c050a2ba16e01914` | `source/llvm/lib/Target/X86/X86InterleavedAccess.cpp` |
| `cu-9c99e676861367d52a6b284a8a78fdf4` | `source/llvm/lib/Target/X86/X86LoadValueInjectionLoadHardening.cpp` |
| `cu-8657af93e91f741b2cf52187f5a66a8e` | `source/llvm/lib/Target/X86/X86LoadValueInjectionRetHardening.cpp` |
| `cu-a96d66b1967df5a6dba38888fcc0913e` | `source/llvm/lib/Target/X86/X86LowerAMXIntrinsics.cpp` |
| `cu-f6a73cc99e4039c950789a4d5209848a` | `source/llvm/lib/Target/X86/X86LowerAMXType.cpp` |
| `cu-168f75aea70f46178cb0ff4dcdf055bc` | `source/llvm/lib/Target/X86/X86LowerTileCopy.cpp` |
| `cu-bf7579dc396747a79f68421c76082957` | `source/llvm/lib/Target/X86/X86MCInstLower.cpp` |
| `cu-94fa5891861e5dd8414d981cfddf9a6b` | `source/llvm/lib/Target/X86/X86MachineFunctionInfo.cpp` |
| `cu-4206b43601af11ecb975134e1382e8bd` | `source/llvm/lib/Target/X86/X86MacroFusion.cpp` |
| `cu-d85e29a74ffc46820c7234adb84fd451` | `source/llvm/lib/Target/X86/X86OptimizeLEAs.cpp` |
| `cu-8b9eb276b749ae6ef196574a6fea6408` | `source/llvm/lib/Target/X86/X86PadShortFunction.cpp` |
| `cu-ffb5ce650c2c011b001dd6298554a624` | `source/llvm/lib/Target/X86/X86PartialReduction.cpp` |
| `cu-e9f0b7805e0804b3154eced20c6af1cb` | `source/llvm/lib/Target/X86/X86PreTileConfig.cpp` |
| `cu-6ebca2b29ea372316be2b30ba469bc36` | `source/llvm/lib/Target/X86/X86RegisterInfo.cpp` |
| `cu-d9abd4570fb2a7cc5a3f674788942f3c` | `source/llvm/lib/Target/X86/X86ReturnThunks.cpp` |
| `cu-0becbe7a03301bc8fed8f47dd27e24f1` | `source/llvm/lib/Target/X86/X86SelectionDAGInfo.cpp` |
| `cu-2f14f70a34fafc4a68d6186b2f7ae77f` | `source/llvm/lib/Target/X86/X86ShuffleDecodeConstantPool.cpp` |
| `cu-b422a2fafca5240e666bcf9a40cf9218` | `source/llvm/lib/Target/X86/X86SpeculativeExecutionSideEffectSuppression.cpp` |
| `cu-932c67c2ad758c5914925fc87e267acb` | `source/llvm/lib/Target/X86/X86SpeculativeLoadHardening.cpp` |
| `cu-5c2099a936fd490d0e238e0eb97d603f` | `source/llvm/lib/Target/X86/X86Subtarget.cpp` |
| `cu-d8dae753b4bfc32178768cd05a0653f2` | `source/llvm/lib/Target/X86/X86SuppressAPXForReloc.cpp` |
| `cu-e888520e5e9d40c7cca4ea59c0889e6a` | `source/llvm/lib/Target/X86/X86TargetMachine.cpp` |
| `cu-66926df65d9f30dc3b29f65a3068114e` | `source/llvm/lib/Target/X86/X86TargetObjectFile.cpp` |
| `cu-1e5ede5d92f52fdbe331fa0a2a87d173` | `source/llvm/lib/Target/X86/X86TargetTransformInfo.cpp` |
| `cu-134c42bce3ca6b4faf8ac371883ea454` | `source/llvm/lib/Target/X86/X86TileConfig.cpp` |
| `cu-f5849e06303ff34e9891e04e1c151e31` | `source/llvm/lib/Target/X86/X86VZeroUpper.cpp` |
| `cu-f3312f819f33a82f8932844e5d71e076` | `source/llvm/lib/Target/X86/X86WinEHState.cpp` |
| `cu-769e2673cb78aa6279554d772b302757` | `source/llvm/lib/Target/X86/X86WinEHUnwindV2.cpp` |

The full-tree source inventory also records 1,074 source-only rows for this
shard. Those rows preserve authenticated source-graph ownership and are not an
emitted-function or accepted-implementation denominator. The 87 linked rows
are the complete current module population for this shard; no module was
silently removed from the checked inventory.

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. The
planning record binds to scope
`48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

These bindings establish exact module ownership and denominator context. The
planning count is not an emitted-function or accepted-implementation count.

## Acceptance state

No shard-specific generated source, authenticated emitted-function population,
ACP invocation receipt, compiler receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. Therefore the implementation
population remains unresolved and release-blocking under #1045. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for this exact shard, run the qualified isolated
generation workflow with the existing bundled Ghidra/API and authenticated
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

The source-inventory report digest is
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.
