# `llvm-lib-targetparser` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1046. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventory and planning inventory bind exactly these 14
handwritten source modules to this shard:

| Module/unit ID | Source path |
| --- | --- |
| `cu-6fb34da2e0b6a53c394777035ab2ab51` | `source/llvm/lib/TargetParser/AArch64TargetParser.cpp` |
| `cu-d14c276d7258d17a997cbf1ce1247019` | `source/llvm/lib/TargetParser/ARMTargetParser.cpp` |
| `cu-72859c6d7b7c8212619cfa7f39efef70` | `source/llvm/lib/TargetParser/ARMTargetParserCommon.cpp` |
| `cu-b4bf9e50afe9e149cdaac3d90eab1873` | `source/llvm/lib/TargetParser/CSKYTargetParser.cpp` |
| `cu-aaba6dd48dbd1e9ae2e549eb3890f645` | `source/llvm/lib/TargetParser/Host.cpp` |
| `cu-e6f617c850a366bf90ee46f1f0c14510` | `source/llvm/lib/TargetParser/LoongArchTargetParser.cpp` |
| `cu-ad6319818ea02a7d85c662c2a1b23194` | `source/llvm/lib/TargetParser/PPCTargetParser.cpp` |
| `cu-197afd26301ccfda4ee2cb0884720f5a` | `source/llvm/lib/TargetParser/RISCVISAInfo.cpp` |
| `cu-b6c14c4a5f199776f044e0506454d2bd` | `source/llvm/lib/TargetParser/RISCVTargetParser.cpp` |
| `cu-1361ed97afd96252cebfff44ab5ab425` | `source/llvm/lib/TargetParser/SubtargetFeature.cpp` |
| `cu-aaca5a4e2e84607252a9f08e630ee4bf` | `source/llvm/lib/TargetParser/TargetDataLayout.cpp` |
| `cu-e3657e2bd75a37ba61790a12da92553c` | `source/llvm/lib/TargetParser/TargetParser.cpp` |
| `cu-6e9bfedc1d9283adba6a5ae5fd284013` | `source/llvm/lib/TargetParser/Triple.cpp` |
| `cu-6dadb15c2f9e58633c921509c36e3e75` | `source/llvm/lib/TargetParser/X86TargetParser.cpp` |

The planning artifact records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. The
authenticated inventory contains the same 14 targetparser owners. The source
inventory separately retains
`source/llvm/lib/TargetParser/XtensaTargetParser.cpp` as
`not-selected-by-authenticated-build-graph`; it is source-only evidence and is
not an owning emitted module.

These bindings establish the exact module ownership and denominator context
before dispatch. The 14-module planning count is not an emitted-function or
accepted-implementation count.

## Acceptance state

No shard-specific emitted-function population, generated source, ACP invocation
receipt, compiler receipt, behavioral receipt, or retained accepted checkpoint
is present in this slice. Therefore the implementation population remains
unresolved and release-blocking under #1046. A placeholder, abort/no-op body,
undeclared shim, or reduced denominator must not be recorded as an accepted
implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for these exact owners, run the qualified isolated
generation workflow with the existing bundled Ghidra/API and authenticated
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
