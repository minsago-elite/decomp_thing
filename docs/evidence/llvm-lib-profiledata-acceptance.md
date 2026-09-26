# `llvm-lib-profiledata` planning ownership evidence

This checkpoint records the authenticated source ownership boundary for issue
#1041. It supports bounded planning and dispatch. It does not claim generated,
accepted, merged, or production-qualified implementations.

## Authenticated population

The LLVM 22.1.6 planning inventory binds exactly 18 linked handwritten
compilation units to this shard. The planning registry test checks each unit
identity, the `source/llvm/lib/ProfileData/` path prefix, and the owner count.

| Module/unit ID | Source path |
| --- | --- |
| `cu-19fe7b34cd4f85848972e8a227bfe4e9` | `source/llvm/lib/ProfileData/Coverage/CoverageMapping.cpp` |
| `cu-6e58360b907f408b404d0deeeb8c3226` | `source/llvm/lib/ProfileData/Coverage/CoverageMappingReader.cpp` |
| `cu-68dc9d9dace05087bd2c3903ff7dee01` | `source/llvm/lib/ProfileData/Coverage/CoverageMappingWriter.cpp` |
| `cu-f624fc8f21784940d4bf211f84a3ef8b` | `source/llvm/lib/ProfileData/DataAccessProf.cpp` |
| `cu-4edcbab422fb93692b69eb464536025a` | `source/llvm/lib/ProfileData/IndexedMemProfData.cpp` |
| `cu-61e93856b007c28ae346fc44bbc76dc7` | `source/llvm/lib/ProfileData/InstrProf.cpp` |
| `cu-e873d7d2d14f0384d3c788589852f10e` | `source/llvm/lib/ProfileData/InstrProfCorrelator.cpp` |
| `cu-68e571469da776cc38ad9c2e91b38dbe` | `source/llvm/lib/ProfileData/InstrProfReader.cpp` |
| `cu-e78e9ef1ae7588b7d5641e333c4d4d03` | `source/llvm/lib/ProfileData/ItaniumManglingCanonicalizer.cpp` |
| `cu-4fcf41d3ff82e14345e9f2b24beaf1fb` | `source/llvm/lib/ProfileData/MemProf.cpp` |
| `cu-71a24a91f9e7904474b07932b56968a4` | `source/llvm/lib/ProfileData/MemProfCommon.cpp` |
| `cu-a3f9902353be6a57148efc168bcc2365` | `source/llvm/lib/ProfileData/MemProfRadixTree.cpp` |
| `cu-ea88912ed409d93cf092ed19212abf1c` | `source/llvm/lib/ProfileData/MemProfSummary.cpp` |
| `cu-5418c6fe09733799a000b4e829f3bb83` | `source/llvm/lib/ProfileData/PGOCtxProfReader.cpp` |
| `cu-e7480729c2f74c42d4b021184e9c0ebd` | `source/llvm/lib/ProfileData/ProfileSummaryBuilder.cpp` |
| `cu-f1cdb7f2980cbeb4532fc35ee9bdff8b` | `source/llvm/lib/ProfileData/SampleProf.cpp` |
| `cu-0f14c02d18ab4681357def349334df8b` | `source/llvm/lib/ProfileData/SampleProfReader.cpp` |
| `cu-07ca05e531f6af110fb76470de025ebc` | `source/llvm/lib/ProfileData/SymbolRemappingReader.cpp` |

Six source-only records in the same shard are excluded from the linked
compilation-unit population: `GCOV.cpp`, `InstrProfWriter.cpp`,
`MemProfReader.cpp`, `MemProfSummaryBuilder.cpp`, `PGOCtxProfWriter.cpp`, and
`SampleProfWriter.cpp`. All six carry the reason code
`not-selected-by-authenticated-build-graph`. The 18 owners are planning context,
not an emitted-function or accepted-implementation denominator.

## Acceptance state and remaining gaps

This slice contains no authenticated emitted-function population, accepted
source, ACP execution receipt, compiler/validation receipt, behavioral receipt,
or retained implementation checkpoint for this shard. The implementation work
in #1041 remains unresolved and release-blocking. It must derive the current
emitted population, generate every required implementation through the qualified
bounded ACP workflow, retain source and validation receipts per module, and
reconcile unresolved entities. ABI, calls, globals, names, and cross-shard
interfaces remain subject to existing validation and invalidation authority.

## Artifact provenance

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The planning inventory lists 2,150 source modules across 57 shards. These
repository-wide counts carry no acceptance or release authority.

Refs #1041
