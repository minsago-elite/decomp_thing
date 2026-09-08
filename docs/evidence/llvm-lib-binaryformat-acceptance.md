# `llvm-lib-binaryformat` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1020. It is bounded planning evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly these 12 linked handwritten compilation units:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-29e771c3529e4352e045871b9313ae38` | `source/llvm/lib/BinaryFormat/AMDGPUMetadataVerifier.cpp` | `d9e5083ab06d3f9ef41a3c970c63a3c2be2eacdf46ad3477076b5d751b9552a8` |
| `cu-703f9741c10120ed2fdfa43d129c262d` | `source/llvm/lib/BinaryFormat/COFF.cpp` | `38cb1db4179a627e41cda14f6dabea45607c1dddef7e58de03a173205d9cded3` |
| `cu-d4be6cba121d56ed028495c52c431dc9` | `source/llvm/lib/BinaryFormat/DXContainer.cpp` | `fc4821855904950f58a5dc4b36569c1be8d57fd7409c5b4efb0ec5468b21befa` |
| `cu-132b9545b89f57e610fd57320afc882a` | `source/llvm/lib/BinaryFormat/Dwarf.cpp` | `be0cebbbd1905470b7895ae4a164c3e13890a1d26a24f427aa6890203ab35180` |
| `cu-8cebaa54a49ed447d518dcf20a7a7325` | `source/llvm/lib/BinaryFormat/MachO.cpp` | `0f1f8fea27e148c1938849ed3b75104aecf4dc7b44d0e3725a41204c264c8658` |
| `cu-94dd8e3242ea45d0ad6050285704d18e` | `source/llvm/lib/BinaryFormat/Magic.cpp` | `5928ad3cc280b99fb0fbfb4eee22b638d275da2352655daae3b10e3c7258098e` |
| `cu-f0c6e2f6be0db7ebf9701b7ffa7d31ff` | `source/llvm/lib/BinaryFormat/MsgPackDocument.cpp` | `92d4940d211450832ee39f643f8bb826f5f58fa0a0f382d80241ce0daa19b09b` |
| `cu-aac4a2dc9f002ea4145dbb8f8e9ce34a` | `source/llvm/lib/BinaryFormat/MsgPackDocumentYAML.cpp` | `8c70e87afc45e6a640f6051140be2fed56f9278cca9d51b3e99c0b2ccabbb903` |
| `cu-5d1b1994287e42188373d7719bbd2a12` | `source/llvm/lib/BinaryFormat/MsgPackReader.cpp` | `d2a5eea758f2f09eec967ef144b9e109b176376dd21aa9a8a639cbc704643ccb` |
| `cu-c969806c41b54809708c6fce10f22b65` | `source/llvm/lib/BinaryFormat/MsgPackWriter.cpp` | `6f2be2627ed908a2ecac8c18660b5afef6d93f520e4651c03c9313921e8d764f` |
| `cu-6c2b8de7404708b8bd81f7a06ae78d48` | `source/llvm/lib/BinaryFormat/Wasm.cpp` | `03757cea5101f780f895ff5b32cead67fd3f4bfe123f0f21e1f4581aa532a3b3` |
| `cu-737b7d2cf984979adb054e1cdad44e3d` | `source/llvm/lib/BinaryFormat/XCOFF.cpp` | `824daf5cc8ecf7be03d065aaaa9608b5717815087d6e15cc54ccb4fc755c5033` |

The source inventory separately records these two source-only paths, excluded
by the authenticated build graph and therefore not owner modules:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/BinaryFormat/ELF.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/BinaryFormat/SFrame.cpp` | `not-selected-by-authenticated-build-graph` |

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Those planning counts
establish ownership context; they are not an emitted-function or
accepted-implementation denominator.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 12 linked units and
2 source-only records therefore remain unresolved and release-blocking under
#1020.

The remaining bounded work must bind the current emitted population before
dispatch, generate every required implementation through the qualified bounded
ACP workflow, and retain exact per-module source plus ACP/validation receipts.
Every unresolved entity must remain an explicit blocker; cross-shard interface
changes require the existing invalidation authority. Placeholder returns,
abort/no-op bodies, undeclared shims, and reduced denominators cannot count as
accepted implementations.

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

Refs #1020
