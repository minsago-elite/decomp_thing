# `llvm-lib-cgdata` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1024. It is bounded planning evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly seven linked handwritten compilation units:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-15f478330c0fbedf00846f039c4dea7f` | `source/llvm/lib/CGData/CodeGenData.cpp` | `4a61eebbb74f60b258b52115b1c879671d4e42d4c547c3eff14a0b17b0f3848b` |
| `cu-a33c51fcc68b8983abcf41e71d00ad0d` | `source/llvm/lib/CGData/CodeGenDataReader.cpp` | `f0ca562c1780ff07f90e7d35044db7c1d977936c8d8f8906b42db486b83450e9` |
| `cu-ed2317f91a7c6ed1c4762ef4615afb14` | `source/llvm/lib/CGData/CodeGenDataWriter.cpp` | `f5ab03fcc40158e7538cdc65794731ca2993052c924fe23f62841c1b2d073c97` |
| `cu-1d1463ae02a4d79ce27f850f20c659b6` | `source/llvm/lib/CGData/OutlinedHashTree.cpp` | `888e198be0cd28157373d2bd234fd4580b3dc4e4f30d6a50053ea8d36b38cdb4` |
| `cu-2a8c065486201de5e6ba6df84366fef2` | `source/llvm/lib/CGData/OutlinedHashTreeRecord.cpp` | `7321d54eaab20bfc4f982f0e3914bb2150233e9d95c61f0c4b98937d50dedd80` |
| `cu-fa108bb0cfdd83f4e63203f3c5fef177` | `source/llvm/lib/CGData/StableFunctionMap.cpp` | `f32ed2f3691dae4f8740f950d0c126cd28255bf896d04a2aa47a95cb58528c9a` |
| `cu-64d42f6fd16d36a6d52e2519f6b2b67a` | `source/llvm/lib/CGData/StableFunctionMapRecord.cpp` | `54599d08e409e86798833e250e67040fe2591a40a99201f0f4973081e5350537` |

The source inventory records no source-only units in this shard. The checked
planning artifact records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Those planning counts establish
module ownership context; they are not an emitted-function or accepted-
implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The seven linked units
therefore remain unresolved and release-blocking under #1024. Placeholder,
abort/no-op, undeclared shim, and reduced-denominator results cannot be
recorded as accepted implementations.

The next bounded work item must bind the current emitted population for these
exact owners, generate every required implementation through the qualified
isolated ACP workflow, and retain per-module source plus ACP and validation
receipts. Every unresolved entity must remain an explicit blocker;
cross-shard interface changes require the existing invalidation authority.

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

Refs #1024
