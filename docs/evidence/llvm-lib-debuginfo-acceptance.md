# `llvm-lib-debuginfo` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1027. It is evidence for the bounded planning slice; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind these 47 linked handwritten compilation units
to `llvm-lib-debuginfo`:

| Module/unit ID | Source path |
| --- | --- |
| `cu-e1f05114cd89ddb06abdd9ad2df93c0d` | `source/llvm/lib/DebugInfo/CodeView/CVTypeVisitor.cpp` |
| `cu-39a32a43e0ae0619f56a9bc50350c715` | `source/llvm/lib/DebugInfo/CodeView/CodeViewError.cpp` |
| `cu-58cd9216e7262757ebd40162f65b234f` | `source/llvm/lib/DebugInfo/CodeView/CodeViewRecordIO.cpp` |
| `cu-067094e4865b957986dd400e92d813ec` | `source/llvm/lib/DebugInfo/CodeView/ContinuationRecordBuilder.cpp` |
| `cu-cdd84692347a09372d7ebf625faa280e` | `source/llvm/lib/DebugInfo/CodeView/EnumTables.cpp` |
| `cu-25654e57f644c44bb2a316e0f4c14cad` | `source/llvm/lib/DebugInfo/CodeView/GlobalTypeTableBuilder.cpp` |
| `cu-656f473db6b1b6fec28f4573e7aeb6c3` | `source/llvm/lib/DebugInfo/CodeView/Line.cpp` |
| `cu-7f926943471d8826e311643bdae9df98` | `source/llvm/lib/DebugInfo/CodeView/RecordName.cpp` |
| `cu-d4d0396553e4b7769fe1ec94e1d8a72c` | `source/llvm/lib/DebugInfo/CodeView/RecordSerialization.cpp` |
| `cu-8d53d0e49d81e69f014864c861d6b08b` | `source/llvm/lib/DebugInfo/CodeView/SimpleTypeSerializer.cpp` |
| `cu-35504116851a4e8707597cc2db318e2e` | `source/llvm/lib/DebugInfo/CodeView/SymbolRecordMapping.cpp` |
| `cu-b7766ae979604ca3cabe049ea4d8f0fd` | `source/llvm/lib/DebugInfo/CodeView/TypeHashing.cpp` |
| `cu-b6f038c1b927ec95f03a3d2573be828a` | `source/llvm/lib/DebugInfo/CodeView/TypeIndex.cpp` |
| `cu-4c3706ab50f6162ef54af2b2d7586ccd` | `source/llvm/lib/DebugInfo/CodeView/TypeIndexDiscovery.cpp` |
| `cu-e5d8d84e7f1221ca4d6d0f57425ab56a` | `source/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp` |
| `cu-a793a8502926d579178cc99558f9d48a` | `source/llvm/lib/DebugInfo/CodeView/TypeTableCollection.cpp` |
| `cu-3ec6252f4e06a7c1190c9bdf87be9e6d` | `source/llvm/lib/DebugInfo/DWARF/DWARFAbbreviationDeclaration.cpp` |
| `cu-fe81f81831913f558c3f70060f009dca` | `source/llvm/lib/DebugInfo/DWARF/DWARFAcceleratorTable.cpp` |
| `cu-c3aa6d075b01aa22d7e775ba6a568231` | `source/llvm/lib/DebugInfo/DWARF/DWARFAddressRange.cpp` |
| `cu-bad48fb5d29bec20e31380ef518beb63` | `source/llvm/lib/DebugInfo/DWARF/DWARFCFIPrinter.cpp` |
| `cu-d605ccec3ede6ea519787fb3411a8ce9` | `source/llvm/lib/DebugInfo/DWARF/DWARFCompileUnit.cpp` |
| `cu-a857f100319bde506214c9d9683ed345` | `source/llvm/lib/DebugInfo/DWARF/DWARFContext.cpp` |
| `cu-be36cf1211d608ffaa41eb09672b64cc` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugAbbrev.cpp` |
| `cu-ff76beab08d34dd8b7dc190a7e55a307` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugAddr.cpp` |
| `cu-6eaded623fb5ca4a76d5427c464bcfad` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugArangeSet.cpp` |
| `cu-3ce23e2e5af223620793821f06711171` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugAranges.cpp` |
| `cu-22fc7f5a36710039aaa1e417a19109b1` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugFrame.cpp` |
| `cu-044bbe6799dc12a00be7122b1f3184a8` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugInfoEntry.cpp` |
| `cu-62bec91df17e65217d145d36ad0928d2` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugLine.cpp` |
| `cu-477b8db7df114d591637d3b262e0a4d3` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugLoc.cpp` |
| `cu-d029b56a90d6e6e91e582a1740642f89` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugMacro.cpp` |
| `cu-fc2cc0e02f465f184d98429a4c917e88` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugPubTable.cpp` |
| `cu-fd943fe33f1ee4b9f139a3e7ec397bf3` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugRangeList.cpp` |
| `cu-7a3deccf5f44ef9b473a6dfaf8e7dcc9` | `source/llvm/lib/DebugInfo/DWARF/DWARFDebugRnglists.cpp` |
| `cu-fe7119b71eb7a44352d61d38f9b6548c` | `source/llvm/lib/DebugInfo/DWARF/DWARFDie.cpp` |
| `cu-f0b4b3853ab1106456b162d3dd28cc35` | `source/llvm/lib/DebugInfo/DWARF/DWARFExpressionPrinter.cpp` |
| `cu-572360dcc28fc08270155942151a4536` | `source/llvm/lib/DebugInfo/DWARF/DWARFFormValue.cpp` |
| `cu-d6be115b6cbe69247bc37b4a2a73c44b` | `source/llvm/lib/DebugInfo/DWARF/DWARFGdbIndex.cpp` |
| `cu-83acb6948f1e2ddb0d26a0b8384af8b9` | `source/llvm/lib/DebugInfo/DWARF/DWARFListTable.cpp` |
| `cu-230716ae43218f01fc46e3d4e642ab5c` | `source/llvm/lib/DebugInfo/DWARF/DWARFTypeUnit.cpp` |
| `cu-4677918afe35f0d60be33081ed29f9c0` | `source/llvm/lib/DebugInfo/DWARF/DWARFUnit.cpp` |
| `cu-36e6397e682798b84e525f346d99df57` | `source/llvm/lib/DebugInfo/DWARF/DWARFUnitIndex.cpp` |
| `cu-68c0b54734af3816f490dd323531e285` | `source/llvm/lib/DebugInfo/DWARF/DWARFUnwindTablePrinter.cpp` |
| `cu-88d535a71253aacb15548594abe4a21a` | `source/llvm/lib/DebugInfo/DWARF/DWARFVerifier.cpp` |
| `cu-ef8bd8f9caf7ac1604bc153c056a0a74` | `source/llvm/lib/DebugInfo/DWARF/LowLevel/DWARFCFIProgram.cpp` |
| `cu-2ec8eaaf2e4598b9fafed51b93157e88` | `source/llvm/lib/DebugInfo/DWARF/LowLevel/DWARFExpression.cpp` |
| `cu-5583de22a99362af0cc0f1c8686f26ae` | `source/llvm/lib/DebugInfo/DWARF/LowLevel/DWARFUnwindTable.cpp` |

The source inventory also retains 180 source-only records for this shard, each
excluded from the authenticated build graph with reason
`not-selected-by-authenticated-build-graph`. These records are non-owning
evidence and do not reduce the required implementation population.

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. That planning count is
module ownership context; it is not an emitted-function or accepted-
implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 47 linked units
remain unresolved and release-blocking under #1027. Placeholder, abort/no-op,
undeclared shim, and reduced-denominator results cannot be recorded as accepted
implementations.

The next bounded work item must bind the current emitted population for these
exact owners, generate every required implementation through the qualified
isolated ACP workflow, and retain per-module source plus ACP and validation
receipts. Every unresolved entity must remain an explicit blocker; cross-shard
interface changes require the existing invalidation authority.

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

Refs #1027
