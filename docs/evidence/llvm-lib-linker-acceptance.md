# `llvm-lib-linker` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1033. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind exactly these two linked handwritten
compilation units to this shard:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-b13dfb43393a47b7bf0147c82aa89b87` | `source/llvm/lib/Linker/IRMover.cpp` | `2cd7638ce2f1de00868fcd4db442b934d8040a75e06efd5d505eea42f2ce53c5` |
| `cu-48436e3024eff262c15b07279d2269fd` | `source/llvm/lib/Linker/LinkModules.cpp` | `943a7502ee03a3b920ec4ddded7adfd3a1dfd87a3fb2baaf6b7c1f5fc83d6fa9` |

The source inventory records no source-only unit in this shard. The checked
planning artifact records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Those planning counts establish
module ownership context; they are not an emitted-function or
accepted-implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. Both linked units
therefore remain unresolved and release-blocking under #1033. Placeholder,
abort/no-op, undeclared shim, and reduced-denominator results cannot count as
accepted implementations.

The next bounded work item must derive the current emitted population for
these exact owners, generate every required implementation through the
qualified isolated ACP workflow, and retain per-module source plus ACP and
validation receipts. Any unresolved entity remains an explicit blocker;
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

The linked units are bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`,
and source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1033
