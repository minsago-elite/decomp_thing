# `llvm-lib-codegentypes` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1026. It is bounded planning evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly one linked handwritten compilation unit:

| Module/unit ID | Source path | Raw path SHA-256 |
| --- | --- | --- |
| `cu-da858bd1d57372dd783722e2e0059c58` | `source/llvm/lib/CodeGenTypes/LowLevelType.cpp` | `0664d69545b4c2ebfac04739d1555365772be66dcba2524364cf6b6d91d52f36` |

The source inventory records no source-only units for this shard. The checked
planning artifact records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Those planning counts establish
module ownership context; they are not an emitted-function or
accepted-implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The linked unit
therefore remains unresolved and release-blocking under #1026. Placeholder
returns, abort/no-op bodies, undeclared shims, and reduced denominators cannot
count as accepted implementations.

The remaining bounded work must derive the current emitted population for this
authenticated owner, generate every required implementation through the
qualified isolated ACP workflow, and retain source plus ACP/validation receipts
for each required entity. Any unresolved entity remains an explicit blocker;
cross-shard interface changes require the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3bb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The linked unit is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1026
