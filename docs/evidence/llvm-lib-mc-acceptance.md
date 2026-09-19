# `llvm-lib-mc` acceptance evidence

This checkpoint records the authenticated ownership boundary for issue #1035.
It is planning evidence only and does not claim that an implementation has
been generated, accepted, merged, or qualified for production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that shard `llvm-lib-mc` owns 68 linked handwritten compilation units. Each
linked record has the same authenticated `unitId`/`moduleId`, shard ID, source
kind, and source path across the checked inventories. The planning inventory
also records 20 source-only paths for this shard, each with reason
`not-selected-by-authenticated-build-graph`; those paths do not own emitted
implementations and must not be used to reduce the required denominator.

The planning inventory contains 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. That planning count is
module ownership context, not an emitted-function or accepted-implementation
denominator. The current emitted-function population still requires a
shard-specific authenticated derivation before dispatch.

## Acceptance state

No `llvm-lib-mc` generated source, emitted-function population, ACP invocation
receipt, compiler or validation receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. The 68 linked units and their
20 explicit source-only records therefore remain unresolved and
release-blocking under #1035. Placeholder returns, abort/no-op bodies,
undeclared shims, and reduced denominators must not be recorded as accepted
implementations.

The next bounded step must derive the current emitted population for these
authenticated owners, run the qualified isolated generation workflow through
the bundled Ghidra/API and authenticated oracle boundaries, and retain source
plus ACP/validation receipts for every required entity. Any unresolved entity
must remain an explicit blocker; cross-shard interface changes require the
existing invalidation authority.

## Artifact provenance

The evidence above is bound to the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The linked population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`,
and source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1035
