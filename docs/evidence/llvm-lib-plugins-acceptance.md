# `llvm-lib-plugins` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1040. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The checked LLVM 22.1.6 inventories bind exactly one linked handwritten
compilation unit to this shard:

| Field | Value |
| --- | --- |
| shard | `llvm-lib-plugins` |
| module/unit ID | `cu-e30aebfb8fc9d693d2a84dcb07d388c5` |
| source kind | `handwritten` |
| source path | `source/llvm/lib/Plugins/PassPlugin.cpp` |
| raw path SHA-256 | `cba2280ecba7ba9f24d520266c6d8d65bc880378685fdd116b631dc17350a17a` |

The rich inventory, source inventory, planning inventory, and shard index all
agree on this single linked owner. The source inventory records no source-only
unit in this shard. The planning artifact records 2,150 source modules across
57 shards, including 2,149 handwritten and one generated module; that planning
count is module ownership context, not an emitted-function or
accepted-implementation denominator.

These bindings establish the exact module ownership before dispatch. The
authenticated emitted population still has to be derived from the rich
artifact for this unit; the one-module planning count cannot substitute for
that population.

## Acceptance state

No shard-specific generated source, emitted-function population, ACP invocation
receipt, compiler or validation receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. The linked unit therefore
remains unresolved and release-blocking under #1040. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the current emitted population for this
exact owner, run the qualified isolated generation workflow through the
existing bundled Ghidra/API and authenticated oracle boundaries, and retain
one source plus ACP/validation receipt per required entity. Any unresolved
entity must remain an explicit blocker; cross-shard interface changes require
the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The linked unit is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`,
and source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.
