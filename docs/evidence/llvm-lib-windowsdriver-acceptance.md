# `llvm-lib-windowsdriver` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1049. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The A14 planning inventory binds exactly one source module to this shard:

| Field | Value |
| --- | --- |
| shard | `llvm-lib-windowsdriver` |
| module ID | `cu-5572c6d4ba5cb08588ce2d19fb539cec` |
| unit ID | `cu-5572c6d4ba5cb08588ce2d19fb539cec` |
| source kind | `handwritten` |
| source path | `source/llvm/lib/WindowsDriver/MSVCPaths.cpp` |

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`.
The planning record binds to scope
`48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

These bindings establish module ownership and denominator context. The
planning count is not an emitted-function or accepted-implementation count.

## Acceptance state

No shard-specific generated source, authenticated emitted-function population,
ACP invocation receipt, compiler receipt, behavioral receipt, or retained
accepted checkpoint is present in this slice. Therefore the implementation
population remains unresolved and release-blocking under #1049. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the current emitted population from the
authenticated rich artifact for this exact unit, run the qualified isolated
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

