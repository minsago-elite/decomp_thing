# `llvm-lib-lto` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1034. It is evidence for the bounded planning and dispatch slice; it does not
claim that an implementation has been generated, accepted, merged, or
qualified for production.

## Authenticated population

The checked LLVM 22.1.6 planning inventory binds exactly these two linked
handwritten compilation units to `llvm-lib-lto`:

| Module/unit ID | Source path |
| --- | --- |
| `cu-10e0cf737e9c7e002b4d5152b4b2a3ab` | `source/llvm/lib/LTO/LTO.cpp` |
| `cu-9ceb01df3d2e8ec51343ed207b366ec6` | `source/llvm/lib/LTO/LTOBackend.cpp` |

The same shard retains four source-only records, each excluded by the
authenticated build graph:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/LTO/LTOCodeGenerator.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/LTO/LTOModule.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/LTO/ThinLTOCodeGenerator.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/LTO/UpdateCompilerUsed.cpp` | `not-selected-by-authenticated-build-graph` |

The planning artifact records 2,150 source modules across 57 shards, including
2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. That
planning count establishes module ownership context; it is not an
emitted-function or accepted-implementation denominator.

The planning registry now exposes an exact shard-owner lookup that fails closed
for unknown or malformed shard IDs. This binds the two owners before dispatch
while keeping the source-only records non-owning evidence.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The two linked units and
four source-only records therefore remain unresolved and release-blocking under
#1034. A placeholder, abort/no-op body, undeclared shim, or reduced denominator
must not be recorded as an accepted implementation.

The remaining acceptance work must derive the current emitted population for
these exact owners, run the qualified isolated generation workflow through the
existing bundled Ghidra/API and authenticated oracle boundaries, and retain
per-entity source plus ACP/validation receipts. Every unresolved entity must
remain an explicit blocker; cross-shard interface changes require the existing
invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |

The profile binds to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1034
