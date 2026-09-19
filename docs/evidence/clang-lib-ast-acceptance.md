# `clang-lib-ast` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#994. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

The task request named `clang-lib-apinotes`, but the live GitHub issue #994 is
currently scoped to `clang-lib-ast`; `clang-lib-apinotes` is the subject of
issue #993. This document follows the current #994 issue scope so its `Refs`
line remains truthful.

## Authenticated population

The LLVM 22.1.6 planning and checked inventory artifacts bind
`clang-lib-ast` to exactly 110 linked handwritten compilation units. The
planning records expose the exact module identity fields
`moduleId`, `unitId`, `shardId`, `sourceKind`, and `sourcePath`; the checked
inventory exposes the corresponding exact `id`, `shardId`, `sourceKind`, and
`sourcePath` fields. The focused inventory control test binds the complete
module-ID set to the inventory unit-ID set and the complete source-path set to
the same shard.

| Identity | Current repository value |
| --- | --- |
| Shard | `clang-lib-ast` |
| Linked planning modules | `110` |
| Checked inventory units | `110` |
| Linked source kind | `110 handwritten`, `0 generated` |
| Source-only records | `4` |

The four retained source-only records are excluded from linked ownership
because the authenticated build graph did not select them:

| Source-only path | Reason |
| --- | --- |
| `source/clang/lib/AST/AttrDocTable.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/AST/ExternalASTMerger.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/AST/InheritViz.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/AST/QualTypeNames.cpp` | `not-selected-by-authenticated-build-graph` |

The 110 linked module/unit identities establish planning ownership context.
They are not an emitted-function or accepted-implementation denominator. The
planning inventory also contains no `acceptedImplementations` count.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. All 110 linked units
therefore remain unresolved and release-blocking under #994.

The remaining bounded work must bind the current emitted population for this
exact owner, generate every required implementation through the qualified
bounded ACP workflow, preserve ABI/call/global/name interfaces, and retain
per-module source plus ACP/validation receipts. Unresolved entities remain
explicit blockers; cross-shard interface changes require the existing
invalidation authority. Placeholder returns, abort/no-op bodies, undeclared
shims, and reduced denominators cannot count as accepted implementations.

## Artifact provenance

The evidence is bound to these repository-controlled LLVM 22.1.6 artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The repository-wide planning inventory contains 2,150 source modules across
57 shards. That planning count is context only and grants no emitted-function
or accepted-implementation authority.

No broad test suite was run for this bounded evidence checkpoint.

Refs #994
