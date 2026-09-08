# `clang-lib-astmatchers` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#995. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `clang-lib-astmatchers` to exactly three
linked, handwritten compilation units:

| Module/unit ID | Source path |
| --- | --- |
| `cu-c92b96b2a7deeb38aa0070c4ec3228e7` | `source/clang/lib/ASTMatchers/ASTMatchFinder.cpp` |
| `cu-7ea999cb15665cc462cbcd7cc46b6f4a` | `source/clang/lib/ASTMatchers/ASTMatchersInternal.cpp` |
| `cu-eb1ca5e071877d61b8ce976f1c8e9427` | `source/clang/lib/ASTMatchers/LowLevelHelpers.cpp` |

The authenticated source inventory also retains five source-only records under
the same shard. They are excluded from ownership because the authenticated
build graph did not select them:

| Source-only path | Reason |
| --- | --- |
| `source/clang/lib/ASTMatchers/Dynamic/Diagnostics.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/ASTMatchers/Dynamic/Marshallers.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/ASTMatchers/Dynamic/Parser.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/ASTMatchers/Dynamic/Registry.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/clang/lib/ASTMatchers/Dynamic/VariantValue.cpp` | `not-selected-by-authenticated-build-graph` |

The planning registry now exposes an exact `clang-lib-astmatchers` owner lookup
and rejects invalid or unknown shard IDs. The three linked rows establish
source-module ownership before dispatch; they are not an emitted-function or
accepted-implementation denominator. The five source-only rows remain retained
evidence and cannot become owners through this lookup.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The three linked units
therefore remain unresolved and release-blocking under #995.

The remaining bounded work must bind the current emitted population, generate
every required implementation through the qualified bounded ACP workflow, and
retain exact per-module source plus ACP/validation receipts. Unresolved
entities must remain explicit blockers; cross-shard interface changes require
the existing invalidation authority. Placeholder returns, abort/no-op bodies,
undeclared shims, and reduced denominators cannot count as accepted
implementations.

## Artifact provenance

The evidence above is bound to these repository-controlled LLVM 22.1.6
artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de9f2e9e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The planning inventory contains 2,150 source modules across 57 shards. That
repository-wide planning count is context only and grants no acceptance or
release authority.

Validation was skipped at the owner's direction for this bounded checkpoint.
The focused `FullTreePlanningInventoryControlTest` added above is the intended
verification target. No broad Gradle suite was run.

Refs #995
