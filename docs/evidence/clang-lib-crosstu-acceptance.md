# `clang-lib-crosstu` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#998. It is bounded planning and dispatch evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `clang-lib-crosstu` to exactly one linked,
handwritten compilation unit:

| Module/unit ID | Source path |
| --- | --- |
| `cu-f625ae498a1083e1b03965cb3de020fe` | `source/clang/lib/CrossTU/CrossTranslationUnit.cpp` |

The authenticated source inventory contains no source-only record for this
shard. The linked row establishes planning ownership context; it is not an
emitted-function or accepted-implementation denominator.

The planning registry now exposes an exact `clang-lib-crosstu` owner lookup and
rejects invalid or unknown shard IDs. It does not authorize implementation
acceptance or turn module ownership into an emitted-function count.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The linked unit
therefore remains unresolved and release-blocking under #998.

Required work still must bind the current emitted population before dispatch,
generate every required implementation through the qualified bounded ACP
workflow, and retain exact per-module source plus ACP/validation receipts.
Unresolved entities must remain explicit blockers; ABI, calls, globals, names,
and cross-shard ownership interfaces require the existing validation and
invalidation authorities. Placeholder returns, abort/no-op bodies, undeclared
shims, and reduced denominators cannot count as accepted implementations.

## Artifact provenance

The evidence above is bound to these repository-controlled LLVM 22.1.6
artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The checked planning inventory contains 2,150 source modules across 57 shards.
That repository-wide planning count is context only and grants no acceptance
or release authority.

Focused validation was skipped for this bounded checkpoint at the owner's
direction. No broad Gradle suite was run.

Refs #998
