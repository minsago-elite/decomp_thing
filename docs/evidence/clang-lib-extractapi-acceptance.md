# `clang-lib-extractapi` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1001. It is bounded planning and dispatch evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `clang-lib-extractapi` to exactly six linked,
handwritten compilation units:

| Module/unit ID | Source path |
| --- | --- |
| `cu-d6c656c2b4dfd48b9f35c634322f6b7e` | `source/clang/lib/ExtractAPI/API.cpp` |
| `cu-0718b8055fb7b3600126d47a0a28b25c` | `source/clang/lib/ExtractAPI/APIIgnoresList.cpp` |
| `cu-2625295803cf9e661bf0a36e7fc1a072` | `source/clang/lib/ExtractAPI/DeclarationFragments.cpp` |
| `cu-9a1582e1eb470744d47ecc408fa9a7af` | `source/clang/lib/ExtractAPI/ExtractAPIConsumer.cpp` |
| `cu-0cca1fa31aa940b6294ad5ff2b2d05d8` | `source/clang/lib/ExtractAPI/Serialization/SymbolGraphSerializer.cpp` |
| `cu-432f7b7c1a227aefe5cb9bc6a489bae8` | `source/clang/lib/ExtractAPI/TypedefUnderlyingTypeResolver.cpp` |

The authenticated source inventory contains no source-only record for this
shard. The planning registry now exposes an exact `clang-lib-extractapi`
owner lookup and rejects invalid or unknown shard IDs. These six rows establish
source-module ownership before dispatch; they are not an emitted-function or
accepted-implementation denominator.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The six linked units
therefore remain unresolved and release-blocking under #1001.

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
verification target.

Refs #1001
