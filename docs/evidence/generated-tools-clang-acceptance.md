# `generated-tools-clang` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1017. It is bounded planning and evidence only; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 scope, rich inventory, planning inventory, and source inventory
agree that `generated-tools-clang` owns exactly one linked generated
compilation unit:

| Module/unit ID | Source kind | Source path | Raw path SHA-256 |
| --- | --- | --- | --- |
| `cu-3da39408d5c2027c7eb363fc9bf9d3f3` | `generated` | `generated/tools/clang/tools/driver/clang-driver.cpp` | `1c88f13ae3952cae881655a842bd34571fb1c9d669ea3322e1da7ae213da9632` |

The checked planning inventory lists one source module for this shard. That
row establishes exact module ownership and dispatch context; it is not an
emitted-function or accepted-implementation denominator.

The checked test resources also retain a four-emitted, four-non-emitted
function-observation shape for this shard. Their provenance identifies them as
inert Python-origin differential fixtures rather than authoritative oracle,
production, or release input. They therefore cannot bind the current emitted
population or authorize acceptance.

## Acceptance state and remaining gaps

No shard-specific generated implementation, ACP invocation receipt, compiler or
validation receipt, behavioral receipt, or retained accepted checkpoint is
present in this slice. The one linked generated unit and any emitted entities
that a fresh authenticated dispatch derives therefore remain unresolved and
release-blocking under #1017.

The remaining bounded work must bind the current emitted population before
dispatch, generate every required implementation through the qualified bounded
ACP workflow, and retain exact per-module source plus ACP and validation
receipts. Every unresolved entity must remain an explicit blocker; ABI, calls,
globals, names, and cross-shard ownership changes require the existing
validation and invalidation authorities. Placeholder returns, abort/no-op
bodies, undeclared shims, and reduced denominators cannot count as accepted
implementations.

## Artifact provenance

The ownership boundary above is read from the repository-controlled LLVM 22.1.6
profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The planning inventory contains 2,150 source modules across 57 shards. That
repository-wide planning count is context only and grants no acceptance or
release authority.

Refs #1017
