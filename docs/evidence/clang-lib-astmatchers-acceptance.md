# `clang-lib-astmatchers` acceptance evidence

This issue-specific checkpoint binds the requested A-series shard to the
current authenticated LLVM 22.1.6 repository inventories. It records planning
ownership only; it does not claim generated, accepted, merged, or production
qualified implementations.

## Current authenticated identities

The planning inventory identifies exactly three linked handwritten modules for
`clang-lib-astmatchers`:

| `moduleId` = `unitId` | `sourcePath` |
| --- | --- |
| `cu-c92b96b2a7deeb38aa0070c4ec3228e7` | `source/clang/lib/ASTMatchers/ASTMatchFinder.cpp` |
| `cu-7ea999cb15665cc462cbcd7cc46b6f4a` | `source/clang/lib/ASTMatchers/ASTMatchersInternal.cpp` |
| `cu-eb1ca5e071877d61b8ce976f1c8e9427` | `source/clang/lib/ASTMatchers/LowLevelHelpers.cpp` |

The source inventory agrees that those three units are `linked`. It also
contains five `source-only` records for this shard, each excluded by
`not-selected-by-authenticated-build-graph`:

```text
source/clang/lib/ASTMatchers/Dynamic/Diagnostics.cpp
source/clang/lib/ASTMatchers/Dynamic/Marshallers.cpp
source/clang/lib/ASTMatchers/Dynamic/Parser.cpp
source/clang/lib/ASTMatchers/Dynamic/Registry.cpp
source/clang/lib/ASTMatchers/Dynamic/VariantValue.cpp
```

The five source-only records are evidence of excluded source, not accepted
implementation ownership or a denominator reduction. The current issue body
names `clang-lib-basic`, while this requested shard is `clang-lib-astmatchers`;
that issue metadata mismatch remains an explicit tracking gap.

## Remaining acceptance gaps

No authenticated emitted-function population, generated implementation source,
bounded ACP invocation receipt, per-module validation receipt, ABI/call/global/
name reconciliation, behavioral receipt, or retained accepted checkpoint is
present for these three owners. All three linked modules therefore remain
unresolved and release-blocking under the requested outcome. The five
source-only paths also require an explicit disposition before any claim of
complete shard coverage.

Acceptance still requires every required emitted entity to be reconciled and
generated through the qualified bounded ACP workflow, with per-module source
and ACP/validation receipts retained. Placeholder returns, abort/no-op bodies,
undeclared shims, and reduced denominators cannot count as accepted.

## Repository artifact identities

The evidence is bound to these current repository-controlled LLVM 22.1.6
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

No broad tests were run for this bounded evidence checkpoint.

Refs #996
