# `clang-lib-apinotes` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#993. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 planning inventory and checked inventory bind
`clang-lib-apinotes` to exactly four linked handwritten compilation units. The
planning `moduleId`/`unitId` and checked inventory `id` values agree for every
row below; the inventory values also retain the exact DWARF and raw-path
identities.

| Module/unit identity | Exact source path | Inventory `rawPathSha256` | DWARF offset |
| --- | --- | --- | --- |
| `cu-042402a9ea0c689b0908944cf600ac0e` | `source/clang/lib/APINotes/APINotesManager.cpp` | `3c244cc721b82869137e9d12aa2e8c91c5b72d04ebbe04f58110729fb91d4589` | `0x17368a53` |
| `cu-94b7553866655a83895b7de551d1349f` | `source/clang/lib/APINotes/APINotesReader.cpp` | `5e8b09d4424b3426bfaa2bea362839a21ba5804723421c67712d2e7c7b753524` | `0x1739a8f9` |
| `cu-5ec8d605982cb004179de00a30d18bd5` | `source/clang/lib/APINotes/APINotesWriter.cpp` | `4efa4c2337687acd558aeed09162c40d30c8de22969d33837e48624abec78d5f` | `0x1743a0df` |
| `cu-2a8d04e01f11acac933cf3a9dd4b9b2e` | `source/clang/lib/APINotes/APINotesYAMLCompiler.cpp` | `333db8a3f9f3c8f0fe036d5375fb87e48dddcea21050a8c2df2bfc7011fb0546` | `0x173f87a5` |

The source inventory also retains one source-only record that is outside the
linked compilation-unit population because the authenticated build graph did
not select it:

| Source-only path | Reason |
| --- | --- |
| `source/clang/lib/APINotes/APINotesTypes.cpp` | `not-selected-by-authenticated-build-graph` |

The four linked units are handwritten (`4` handwritten, `0` generated). The
four linked identities establish ownership context; they are not an
emitted-function or accepted-implementation denominator. The planning
inventory contains no `acceptedImplementations` count.

## Acceptance state and remaining gaps

The checked repository revision does not retain a shard-specific authenticated
emitted-function population, generated implementation source, ACP invocation
receipt, compiler or validation receipt, behavioral receipt, or retained
accepted checkpoint for this shard. The aggregate release evidence reports
`267944` function entities and `189841` missing functions for the full tree,
but does not allocate those entities to `clang-lib-apinotes`; those aggregate
counts cannot establish acceptance for this shard.

Consequently, all four linked units remain unresolved and release-blocking for
#993. The source-only `APINotesTypes.cpp` record also needs an explicit
source-scope disposition before a complete source denominator can be claimed.
The remaining work must bind the current emitted population for this exact
owner, generate every required implementation through the qualified bounded ACP
workflow, preserve ABI/call/global/name interfaces, and retain per-module source
plus ACP and validation receipts. Unresolved entities remain explicit blockers;
cross-shard interface changes require the existing invalidation authority.
Placeholder returns, abort/no-op bodies, undeclared shims, and reduced
denominators cannot count as accepted implementations.

## Artifact provenance

This evidence is bound to the following repository-controlled LLVM 22.1.6
artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `full-tree-release-evidence.json` | `2a0f7c69848dda29452bf0dfbb0465df2406dee869ce89de55afe34048a8dbb5` |

The repository-wide planning inventory contains `2150` source modules across
`57` shards. That planning count grants no emitted-function or
accepted-implementation authority. The evidence source revision was
`bf2501568f39ab52b23492dfc37839bb81895587` before this document was added.

No broad test suite was run for this bounded evidence checkpoint, per the task
request. The remaining gaps are release blockers under #993.

Refs #993
