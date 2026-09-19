# `clang-lib-format` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1002. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 planning inventory binds `clang-lib-format` to exactly 22
distinct linked, handwritten compilation units:

| Module/unit ID | Source path |
| --- | --- |
| `cu-57209c22f10d58baa7cf0eecbe9c3aba` | `source/clang/lib/Format/AffectedRangeManager.cpp` |
| `cu-1be3d12356ed189698d0ed89a238feaf` | `source/clang/lib/Format/BreakableToken.cpp` |
| `cu-8d5ff7dc70d3ee00a6b0d9294c5cbbc6` | `source/clang/lib/Format/ContinuationIndenter.cpp` |
| `cu-f1df04c18d457ac2d730b822980bf160` | `source/clang/lib/Format/DefinitionBlockSeparator.cpp` |
| `cu-76b1551aa172d55c8f4aecf0a075ba1c` | `source/clang/lib/Format/Format.cpp` |
| `cu-128f10ad070944ebe1ae11ef1c2ac0b4` | `source/clang/lib/Format/FormatToken.cpp` |
| `cu-5e20d03e2a96fa6b3506c3d54e3788d4` | `source/clang/lib/Format/FormatTokenLexer.cpp` |
| `cu-e671486f3454c206ab21af6159a65f98` | `source/clang/lib/Format/IntegerLiteralSeparatorFixer.cpp` |
| `cu-528d162e027308956bc6bddc84924daa` | `source/clang/lib/Format/MacroCallReconstructor.cpp` |
| `cu-609f20b7bbe84ccc6c101c86f3dcf9ff` | `source/clang/lib/Format/MacroExpander.cpp` |
| `cu-6b34c966feeb22c37d2097a4b6346d5e` | `source/clang/lib/Format/NamespaceEndCommentsFixer.cpp` |
| `cu-1841bcf3f5bc3429f36be9b5e62c7e18` | `source/clang/lib/Format/NumericLiteralCaseFixer.cpp` |
| `cu-6848cf0195512b2cabfcf666ee3a452c` | `source/clang/lib/Format/NumericLiteralInfo.cpp` |
| `cu-d5f72f0aef7904635d273a38a442b4f6` | `source/clang/lib/Format/ObjCPropertyAttributeOrderFixer.cpp` |
| `cu-6060b441729ee28d1bbd6b273b8b331d` | `source/clang/lib/Format/QualifierAlignmentFixer.cpp` |
| `cu-9fcee46c5db216b3ba20e4866916b18e` | `source/clang/lib/Format/SortJavaScriptImports.cpp` |
| `cu-be3625fa1dfffa0c2e1f6f4a94866ba8` | `source/clang/lib/Format/TokenAnalyzer.cpp` |
| `cu-fa9a45b836836e263f175c213480087c` | `source/clang/lib/Format/TokenAnnotator.cpp` |
| `cu-1305fe292f8faabd44ba5c89fbe458fd` | `source/clang/lib/Format/UnwrappedLineFormatter.cpp` |
| `cu-08f279cdec8faf8257b3813cc2a068c9` | `source/clang/lib/Format/UnwrappedLineParser.cpp` |
| `cu-da648a948313d1fbf607042906784bd7` | `source/clang/lib/Format/UsingDeclarationsSorter.cpp` |
| `cu-c275cfaa5865dbc66c777b37c20c92b6` | `source/clang/lib/Format/WhitespaceManager.cpp` |

The authenticated source inventory contains one source-only record for this
shard: `source/clang/lib/Format/MatchFilePath.cpp`, excluded with reason
`not-selected-by-authenticated-build-graph`. The linked rows establish
planning ownership context; they are not an emitted-function or
accepted-implementation denominator.

The planning registry now exposes an exact shard-owner lookup. It rejects
invalid and unknown shard IDs, returns only authenticated linked/generated
modules, and does not authorize implementation acceptance or turn module
ownership into an emitted-function count.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 22 linked units
therefore remain unresolved and release-blocking under #1002.

Required work still must bind the current emitted population before dispatch,
generate every required implementation through the qualified bounded ACP
workflow, and retain per-module source plus ACP/validation receipts. Every
unresolved entity must remain an explicit blocker; ABI, calls, globals, names,
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
That repository-wide planning count is context only and grants no acceptance or
release authority.

Validation was skipped at the owner's direction. No broad Gradle suite was run.

Refs #1002
