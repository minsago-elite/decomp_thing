# `clang-lib-analysis` implementation evidence

This checkpoint records the current authenticated source boundary for issue
#992. It supports bounded planning and dispatch only; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated scope

The LLVM 22.1.6 full-tree artifacts bind `clang-lib-analysis` to 38 linked,
handwritten compilation units. The source inventory retains 31 additional
source-only records under the same shard; each was excluded because it was not
selected by the authenticated build graph. The planning count of 38 is source
ownership context, not an emitted-function or accepted-implementation
denominator. The inventories contain no accepted-implementation count.

| Identity | Current repository value |
| --- | --- |
| Profile | `clang-llvm-full-tree-22.1.6` |
| LLVM source revision | `fc4aad7b5db3fff421df9a9637605b9ca5667881` |
| Shard | `clang-lib-analysis` |
| Linked modules | `38 handwritten`, `0 generated` |
| Source-only records | `31` |
| Full-tree context | `2,150` modules across `57` shards |
| Evidence input commit | `bf2501568f39ab52b23492dfc37839bb81895587` |

These commitments bind the exact current populations without treating their
counts as acceptance denominators:

| Population | Count | SHA-256 commitment |
| --- | ---: | --- |
| Rich inventory `unitIds` | 38 | `7234f87b3b9dba641dff9acb56fc0ea696c67957ddf32a17f79d2870f8aac530` |
| Planning inventory linked records | 38 | `110d370071fb779a0dbd1e808f9dce6ea71cc94bf2a94c2eae8379785a2d270a` |
| Source inventory linked records | 38 | `b67c68cec07c98180292e6148a6dc272da6f1713b8c1f9efc4eefbfc9b030bcd` |
| Source-only path list | 31 | `4a2fa67792e76e7e799f7bd54c11d968640d8e0aae22056fc51f50e0d1b4b6a9` |

The source-only paths are retained evidence and are not owners:

```text
source/clang/lib/Analysis/ExprMutationAnalyzer.cpp
source/clang/lib/Analysis/FlowSensitive/ASTOps.cpp
source/clang/lib/Analysis/FlowSensitive/AdornedCFG.cpp
source/clang/lib/Analysis/FlowSensitive/Arena.cpp
source/clang/lib/Analysis/FlowSensitive/CNFFormula.cpp
source/clang/lib/Analysis/FlowSensitive/DataflowAnalysisContext.cpp
source/clang/lib/Analysis/FlowSensitive/DataflowEnvironment.cpp
source/clang/lib/Analysis/FlowSensitive/DebugSupport.cpp
source/clang/lib/Analysis/FlowSensitive/Formula.cpp
source/clang/lib/Analysis/FlowSensitive/FormulaSerialization.cpp
source/clang/lib/Analysis/FlowSensitive/HTMLLogger.cpp
source/clang/lib/Analysis/FlowSensitive/Logger.cpp
source/clang/lib/Analysis/FlowSensitive/Models/ChromiumCheckModel.cpp
source/clang/lib/Analysis/FlowSensitive/Models/UncheckedOptionalAccessModel.cpp
source/clang/lib/Analysis/FlowSensitive/Models/UncheckedStatusOrAccessModel.cpp
source/clang/lib/Analysis/FlowSensitive/RecordOps.cpp
source/clang/lib/Analysis/FlowSensitive/SimplifyConstraints.cpp
source/clang/lib/Analysis/FlowSensitive/SmartPointerAccessorCaching.cpp
source/clang/lib/Analysis/FlowSensitive/Transfer.cpp
source/clang/lib/Analysis/FlowSensitive/TypeErasedDataflowAnalysis.cpp
source/clang/lib/Analysis/FlowSensitive/Value.cpp
source/clang/lib/Analysis/FlowSensitive/WatchedLiteralsSolver.cpp
source/clang/lib/Analysis/IntervalPartition.cpp
source/clang/lib/Analysis/Scalable/ASTEntityMapping.cpp
source/clang/lib/Analysis/Scalable/Model/BuildNamespace.cpp
source/clang/lib/Analysis/Scalable/Model/EntityIdTable.cpp
source/clang/lib/Analysis/Scalable/Model/EntityName.cpp
source/clang/lib/Analysis/ThreadSafetyLogical.cpp
source/clang/lib/Analysis/plugins/CheckerDependencyHandling/CheckerDependencyHandling.cpp
source/clang/lib/Analysis/plugins/CheckerOptionHandling/CheckerOptionHandling.cpp
source/clang/lib/Analysis/plugins/SampleAnalyzer/MainCallChecker.cpp
```

## Acceptance state and remaining gaps

The current repository has no shard-specific authenticated emitted-function
population, generated implementation source, ACP invocation receipt, compiler
or validation receipt, behavioral receipt, or retained accepted checkpoint for
this owner. The accepted-implementation count is therefore unestablished, and
the 38 linked units remain unresolved and release-blocking under #992. The 31
source-only records remain excluded non-owning evidence.

The remaining bounded work must bind the current emitted population and exact
module ownership, generate every required implementation through the qualified
bounded ACP workflow, preserve ABI/call/global/name interfaces, and retain
exact per-module source plus ACP and validation receipts. Every unresolved
entity must remain an explicit blocker. Placeholder returns, abort/no-op
bodies, undeclared shims, and reduced denominators cannot count as accepted
implementations. Cross-shard interface changes require the existing
invalidation authority. Merged behavior and production qualification remain
unproven.

## Artifact provenance

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The evidence input was read from `a-series-issue-992`, based on the shared
A-series checkpoint `a-series-shared-analysis-deadline` at the input commit
above. No broad tests were run; validation is limited to the requested
documentation checkpoint and `git diff --check`.

Refs #992
