# `clang-lib-codegen` implementation state

The request named `clang-lib-basic`, but live issue #997 owns the
`clang-lib-codegen` shard; `clang-lib-basic` is the separate issue #996. This
checkpoint follows the live issue and binds
the implementation work to the repository's authenticated LLVM 22.1.6
inventories and records the remaining acceptance gaps.

| Identity | Current repository value |
| --- | --- |
| owner shard | `clang-lib-codegen` |
| linked source modules | `100` handwritten modules |
| source-only record | `source/clang/lib/CodeGen/CodeGenABITypes.cpp` |
| planning inventory | `oracle/llvm/22.1.6/full-tree-planning-inventory.json` (`sha256: 2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`) |
| source inventory | `oracle/llvm/22.1.6/full-tree-source-inventory.json` (`sha256: 33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4`) |
| linked inventory | `oracle/llvm/22.1.6/full-tree-inventory.json` (`sha256: 6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306`) |
| authenticated owner selection | `39a81d75b6d383d6e5770461097dec9864451ae6aac0a7b5a668bfa37af59d9c` |

The planning population is source ownership context. It is not an emitted
function denominator and does not authorize acceptance. The current checkout
has no shard-specific emitted-function population, generated implementation
source, ACP invocation receipt, compiler or validation receipt, behavioral
receipt, or retained accepted checkpoint for this owner. All 100 linked
modules therefore remain unresolved and release-blocking.

Remaining work is to derive the authenticated emitted population, generate
each required implementation through the bounded qualified ACP workflow, and
retain exact per-module source plus ACP and validation receipts. ABI, call,
global, name, and cross-shard ownership interfaces still require their existing
validation or invalidation authority. Placeholder returns, abort/no-op bodies,
undeclared shims, and reduced denominators cannot satisfy #997.

Validation for this documentation checkpoint is limited to `git diff --check`;
no broad test suite was run.

Refs #997
