# `clang-lib-codegen` acceptance evidence

This bounded checkpoint records the authenticated source ownership boundary for
live issue #997. It supports planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `clang-lib-codegen` to exactly 100 linked,
handwritten compilation units. The exact authenticated unit and source
populations are retained by the planning registry and its focused control test.

| Field | Value |
| --- | --- |
| shard | `clang-lib-codegen` |
| linked source modules | `100` |
| source kind | `100 handwritten`, `0 generated` |
| source-only records | `1` |
| source-only path | `source/clang/lib/CodeGen/CodeGenABITypes.cpp` |
| planning selection SHA-256 | `39a81d75b6d383d6e5770461097dec9864451ae6aac0a7b5a668bfa37af59d9c` |
| linked source-record SHA-256 | `2055acddee4ff8ac0d9b1062d25210ee576c18f3db43ac2502243dba1229d0f7` |
| unit-ID SHA-256 | `aab73d25132cb49c991c0047b5bc1822092a61eda3376d0614bef5172e09e926` |
| source-only path SHA-256 | `9bd50ccd203d564c30fffdf48599d626e82a9a3d916135dc168908331e25450f` |
| rich artifact SHA-256 | `c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a` |

The planning selection and linked source-record digests bind module identity,
source path, source kind, and shard ownership. The source-only record remains
explicit evidence and is not a linked emitted-unit denominator. The planning
registry rejects malformed or unknown shard IDs and returns only the exact
authenticated linked module population.

The repository-wide planning inventory contains 2,150 source modules across 57
shards. That planning count is context for ownership and grants no emitted-
function or accepted-implementation authority.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler receipt, validation receipt, behavioral
receipt, or retained accepted checkpoint is present in this slice. The 100
linked units therefore remain unresolved and release-blocking under #997. A
placeholder, abort/no-op body, undeclared shim, or reduced denominator must not
be recorded as an accepted implementation.

The next bounded work must derive the current emitted population for this exact
owner, generate every required implementation through the qualified isolated
ACP workflow, preserve ABI/call/global/name interfaces, and retain one source
plus ACP/validation receipt per required entity. Unresolved entities remain
explicit blockers; cross-shard interface changes require the existing
invalidation authority.

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

Validation was skipped at the owner's direction for this bounded checkpoint.
No broad Gradle suite was run.

Refs #997
