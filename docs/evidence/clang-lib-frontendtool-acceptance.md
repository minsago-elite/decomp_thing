# `clang-lib-frontendtool` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1004. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `clang-lib-frontendtool` to exactly one
linked, handwritten compilation unit:

| Module/unit ID | Source path |
| --- | --- |
| `cu-b4837ea4cc24818596b117946fc94bc8` | `source/clang/lib/FrontendTool/ExecuteCompilerInvocation.cpp` |

The authenticated source inventory contains no source-only record for this
shard. The linked module row establishes planning ownership context; it is not
an emitted-function or accepted-implementation denominator.

The planning registry now exposes an exact shard-owner lookup. It rejects
invalid and unknown shard IDs, returns only authenticated linked/generated
modules, and does not authorize implementation acceptance or turn module
ownership into an emitted-function count.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The linked unit
therefore remains unresolved and release-blocking under #1004.

Required work still must derive the current emitted population for this exact
owner, generate every required implementation through the qualified bounded ACP
workflow, and retain per-module source plus ACP/validation receipts.
Unresolved entities must remain explicit blockers. ABI, calls, globals, names,
and cross-shard ownership interfaces require the existing validation and
invalidation authorities. Placeholder returns, abort/no-op bodies, undeclared
shims, and reduced denominators cannot count as accepted implementations.

## Artifact provenance

The evidence is bound to these repository-controlled LLVM 22.1.6 artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de9f2e9e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The compact JSON hash of the planning module row is
`63abfdb1d5b7b0bd70003048905424b5acd2389a5a37849b268e53b5eb4504dd`. The
inventory's ordered unit-ID hash is
`bd9b3d6defde62f9d40cc41cf4b5fb4888208238364afe5c9426bd012225f285`, and the
compact linked source-record hash is
`60cc4ec1e99304646d9bd6d6b13159435ff82b4fd46bc48b1d61921fdd758f92`.

The planning inventory contains 2,150 source modules across 57 shards. That
repository-wide planning count is context only and grants no acceptance or
release authority.

Validation was intentionally skipped at the owner's direction for this bounded
checkpoint. The focused planning-inventory test remains the intended
verification target.

Refs #1004
