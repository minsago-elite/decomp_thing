# `clang-tools-driver` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1016. It is bounded planning and dispatch evidence; it does not claim that an
implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 rich inventory, planning inventory, and source inventory agree
that this shard owns exactly these four linked handwritten compilation units:

| Module/unit ID | Source path |
| --- | --- |
| `cu-45375e567f8128f3c880fa12a28aaf1f` | `source/clang/tools/driver/cc1_main.cpp` |
| `cu-92f0c8b260c7ade50ec6ad30f43cd0b4` | `source/clang/tools/driver/cc1as_main.cpp` |
| `cu-230d152fe3555da86c8713ce34ebdb90` | `source/clang/tools/driver/cc1gen_reproducer_main.cpp` |
| `cu-ec5e5b1e57b7cd770b8252c9d2545a90` | `source/clang/tools/driver/driver.cpp` |

The source inventory contains no source-only record for this shard. The
planning registry now exposes an exact `clang-tools-driver` owner lookup and
rejects invalid or unknown shard IDs. These four rows establish source-module
ownership before dispatch; they are not an emitted-function or
accepted-implementation denominator.

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The four linked units
therefore remain unresolved and release-blocking under #1016.

The remaining bounded work must bind the current emitted population, generate
every required implementation through the qualified bounded ACP workflow, and
retain exact per-module source plus ACP/validation receipts. Unresolved
entities must remain explicit blockers; cross-shard interface changes require
the existing invalidation authority. Placeholder returns, abort/no-op bodies,
undeclared shims, and reduced denominators cannot count as accepted
implementations.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |
| `build-record.json` | `415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The profile binds the linked units to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1016
