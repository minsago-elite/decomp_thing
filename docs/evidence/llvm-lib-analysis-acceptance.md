# `llvm-lib-analysis` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1018. It is evidence for bounded planning and dispatch only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventories bind `llvm-lib-analysis` to exactly 118 linked,
handwritten compilation units. The planning registry now exposes an exact
shard-owner lookup and rejects malformed or unknown shard IDs. The focused
registry test asserts all 118 source paths and their shard/unit identity before
dispatch; the planning count is not an emitted-function or accepted-
implementation denominator.

The source inventory also retains seven source-only paths excluded by the
authenticated build graph. They remain explicit non-owning evidence:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/Analysis/Analysis.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/DevelopmentModeInlineAdvisor.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/ModelUnderTrainingRunner.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/NoInferenceModelRunner.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/SyntheticCountsUtils.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/TFLiteUtils.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Analysis/Trace.cpp` | `not-selected-by-authenticated-build-graph` |

The exact compact-JSON commitments for the shard selection are retained here
to make later population changes detectable:

| Population | Count | SHA-256 |
| --- | ---: | --- |
| Rich inventory `unitIds` | 118 | `66cf0ffa2966d8eb1b71cdd86a5a5538db92db17df08b365705db31534a2d7ee` |
| Planning inventory linked records | 118 | `87e17aa388ea1c9a6041ae8cdc408c4d56bcfafe4712e708eccc27ef0e141e3b` |
| Source inventory linked records | 118 | `112aa5fc6f0d15ec6659de1e0e8e26c0111f57013324f8f4919d5da6c41ec4d6` |
| Source-only path list | 7 | `86f691cb5293103d03713985fa295f8a7781fd9d90b3d9284e0ac3321a4485d9` |

## Acceptance state and remaining gaps

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The 118 linked units
and seven source-only records therefore remain unresolved and release-blocking
under #1018. Placeholder returns, abort/no-op bodies, undeclared shims, and
reduced denominators cannot count as accepted implementations.

The remaining bounded work must bind the current emitted population for these
exact owners, generate every required implementation through the qualified
bounded ACP workflow, and retain per-module source plus ACP/validation
receipts. Every unresolved entity must remain an explicit blocker; cross-shard
interface changes require the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |
| `source-lock.json` | `179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306` |
| `oracle-manifest.json` | `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40` |

The profile binds to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`, inventory
index `95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and
source-inventory report
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.

Refs #1018
