# `llvm-lib-sandboxir` acceptance evidence

This checkpoint records the authenticated source and compilation-unit boundary
for issue #1043. It is evidence for the bounded planning slice only; it does
not claim that an implementation has been generated, accepted, merged, or
qualified for production.

## Authenticated population

The checked planning inventory binds exactly 12 handwritten source modules to
this shard. The rich compilation-unit inventory and source inventory agree
that all 12 are linked units with the following ownership. Each module ID is
also its source-path-derived inventory unit ID.

| Module/unit ID | Source path |
| --- | --- |
| `cu-fbcfe96b746a728233f54f34ee587d70` | `source/llvm/lib/SandboxIR/BasicBlock.cpp` |
| `cu-4775b7db1c0a37f885cf944ebd153ee2` | `source/llvm/lib/SandboxIR/Constant.cpp` |
| `cu-e02519ebfeddbf299e8455558a8fbf18` | `source/llvm/lib/SandboxIR/Context.cpp` |
| `cu-0c9752c6b05f0b080d6d44a7e234b67a` | `source/llvm/lib/SandboxIR/Function.cpp` |
| `cu-09b654b24de08d248f82f20ec34f339f` | `source/llvm/lib/SandboxIR/Instruction.cpp` |
| `cu-cf55c7fb50aa9f1f822d9bae09937b09` | `source/llvm/lib/SandboxIR/PassManager.cpp` |
| `cu-9db39008bc9c0f6e0b87b1720445710b` | `source/llvm/lib/SandboxIR/Region.cpp` |
| `cu-ab2cadecb996658b7392006659f386c3` | `source/llvm/lib/SandboxIR/Tracker.cpp` |
| `cu-304b3d57ff8f55a4047f073546077700` | `source/llvm/lib/SandboxIR/Type.cpp` |
| `cu-933db1fa0535f9739b0488188d870e34` | `source/llvm/lib/SandboxIR/Use.cpp` |
| `cu-273f7b7c0cd8faf5c08088918ce799c7` | `source/llvm/lib/SandboxIR/User.cpp` |
| `cu-62cf726fe96ed0215f075c31276d0b00` | `source/llvm/lib/SandboxIR/Value.cpp` |

The source inventory also records three source-only files in this exact shard:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/SandboxIR/Argument.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/SandboxIR/Module.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/SandboxIR/Pass.cpp` | `not-selected-by-authenticated-build-graph` |

These records establish the current module and linked compilation-unit
population before dispatch. The 12-module planning count is source ownership
context; it is not an emitted-function or accepted-implementation
denominator. The three source-only rows remain explicit non-owning evidence.

## Acceptance state

No shard-specific generated source, authenticated emitted-function population,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. Therefore implementation
coverage remains unresolved and release-blocking under #1043. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the emitted function population from the
authenticated rich artifact for these exact linked units, run the qualified
isolated generation workflow with the existing bundled Ghidra/API and
authenticated oracle boundaries, and retain one source plus ACP/validation
receipt per required entity. Any unresolved entity must remain an explicit
blocker; changes to cross-shard interfaces require the existing invalidation
authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The linked compilation-unit population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a`; the
inventory index is
`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`, and the
source-inventory report is
`a1b552d01d412c48635e56b09d74d456957fc901fa7f811ababd7f64d8226c4c`.
