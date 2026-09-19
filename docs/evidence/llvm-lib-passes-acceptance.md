# `llvm-lib-passes` acceptance evidence

This checkpoint records the authenticated source ownership boundary for issue
#1039. It is evidence for the bounded planning slice only; it does not claim
that an implementation has been generated, accepted, merged, or qualified for
production.

## Authenticated population

The LLVM 22.1.6 inventory and planning inventory bind exactly these four
handwritten compilation units to this shard:

| Module/unit ID | Source path |
| --- | --- |
| `cu-019261db5272a1386153318b02607572` | `source/llvm/lib/Passes/PassBuilder.cpp` |
| `cu-377d4f3f0c8bafc0cc891f34d5fc2e08` | `source/llvm/lib/Passes/PassBuilderPipelines.cpp` |
| `cu-c257ae5ede140dd30a7e652ba7cd3e99` | `source/llvm/lib/Passes/StandardInstrumentations.cpp` |
| `cu-f50933ac384ce952581b62f5f29d2d88` | `source/llvm/lib/Passes/OptimizationLevel.cpp` |

The source inventory also records two source-only files in this shard. They
are explicit non-owning records with the authenticated build-graph reason:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/Passes/CodeGenPassBuilder.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/Passes/PassBuilderBindings.cpp` | `not-selected-by-authenticated-build-graph` |

The checked planning artifact records 2,150 source modules across 57 shards,
including 2,149 handwritten and one generated module. Its SHA-256 is
`2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a`. These
planning counts establish module ownership and denominator context; they are
not an emitted-function or accepted-implementation denominator.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The four linked units
and two source-only records therefore remain unresolved and release-blocking
under #1039. A placeholder, abort/no-op body, undeclared shim, or reduced
denominator must not be recorded as an accepted implementation.

The next bounded work item must bind the current emitted population for these
exact owners, run the qualified isolated generation workflow through the
existing bundled Ghidra/API and authenticated oracle boundaries, and retain
one source plus ACP/validation receipt per required entity. Every unresolved
entity must remain an explicit blocker; cross-shard interface changes require
the existing invalidation authority.

## Artifact provenance

The evidence above was read from the repository-controlled LLVM 22.1.6 profile:

| Artifact | SHA-256 |
| --- | --- |
| `full-tree-scope.json` | `48d15d0db12c67944473feae016123195cf9e1da37c5849d9131ba31248c4b57` |
| `full-tree-inventory.json` | `6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306` |
| `full-tree-planning-inventory.json` | `2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a` |
| `full-tree-source-inventory.json` | `33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4` |

The linked compilation-unit population is bound to rich artifact
`c36ea7da092273ee53d6955557cd8eb7dcd38da92e1f577249968330a275981a` and
inventory index
`95b00830d3ad2fe95ca8635806e03040c01ca1c93fe69c800eeb14a17bf2830d`.

Refs #1039
