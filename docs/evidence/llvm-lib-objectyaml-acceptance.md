# `llvm-lib-objectyaml` acceptance evidence

This checkpoint records the authenticated source and compilation-unit boundary
for issue #1037. It is evidence for the bounded planning slice only; it does
not claim that an implementation has been generated, accepted, merged, or
qualified for production.

## Authenticated population

The checked LLVM 22.1.6 planning inventory binds exactly five handwritten
source modules to this shard. The rich compilation-unit inventory and source
inventory agree that all five are linked units with the following ownership:

| Module/unit ID | Source path |
| --- | --- |
| `cu-f1e6b34b503580b7c36dbac75232a72a` | `source/llvm/lib/ObjectYAML/DWARFEmitter.cpp` |
| `cu-63d65558702ea382542cc3d3c2f39371` | `source/llvm/lib/ObjectYAML/DWARFYAML.cpp` |
| `cu-713b98671e1b17a2e63d9ef21c2aece3` | `source/llvm/lib/ObjectYAML/ELFEmitter.cpp` |
| `cu-75ad75e87ea10d04fb519f7258966d1c` | `source/llvm/lib/ObjectYAML/ELFYAML.cpp` |
| `cu-c72554b2f962cc42e86e00ccbf9d3e26` | `source/llvm/lib/ObjectYAML/YAML.cpp` |

The source inventory also records 23 source-only files in this exact shard.
They are explicit non-owning records with the authenticated build-graph reason:

| Source-only path | Reason |
| --- | --- |
| `source/llvm/lib/ObjectYAML/ArchiveEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/ArchiveYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/COFFEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/COFFYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/CodeViewYAMLDebugSections.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/CodeViewYAMLSymbols.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/CodeViewYAMLTypeHashing.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/CodeViewYAMLTypes.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/DXContainerEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/DXContainerYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/GOFFEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/GOFFYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/MachOEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/MachOYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/MinidumpEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/MinidumpYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/ObjectYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/OffloadEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/OffloadYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/WasmEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/WasmYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/XCOFFEmitter.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/XCOFFYAML.cpp` | `not-selected-by-authenticated-build-graph` |
| `source/llvm/lib/ObjectYAML/yaml2obj.cpp` | `not-selected-by-authenticated-build-graph` |

These records establish the current module and linked compilation-unit
population before dispatch. The five-module planning count is source ownership
context; it is not an emitted-function or accepted-implementation denominator.
The 23 source-only rows remain explicit non-owning evidence.

## Acceptance state

No shard-specific authenticated emitted-function population, generated source,
ACP invocation receipt, compiler or validation receipt, behavioral receipt, or
retained accepted checkpoint is present in this slice. The five linked units
therefore remain unresolved and release-blocking under #1037. A placeholder,
abort/no-op body, undeclared shim, or reduced denominator must not be recorded
as an accepted implementation.

The next bounded work item must derive the emitted function population from the
authenticated rich artifact for these exact linked units, run the qualified
isolated generation workflow through the existing bundled Ghidra/API and
authenticated oracle boundaries, and retain one source plus ACP/validation
receipt per required entity. Every unresolved entity must remain an explicit
blocker; cross-shard interface changes require the existing invalidation
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

Refs #1037
