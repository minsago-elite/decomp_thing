# GCC generated declarations: strict profile evidence

This is a narrow evidence record for #695 at repository revision
`bf2501568f39ab52b23492dfc37839bb81895587`. It records checked-in contracts
only; it does not claim that the GCC driver declarations have been recovered or
production-qualified.

## Checked facts

- The registered generated-C Make profile is `generated-c-make-v1`. It selects
  compiler driver `cc` with `-std=c11 -g -Wall -Wextra -Werror -Iinclude`.
- `GeneratedCDeclarations` maps the observed Ghidra spellings `undefined8`,
  `undefined4`, `undefined2`, `undefined1`, `undefined`, and `byte` to fixed
  width C types before rendering declarations. It does not assess ABI
  correctness.
- `GeneratedCModuleValidation` compiles each accepted module with the selected
  profile command and `-c <source> -o /dev/null`, sanitizes the build
  environment, binds the source hash before and after compilation, and retains
  the command, outcome, return code, and bounded diagnostic identity.
- The existing `SourceTreeTest` contract keeps undeclared decompiler types as
  compile failures and unresolved entities. The existing strict build fixture
  requires `-Werror` and emits a source-bound build contract.

The local contract status is `fixture-only` and `productionVerified: false`.
Known decompiler spellings can be normalized, while unsupported or unresolved
facts remain subject to the compiler gate and unresolved evidence.

## Production gap

The repository has no accepted complete GCC reconstructed source tree, current
declaration denominator, per-entity ABI evidence, or production clean-tree
declaration build. The host compiler and fixture tests do not authenticate the
compiler/runtime or the consumed headers. The generated-C production validation
provider remains fail-closed pending qualification of its provisioned compiler,
runtime, public-factory path, retained corpus, and terminal resource evidence.

Therefore #695 remains open and this record does not promote fixture results to
GCC production evidence. Production analysis remains isolated through the
application-bundled Ghidra Java APIs and authenticated oracle boundaries; this
slice introduces no `GHIDRA_HOME` or external `analyzeHeadless` dependency.
