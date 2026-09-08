# GCC driver strict failure attribution: bounded evidence for #700

This record captures one existing repository contract at revision
`bf2501568f39ab52b23492dfc37839bb81895587` on 2026-09-08. It is fixture
evidence only; production qualification remains `unresolved`.

## Observed contract

`ProjectBuildConfiguration` requires `-Werror` and rejects `-w` and
`-Wno-error`. The generated-C build invokes the declared parallel command,
groups compiler output by source or object owner, writes
`reports/build/modules/*.log`, and records `failedOwners` in
`reports/build_contract.json`. A failed command retains its owner IDs in the
raised `BuildException`.

The focused `StrictProjectBuildTest` proves both failure classes with the
same owner contract:

| Fixture | Retained owner evidence |
| --- | --- |
| `warning failure is archived against the module that owns the source` | The module ID appears in the failure, its log is `status=failed` and contains `unused variable`, and `failedOwners` contains that exact ID. |
| `link failure is attributed to the module whose object references the missing symbol` | The module ID appears in the failure and its per-module log retains `undefined reference` with `status=failed`. |

These checks preserve strict diagnostics and owner attribution. They do not
replace implementations with generic stubs or turn an unresolved entity into
an accepted one.

## Production gap

Issue #699 is still open and is the dependency for this issue. The repository
contains the locked GCC 16.2.0 oracle inputs and reference binaries under
`oracle/gcc/16.2.0/`, but it does not contain an accepted complete reconstructed
driver revision with its source manifest, unresolved inventory, generation
receipts, and production build contract. No production-sized failing revision
was available for this record, so no production failure denominator, output
identity, or complete diagnostic inventory is claimed.

The fixture contract therefore remains local evidence and does not satisfy
#700's production acceptance criterion. The next admission requires the exact
accepted source revision from #699/#47, a fresh isolated extraction, the
strict command, and retained diagnostics for every owner, including explicit
unresolved states.

No ACP reconstruction agent, production compiler or linker, Ghidra analysis,
or oracle execution was run for this record. Production analysis remains
bound to the application-bundled Ghidra Java APIs; this evidence introduces no
`GHIDRA_HOME` or external `analyzeHeadless` dependency. The locked oracle
remains a provenance and reference boundary, not reconstructed-source or
behavior-equivalence evidence.

References: [`StrictProjectBuildTest`](../../src/test/kotlin/decompengine/project/StrictProjectBuildTest.kt),
[`GeneratedCProjectBuilder`](../../src/main/kotlin/decompengine/project/GeneratedCProjectBuilder.kt),
[`GCC oracle artifact verification`](../gcc-oracle-artifact-verification.md).

Refs #700
