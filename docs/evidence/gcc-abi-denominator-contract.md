# GCC ABI denominator contract

This evidence record is a small, repository-backed slice for issue #692 at
commit `bf2501568f39ab52b23492dfc37839bb81895587`. It defines the admission
boundary and evidence states for the GCC ABI denominator; it does not claim a
production ABI score or completion of #46, #692, #693, #694, or #695.

## Authenticated boundary input

The checked GCC 16.2.0 profile provides the rich/stripped pair and the
SysV AMD64 descriptor below. These identities are inputs to the denominator;
they do not by themselves provide recovered ABI facts.

| Input | Repository fact |
| --- | --- |
| Oracle manifest | `oracle/gcc/16.2.0/oracle-manifest.json`, SHA-256 `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| Rich artifact | SHA-256 `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b`, image base `0x400000` |
| Stripped artifact | SHA-256 `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4`, image base `0x400000` |
| Target ABI | `oracle/targets/sysv-amd64-v1.json`, SHA-256 `d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343` |
| Boundary/name oracle | `oracle/gcc/16.2.0/function-recovery-oracle.json`, SHA-256 `b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae` |

## Denominator admission

The existing boundary oracle is the only checked GCC structural population.
It admits scoreable physical function starts and retains excluded or alias
evidence as follows:

| Population | Count | ABI denominator treatment |
| --- | ---: | --- |
| Function records | 12,844 | Retain as boundary/name evidence |
| Scoreable physical starts | 3,284 | Candidate entities for each of the five ABI interface dimensions |
| Reviewed compiler-generated exclusions | 140 | Excluded from the scoreable entity denominator; retain the exclusion reason |
| Inline-only exclusions | 9,420 | Excluded from the scoreable entity denominator; retain the exclusion reason |
| Function aliases | 24,163 | Retain as per-alias identity/name evidence; do not inflate physical-start counts |

The ABI dimensions are the closed generic dimensions already defined by the
structural scorer: `function.prototype`,
`function.calling-convention`, `function.variadic`,
`function.parameter-abi-class`, and `function.return-abi-class`.

For each admitted entity and dimension, an oracle fact is either:

- `observable`, with a non-null normalized value and evidence locator; or
- `oracle-unobservable`, with a null value and evidence locator.

Both states remain in `oracleDenominator`. `oracle-unobservable` is counted
separately and receives no credit. A missing or ambiguous recovered claim is
`recovered-unknown`, remains in `recoveredDenominator`, and receives no
credit. Excluded entities remain visible in the boundary evidence but are not
silently converted into ABI facts.

The checked GCC profile contains no production fact records for these five
dimensions. Therefore the production ABI fact counts and score denominator
are `unresolved`, rather than zero or inferred from names, bytes, or the
3,284 boundary count.

## Unresolved facts and unavailable gates

The rich artifact exposes reviewed symbol aliases used by the boundary/name
oracle, but the repository has no authenticated GCC production extraction of
source-level prototypes, calling conventions, variadic state, parameter or
return ABI classes, global/type facts, or their ambiguous/unobservable
classifications. Those facts remain unresolved.

Production qualification is unavailable: the production structural replay
registry is intentionally empty at
`src/main/kotlin/decompengine/oracle/structural/StructuralReplayAdapterRegistry.kt`,
and the generic scorer refuses production-scoped fixture evidence. No checked
GCC production structural oracle, recovered model, identity-map replay, score,
or host-owned replay receipt binds the exporter, bundled-Ghidra loader and
target, image base, input binary, isolated output, model, and mapping.

This record therefore has `productionVerified: false` and
`adapterReplayVerified: false`. Any future production record must preserve
the authenticated artifact and target bindings, run through the isolated
bundled Ghidra Java worker, and keep oracle evidence separate from candidate
or fixture data. It must not require `GHIDRA_HOME` or an external
`analyzeHeadless` installation.

Validation for this documentation-only slice is limited to the repository
hash/count reads recorded above and `git diff --check`; no production replay
or full GCC analysis was run.

Refs #692
