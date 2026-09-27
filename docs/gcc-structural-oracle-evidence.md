# GCC structural oracle evidence for #683

This record is a checked repository-fact slice for the open #683 acceptance
criterion. It records the available boundary oracle without promoting it to
authenticated production structural evidence.

## Available checked facts

| Fact | Repository evidence |
| --- | --- |
| Benchmark profile | `oracle/gcc/16.2.0`, GCC 16.2.0, oracle id `gcc-driver-16.2.0` |
| Rich artifact SHA-256 | `8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b` |
| Stripped artifact SHA-256 | `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |
| Artifact manifest SHA-256 | `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| Checked function oracle | `function-recovery-oracle.json`, 12,558,460 bytes, SHA-256 `b49b8a72a96580bd8727d9dc530753f40f78185a656f472ebe83a7a1f6fc9aae` |
| Boundary populations | 3,284 scoreable, 140 reviewed compiler-generated exclusions, 9,420 inline-only exclusions |
| Existing deterministic contract | `tests/oracle/test_function_recovery_oracle_generation.py::FunctionRecoveryOracleGenerationTest::test_checked_production_oracle_regenerates_byte_identically` regenerates and schema/semantically validates this function oracle |

These facts cover the existing function-boundary/name oracle only. They do not
constitute the full structural oracle or score required by #683.

## Unavailable production gates

The checked repository has no authenticated GCC production replay/model,
identity-map receipt, or checked oracle/score pair covering ABI interfaces,
calls, globals, and recoverable types. Consequently the following #683 gates
remain unresolved:

- byte-identical regeneration of the complete structural oracle and score;
- validation of that complete pair against its production schemas and complete
  denominators; and
- the generic leakage regression applied to that complete production pair.

The existing schema-v1 function score remains
`artifact-verified-model-unattested` with `productionVerified: false`, as
documented in `docs/gcc-function-recovery-scoring.md`. This record preserves
that unresolved state and does not create production authority from a caller
supplied model, bypass bundled Ghidra isolation, or introduce `GHIDRA_HOME` or
external `analyzeHeadless` execution.
