# Issue #928: `cc1` resume/fresh byte-equivalence evidence

**Status:** unverified evidence gap. This record does not claim a real hosted `cc1`
run or A10 qualification.

## Scope and source identity

This record is tied to the code and checked fixtures at source revision
`bf2501568f39ab52b23492dfc37839bb81895587` (the documentation-only commit that adds
this record does not change them). The current opt-in comparison path is:

- `src/test/kotlin/decompengine/oracle/gcc/GccBundledCliQualificationTest.kt`
  (`8a4991cff779a9ef16c403c88ec6b6fe1df16090fa3d4d1d21e59a33114312b7`)
- `src/test/kotlin/decompengine/oracle/gcc/GccInstalledCliInvocation.kt`
  (`10dc1125009ce8331b4812ee56a326f1c637ce310f4ef25c9bee09e1239a578`)
- `src/test/kotlin/decompengine/oracle/gcc/GccBundledCliEvidenceChecks.kt`
  (`4e07d00b09488f6cc9a303fbc2a230d420e58984aa799b36815488a98472c33a`)
- `scripts/ci-qualify-gcc-engine-cli.sh`
  (`87e491f3436c84a676b5e02a8e9437aa440b0c0a7f95d5a512b0b0ed64c365bc`)

The `cc1` profile fixtures are the checked files under `oracle/gcc/16.2.0/`:

- `compiler-engines.json`: `e0ca60b7e856e9330e45fd58e61828313e8dd824413ee0df7ef76ee5d2b47bdc`
- `cc1-build-record.json`: `f6b2711d4f82562195acebe7250d7dc62eb9425af4f736736e0ea69b65103e8e`
- `cc1-oracle-manifest.json`: `dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4`

The selected profile binds GCC `16.2.0`, planning exporter version 10 with exporter
digest `dc0debe2808c2744792f736d150d25aaefd6a46fd90910af7175a454686c6ab9`, and
Ghidra `12.1.3` archive digest
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`.

## What the current path checks

When explicitly enabled by `DECOMP_REQUIRE_GCC_ENGINE_CLI=true`, the `cc1` test
invokes the installed `bin/llm_bin_patch` CLI once for a fresh scratch mount and
once with `--resume-after-checkpoint 512` for a separate resume scratch mount. It
retains and checks the journal record set, linked record hashes, checkpoint prefix,
model and plan hashes, then compares `reports/program_model.json` and
`module_plan.json` with byte-wise `Files.mismatch` checks. The generated comparison
record itself sets `benchmarkAccepted=false` and `releaseEligible=false`.

No committed real-run output is present at this revision: there is no retained
`comparison.json`, journal, model, plan, launcher receipt, authenticated lifecycle
receipt, or measured resource record for a hosted `cc1` execution under
`docs/evidence/` or the checked fixtures. No test or real CLI invocation was run
for this documentation change, as requested.

## Explicitly unverified criteria

The following remain open for issue #928:

1. A real `cc1` process was forced to stop after a durable checkpoint, the exact
   stopped process and containment state were observed, and the same owned state
   was resumed.
2. The interrupted/resumed and independent fresh normal-CLI runs produced
   byte-identical final models and deterministic ownership plans.
3. Every leg retained authenticated identities, lifecycle and checkpoint lineage,
   counts, hashes, and measured A10 wall-clock, memory, PID, and aggregate resource
   evidence.
4. The retained records were produced by the current profile and fixtures above in
   a provisioned hosted environment, rather than only being accepted by the opt-in
   test and its caller-supplied inputs.

The existing validator and CLI test are reusable verification infrastructure. They
do not turn this record into hosted production evidence or close the issue's
acceptance criteria.
