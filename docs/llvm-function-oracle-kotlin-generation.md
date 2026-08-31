# Kotlin LLVM function-oracle generation

`LlvmFunctionOracleGenerator` is the Kotlin/JVM authority that composes the historical LLVM
function-recovery oracle v1 document from raw artifacts. The narrow
`generateLlvmFunctionRecoveryOracle` Gradle/CLI entry point now owns regeneration in the required
LLVM workflow; its output must compare byte-for-byte with the checked document.

## Authority boundary

The production entry point accepts exactly four `Path` values:

1. the raw LLVM artifact manifest;
2. the raw reviewed function-exclusion profile;
3. the artifact-root directory containing the rich and stripped twins; and
4. an absent output path beneath a dedicated owner-only (`0700`) directory.

The artifact manifest is reverified by `LlvmArtifactManifestVerifier`. Both artifact files remain
open through the bounded scan, the exclusion profile remains open through composition, and all of
them are checked again before publication. Manifest verification is repeated at that terminal
boundary. Parsed JSON, precomputed facts, selectors, limits, authority tokens, and ACP messages are
not accepted by the production entry point.

The CLI preserves that boundary and accepts exactly `--manifest`, `--exclusions`,
`--artifact-root`, and `--output`. The output parent must already exist with mode `0700`, and the
output itself must be absent:

```sh
install -d -m 0700 /tmp/llvm-function-oracle
./gradlew --no-daemon generateLlvmFunctionRecoveryOracle \
  --args="--manifest oracle/llvm/22.1.6/oracle-manifest.json --exclusions oracle/llvm/22.1.6/function-recovery-exclusions.json --artifact-root /absolute/release/root --output /tmp/llvm-function-oracle/function-recovery-oracle.json"
cmp /tmp/llvm-function-oracle/function-recovery-oracle.json \
  oracle/llvm/22.1.6/function-recovery-oracle.json
```

The Python generator and adapter remain only as visibly non-authoritative differential/unit
compatibility. Their output is not consumed by the required generation step and cannot enter a
new Kotlin-only release.

The historical Clang profile is closed implementation policy:

- symbol names are `main`, `clang_main`, or names beginning `_ZN5clang6driver`;
- compilation units contain `/clang/lib/Driver/` or end in
  `/clang/tools/driver/driver.cpp`;
- inline-only records are omitted; and
- `nearMissBytes` is exactly 16.

ACP is a first-class operator and observation surface, but remains read-only with respect to oracle
truth. It cannot supply, approve, validate, or score function facts.

## Shared scanner and v1 semantics

`BoundedDwarfFunctionFactScanner` shares the full-tree Kotlin DIE repository, reference-chain
resolution, indexed-address decoding, range-list decoding, ELF layout reader, and stable-file layer.
It preserves the historical v1 merge rules:

- emitted DWARF starts and defined `STT_FUNC` symbols merge only by RVA;
- linkage, MIPS-linkage, and ordinary DWARF names form separately evidenced aliases;
- stripped aliases may disappear but may not invent a name or RVA;
- evidence sorts by Unicode code point over `(kind, locator)` and aliases sort by Unicode code
  point;
- reviewed exclusions bind exact increasing RVAs to the verified rich artifact; and
- the JSON document uses the existing schema and canonical pretty-printed byte form.

The scanner retains the historical hard ceilings: 512 MiB per artifact, 20,000 records, 256 aliases
per record, 256 evidence atoms per alias, 2,000,000 ELF symbols, 2,000,000 DWARF subprograms,
5,000,000 scanned DIE records, a 16 MiB logical range section, 4,096 code points per name, and
16,384 code points per evidence locator. Canonical output is capped at 64 MiB and validated first by
the bundled `function-recovery-oracle` schema and then by
`StructuralRecoveryV1Inputs.loadFunctionOracle` from a private staged file.

## Publication and residual trust

The dedicated publisher prepares an unnamed inode, writes and synchronizes the complete canonical
bytes, changes it to `0400`, materializes a private temporary, and commits with a descriptor-relative
no-replace rename. The target and deterministic temporary must both be absent. The general atomic
state-file helper retains its independent 1 MiB ceiling; only function-oracle publication has the
64 MiB ceiling.

The implementation rejects symlinked parents, target or temporary collisions, lexical output/input
replacement, artifact/exclusion drift, and manifest reauthentication drift. Linux and Java cannot
prove the absence of a perfectly restored transient mutation by a cooperating same-UID process or
root between observations. The dedicated `0700` output directory and the input owners therefore
remain cooperating trust principals; this checkpoint does not claim same-UID exclusion.

The long parity test is opt-in:

```sh
LLVM_ORACLE_ARTIFACT_ROOT=/absolute/release/root \
  ./gradlew test --tests \
  'decompengine.oracle.provenance.LlvmFunctionOracleGenerationTest.real Kotlin authority reproduces the checked LLVM v1 bytes exactly'
```

It requires exact equality with the checked 4,674,632-byte document whose SHA-256 is
`a37d6eda0fb9b95fa884c8ce4eff358ab7bf424fa9b990e61cb4f465f3e0410c`.
