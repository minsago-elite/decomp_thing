# LLVM candidate cross-binding evidence — 2026-09-08

This is a bounded source-and-fixture record for [#940](https://github.com/minsago-elite/decomp_thing/issues/940). It records the current structural checkpoint; it does not close the issue or qualify production admission.

## Exact snapshot

The inspected checkout was at `bf2501568f39ab52b23492dfc37839bb81895587` before this record was added. The relevant source and fixture files had these SHA-256 identities:

```text
src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2Verifier.kt  dc70a121acafbb105541b626382da0e1b8b6eb27c7accabc68a0fc743202233c
src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2Verifier.kt           c3384b7f47ba434c32c171460e8f63bc53509f574833fe8a161d934c98a2ac79
src/main/kotlin/decompengine/oracle/core/DescriptorBoundAtomicStateFile.kt                         651ac46e7f149e39885d3c4cf2f04849211c3e3a869c145018424a703aeb2946
src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2VerifierTest.kt 1f360f020dc05c7ff3cfdc376bbfc5c5854dbfc5a18d0c1e864760854bd2cbe3
src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2VerifierTest.kt        a4c04a81904a4aba0ecf80975b94de7e67a33bfb97caa04dc0c16e80bd7bfb7a
src/test/kotlin/decompengine/oracle/core/DescriptorBoundAtomicStateFileTest.kt                     81c9ee07e7cd96a7bf797dbdc988f27b53d96be50804bba8f5e08d24d431210a
```

## What the current checkpoint covers

- `LlvmBehaviorCandidateFourWayBindingV2Verifier` accepts exactly four raw paths, pins and snapshots their parents/files, rechecks source identity around both subordinate verifiers, and derives one defensive structural identity ([source](../../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2Verifier.kt#L100-L161)). The fixtures cover successful identity derivation, archive/lineage/receipt/executable cross-pairing, ACP association drift, bounded/noncanonical input, aliases, terminal source replacement, and post-pin file/parent replacement ([tests](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateFourWayBindingV2VerifierTest.kt#L69-L307)).
- `LlvmBehaviorHostedCleanBuildV2Verifier` cross-checks the canonical receipt with the exact executable and keeps execution, runtime closure, workflow, admitted-artifact, and release claims false ([source](../../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2Verifier.kt#L31-L146)). Its synthetic receipt/system-ELF fixtures cover build/runtime projection drift, executable drift, residue and mode rejection, ELF entry-point validation, parent replacement, and noncanonical/schema substitution ([tests](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2VerifierTest.kt#L24-L247)).
- `DescriptorBoundAtomicStateFile` copies requested bytes, uses a deterministic temporary inode, synchronizes, publishes with no-replace rename, and rejects conflicting or unknown residue ([source](../../src/main/kotlin/decompengine/oracle/core/DescriptorBoundAtomicStateFile.kt#L61-L196)). Its fixtures cover read-only/idempotent publication, different-byte replacement rejection, mutable-array isolation, and every modeled crash point with retry recovery ([tests](../../src/test/kotlin/decompengine/oracle/core/DescriptorBoundAtomicStateFileTest.kt#L19-L334)). The hosted worker publishes the executable before the receipt, with the receipt as the pair marker ([source](../../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2.kt#L2068-L2089)).

The fixtures create temporary synthetic archives/receipts and use `/bin/true`, `/bin/false`, or the host system ELF. They are not a retained candidate archive, authenticated hosted run, workflow attestation, or production artifact.

## Explicitly unverified

- The #940 hostile-test acceptance criterion is still open. The focused Gradle command was intentionally skipped after it was interrupted during `:compileKotlin`; no test pass is claimed in this record.
- No duplicate-field fixture was identified in the three exact test classes above. Duplicate-field rejection remains unverified here.
- Synthetic receipt drift does not authenticate a real compiler, linker, runtime, image, workflow, Sigstore bundle, or full-tree clean build. The current code deliberately keeps hosted execution, admitted-artifact, PREPARED/START, scoring, certification, and release eligibility false.
- No production qualification, authenticated artifact ingress, or immutable final admission record has been demonstrated. Those gaps remain with the dependent hosted-build/admission work.
