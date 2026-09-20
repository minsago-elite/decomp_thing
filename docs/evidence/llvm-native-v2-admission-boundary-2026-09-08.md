# LLVM native-v2 admission boundary evidence — 2026-09-08

This is a bounded source-and-fixture record for [#935](https://github.com/minsago-elite/decomp_thing/issues/935). It records the current checkpoint; it does not close the issue or qualify native-v2 production admission.

## Exact snapshot

The inspected checkout was at `bf2501568f39ab52b23492dfc37839bb81895587` before this record was added. Relevant source, schema, and fixture identities were:

```text
src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorNativeSandboxPolicyV2.kt                         bb80158cc248b5a92965bf9f0972b5f1e6a918e92c13edb54b872d809ea4e121
src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateExecutionAdmission.kt                    d4a005a3967974691e569684de1c46625d5e76b049f8f54119da1208cfd7b04b
src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorRuntimePreflight.kt                                7fa6be6d1bbe79ce39b7f49ed1fff5bfcfb28d80a3487243899ab53e2c570831
src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorNativeSandboxPolicyV2Test.kt                      ef9e27f8c8165ad1cfce67eaefb9d0d0f3bbb9fdda1e8d034e2c28e8d736dfa1
src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateExecutionAdmissionTest.kt                e906ec95b9f6594edfcf8e7e271fee6f736bf9a0fc690274dc6235c82a4951e1
src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorRuntimePreflightTest.kt                            9d3c81f599a0b732d080522e30cd3de9c45955f0e04e7a3f08d110ff4c0ddad3
oracle/llvm-behavior-native-sandbox-policy-v2.schema.json                                                  bdce127600546944a3545682c22983383a348aa5a453fa823292fd176bb6f079
oracle/llvm-behavior-candidate-execution-admission.schema.json                                              4322af2af7b02b4b57e7bf6453feb7d6377d98c707d2ac799bcedc22bc0daef7
oracle/llvm-behavior-runtime-preflight.schema.json                                                         4dc5d7dd5004c02634b405bd2e82c0742161b558daf5c14e3bb5feeb4151255e
src/main/c/decomp_llvm_behavior_helper.c                                                                   8465bd7761e3ecc2eefc42f194505e24d6adf3ed68a676a8370ee294f30cd713
```

The policy test fixture copies the configured helper and checksum and the repository helper source, then constructs a schema-v2 build record and policy in `LlvmBehaviorNativeSandboxPolicyV2Test` ([fixture](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorNativeSandboxPolicyV2Test.kt#L492-L598)). The candidate-admission fixture copies the checked `22.1.6` corpus, report, diagnostic matrix, and manifest; their current SHA-256 values are `acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b`, `e9595bfd941c406d2c8fff618986e60dc0b810f1c384848b3ba540020ca00a6f`, `9e3b3223e014de49e0df50892556ae4649f819d5571751378ed9bfd12d684b2d`, and `5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40`.

## What the checkpoint demonstrates

- The v2 policy verifier accepts exactly five raw paths and returns non-authoritative draft validation. Its focused fixtures reject closed-field changes to argv, environment, mounts, users, limits, and claims; helper, checksum, source, and build-record substitution; Python text; known v1 markers; noncanonical bytes; bounds; aliases; and symlinks ([tests](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorNativeSandboxPolicyV2Test.kt#L216-L435)). These checks cover the five policy artifacts as one draft input set and do not start a runtime.
- Candidate admission is a separate `kotlin-host-pre-start-binding-v1` surface. It binds the checked corpus/reference tuple, candidate bytes, candidate-derived command projections, sandbox and limit digests, and an immutable pre-START receipt. Its fixtures cover candidate substitution, corpus sandbox/limit and reference drift, alias/permission rejection, expected-output non-exposure, and hostile target/temporary publication collisions ([source](../../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateExecutionAdmission.kt#L64-L247), [tests](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateExecutionAdmissionTest.kt#L38-L262)).
- Runtime preflight is also a separate `kotlin-host-live-runtime-preflight-v1` surface. Its fixture explicitly declares `backend: oci-container-v1` and `resourcePolicyVersion: 1`; its non-authoritative tests cover historical query/digest comparison, declared runtime/image/security drift, malformed or failed responses, lowering limits, path aliases, and the four fixed query arguments ([source](../../src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorRuntimePreflight.kt#L152-L172), [fixture](../../src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorRuntimePreflightTest.kt#L342-L407)).

## Explicitly unverified for #935

- No current production admission method carries the v2 policy, helper, checksum, source, and build-record identities into candidate admission or live runtime preflight.
- No integrated v2 boundary currently proves rejection of every v1/v2 mixture, locally rewritten adjacent checksum, unpinned helper, or substituted policy. The v2 verifier's marker and artifact tests are component-level checks; the existing admission and runtime receipts remain v1 surfaces.
- No integrated native-v2 hostile fixture covers helper/client/corpus substitution together with argv, environment, mount, user, limit, canonicalization, expected-output, bounds, and crash-safe publication checks.
- No native-v2 runtime has been started or qualified here. The policy and operation-journal checkpoints remain draft/pre-START records; no fresh v2 reference observations or production release authority are evidenced.
- Validation was intentionally skipped for this documentation-only checkpoint at the request for no tests; this record claims no test result.
