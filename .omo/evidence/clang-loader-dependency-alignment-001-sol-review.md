# Clang loader dependency alignment001 — source review

Verdict: **CLEAR_SCOPED** for the fixed dedicated Kotlin stdlib alignment. No source blocker found; dependency resolution and loader compilation remain unexecuted/unqualified.

GPT-6.1 Sol; source/hash and retained log inspection only. No Gradle/JVM/compiler/tests/native/network/auth/Git/remote operations. Only this report written. Root retains separate commit and composed-push custody.

## Pins

Worktree `.claude/worktrees/wf_ce026d1b-c24-59`:

- `build/clang-loader-dependency-alignment-001/manifest.json`: `5abaad6baa8df308e3804fb89932fdef6260fbf0347339d50813025933947632`.
- Init script: `cd71f2940b69aa8c377f83773411abbfeea0dcef26d7b34c9cc42936009a72e7`.
- Before script: `d992de308f7bad9c1e24e2225b5b7bcf8dad5de5369bad42ecd3f7b2c4974fb3`.
- Project build.gradle.kts: `608b7dd6a6c685c22c3ab3539823a13b5655a21473fce3ba0021081f91e5ce2b`.
- Root retained loader job log: `f864e2b21794ed63c88993ca0b81fb61d7561a7b045a51ee2ee3bc256ff7d2e8`.

All manifest source/evidence/input hashes match. Independently removed only the added comment/force block and restored the exact before-script bytes.

## Assessment

The retained Actions log303–308 fails capture-input resolution, before loader compilation: dedicated clang1813LoaderRuntimeClasspath encounters kotlin-stdlib2.4.0/2.2.0 conflict. Project plugin is explicitly Kotlin2.4.0 at build.gradle.kts21. Merely repeating a direct dependency would retain the same fail-on-conflict problem.

The new resolutionStrategy.force selects exactly kotlin-stdlib, stdlib-common, stdlib-jdk7 and stdlib-jdk8 at fixed2.4.0 on the dedicated loader runtime configuration. This is an explicit version-selection rule, not dynamic highest/latest selection or four additional dependency declarations. An otherwise absent module is not requested solely by force. Other conflicts still fail: the existing failOnVersionConflict call remains immediately afterward. No main configuration, plugin, serialization version or other module rule changes.

The full selected runtime JAR set still flows through the existing capture helper, followed by compile/runtime classpaths restricted to captured inputs and manifest verification before/after compilation. No ambient main/runtime classpath fallback or new executable path appears. Existing smoke execution still refuses unavailable authenticated immutable-host authority; compile-only evidence stays unqualified.

Public Gradle resolutionStrategy.force is the appropriate API for a deliberate fixed transitive override; the author's handoff cites official current documentation while explicitly disclosing that it is not exact Gradle9.6.1 runtime proof. This review makes no network lookup or resolution-success claim. Static insertion checks do not establish artifact availability, ABI compatibility, successful resolution or compilation. Those remain root-owned Actions gates; no loader/toolchain/production host qualification or issue closure follows.
