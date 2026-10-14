# Independent CI wrapper integration correction review

Verdict: **ITERATE** for the exact held generation. The retained focused execution evidence is sound, but the new Gradle scratch property is not bound to the repository or the wrapper's admitted scratch. A command-line property override can direct Test temporary/JNA writes outside the repository before selective child checks. Correct this binding and add a refusal control before source CLEAR_SCOPED.

Reviewer: GPT-6.1 Sol; independent of implementation, no descendants. Root alone owns source/Git/remote/CI custody. Only this report was written. Source/evidence/hash and existing-path metadata inspection only; no Gradle/JVM/native/target/helper, broad test, credential/auth/model, acquisition, Git, remote or Actions execution was performed. No files were created outside the repository or in another worker's owned source.

## Exact held source and evidence

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

| Artifact | SHA256 |
| --- | --- |
| `build/ci-wrapper-integration-correction/source-freeze.json` | `869962a9b3ea8e06ac715c3c9f3b0bd07559181ba4e530f6a46b9a6cdc423b9f` |
| Adjacent `handoff.md` | `0fbf5b3f083057aa530c7be8025b98fc42279f521e3c1590460d77a20f2144bb` |
| Adjacent `verification.json` | `d0e8c58c1d3c56535e511ef6d8f87b27b7971bf50b66b83bf800694ac7117eed` |
| Adjacent `diagnosed-source-delta.diff` | `c6481b7bfe174bfd4adb37ae603a3633b53060957a2757461570e726c7936b36` |
| Adjacent `command.log` | `8ea6fb2a4ae1703e56170178b0891e9b1e5313614e2f942aff672f01d914aabd` |
| Adjacent `unit-controls.log` | `8bc4516a06aa6eedf8268120e7c68064a4a5fb809721981ead70947f018c946e` |

All10owned source hashes match current files and their10source-snapshot copies. All10frozen evidence pins match. Verification's eight compiler-JAR records,30mini-project file records,two helper class records and nine actual-owned-state records match actual bytes. Source hashes in verification agree with source freeze. The helper's compiled source copy equals the current Kotlin helper; the actual miniature Gradle project contains the exact production Test selector substring. Artifact-only upload additions after execution are explicitly disclosed and do not change the tested selector/helper behavior.

## Blocking finding — scratch property is not an admitted path binding

`build.gradle.kts:196–203` reads `ciAcpFixtureJvmScratch` directly from Gradle properties. It checks absolute/canonical path, encoded socket-length budget, directory type, owner equality with provision UID and absence of group/world write permission. It does **not** require the path to equal the canonical repository root, be repository-contained, equal the wrapper's admitted path, or match a verified scratch.json path/device/inode.

The property is supplied through `ORG_GRADLE_PROJECT_ciAcpFixtureJvmScratch`, but a command-line `-PciAcpFixtureJvmScratch=...` can override it. A short existing same-UID0755directory outside the repository passes every added check. The selector then puts that path in `-Djava.io.tmpdir` and `-Djna.tmpdir` before launching the Test JVM. Ordinary Test temp/JNA work can therefore occur outside the repository even though the wrapper itself admitted the correct repository scratch.

Read-only counterexample: the existing `/home/june` directory is canonical, UID1000matching the provision receipt,0755, and yields73UTF8bytes including the worst63byte socket suffix. It is outside `/home/june/decomp_thing`, but satisfies the exact added predicate. This was checked with metadata only, without launching Java or writing to that directory.

`OwnedJdkFixtureSession.java:59–89` binds the actual kernel executable, credentials and matching selection/receipt, but does not validate tmp/JNA scratch. `scripts/ci-owned-jdk.py:377` only rechecks its original repository's scratch identity; it cannot detect the overridden Test property. `OwnedJvmChild.kt:15` may later reject scratch/TMPDIR disagreement for the five selected children, but that happens after the Test JVM is running and does not cover ordinary tests or earlier JNA/temp work. Valid actual-worker executable proof does not establish scratch provenance.

Required correction: bind the Test scratch to the exact canonical repository root admitted by this wrapper (or an equivalently authenticated repository-contained scratch receipt), and refuse substituted/overridden paths before Test launch/work. Validate the actual Test JVM uses the admitted path where needed; keep the byte budget and fixed child containment. Add a negative property-substitution control, including an existing canonical owned short outside directory, and distinguish it from the current negative user.home child-helper test. Do not solve this by creating an external short directory/symlink alias or dropping scratch checks.

This is a validation/containment-contract defect under an alternate configuration, not a claim that the retained positive fixture wrote outside the repository. Its scratch proof actually names the correct enclosing repository and remains valid.

## Supported narrow corrections

### Socket path calculation and failure ordering

The audited worst default-temp bind suffix is63ASCIIbytes: the longest relevant fixture prefix,20decimal random digits and `/runtime/docker.sock`. The hosted canonical root contributes43bytes, giving106<=107; adding a one-character child contributes two more and exceeds the limit. Encoded UTF8bytes are used for the repository component, so Unicode cannot exploit character counts. The audit covers the five default-temp fixture groups and explicitly excludes NativeMeasurementFixture's separate build/nrm parent; no universal native-socket bound is claimed. The longer rename-only Docker filename is not falsely counted as a bind.

`scripts/ci-owned-jdk.py:348–350` calls socket_scratch before JDK provisioning. It uses secure_directory's canonical/no-follow/owner/mode checks, captures identity, writes scratch.json under owned state and rechecks original identity after work. The actual nested local worktree is too long; the retained miniature run transparently uses its enclosing canonical repository root, with owned state under that repository/build. It does not hide the worktree length through a symlink or external fallback. These properties support the ordinary wrapper route; they do not close the independent Gradle override finding.

### Selective exact-output children

The diff modifies exactly five child launch sites across four diagnosed test classes, adding the helper before start. Original commands/arguments, merged-stream handling, exact READY/READY: comparisons and test/production assertions remain unchanged. The helper is a no-op without the admitted CI receipt property. In CI it verifies actual java.home launcher, canonical owned fixed scratch/home/preferences paths and adds explicit fixed PerfData/attach/tmp/JNA/home/preferences JVM options. It does not parse arbitrary shell option text.

Only these selected children remove JAVA_TOOL_OPTIONS/JDK_JAVA_OPTIONS/_JAVA_OPTIONS, after fixed options are added. Blanket JAVA_TOOL_OPTIONS remains in the wrapper for other descendants, so removing the banner at these sites does not discard containment for unrelated direct JVM children. No stderr stripping or relaxed prefix parser was added. Current call sites supply no later contradictory JVM properties; the known commands use the cloned Java launcher and original classpath/probe arguments. The helper's correct path checks are useful but do not turn a Gradle project property into a prelaunch scratch binding.

### Populated offline Gradle context

The bundled workflow now runs the unchanged selected Ghidra Test command followed by `./gradlew --no-daemon --offline verifyGhidraDistributionArchives` inside one owned-wrapper `bash -euc` command. First-command failure stops the shell. No second fresh wrapper, implicit cache transfer or external Ghidra installation is introduced. Both commands inherit the same JDK, GRADLE_USER_HOME, HOME/cache/preferences/scratch. Existing Ghidra selectors and archive verification command remain intact; workflow artifact globs add scratch.json receipt retention. ACP workflow changes are artifact-only. Actual archive verification was not executed in this focused check.

## Actual retained verification

The miniature actual Gradle9.6.1/JUnit run has two tests,0failures/errors/skips, not reflection-only invocation. The XML binds the two controlled checks, and final.json records one admitted actual Test JVM, exit0 and unchanged source JDK. Actual kernel executable/selection/credential admission is exercised via the production session listener. The helper bytecode and exact production selector are independently tied to the frozen source, rather than inferred from a similar handwritten setup.

One test witnesses the old inherited JAVA_TOOL_OPTIONS banner, then verifies repaired whole output is exactly READY newline CONTAINED newline. The child checks all five properties and PerfData/attach options. Its deliberately incorrect user.home property refuses before child start. The other test actually binds the longest-prefix default-temp Unix socket within the admitted root. These prove the positive ordinary route and child-property refusal, not the missing Test-scratch substitution control.

The second offline miniature Gradle command requires offline mode, reads a marker created by the first command from the same GRADLE_USER_HOME and compares java.home; `SAME_POPULATED_OFFLINE_CONTEXT_VERIFIED` and the retained marker prove continuity. This is a small cache-context test, not real Ghidra archive qualification or the full production suite. The14pure wrapper controls pass and cover socket byte limits, canonical ownership, symlink/writable refusal and prior JDK clone/source/descriptor/receipt rules. They do not test a Gradle scratch -P override.

Python/workflow/shell syntax and exact call-site checks are retained. The initial harness ancestor-path assertion failure is preserved as pre-JVM failure, not counted as qualification. The four large changed test classes were not run as a broad suite. TLS/native-DNS/FD/prelaunch fixes owned by other workers are neither modified nor qualified here. No hosted result, full CI, native isolation, real archive, universal RSS/performance or production authority follows from these narrow passes.

## Disposition and owned source pins

Keep this generation ITERATE until the scratch-property binding and negative prelaunch control are corrected under a fresh held source/evidence pin. Retain the valid positive evidence and original failure history. Root owns the next source assignment, checkpoint and hosted integration; this report grants no Git/remote/native execution authorization.

| Path | SHA256 |
| --- | --- |
| `.github/workflows/acp-contract.yml` | `376ff83d072668ca1da3dfb3596a71e8de23c5b4b5d7e126be97e0967a46b0e2` |
| `.github/workflows/ci.yml` | `5692268af72780228f6867e98e0e5c7adacab292fe0779393d06ec85af52070c` |
| `build.gradle.kts` | `cf9a87cba85f875e31490a09d33e0dce4d36dc873f57bdf577b9ab9a6a7c371a` |
| `scripts/ci-jdk/test_owned_jdk.py` | `fc409f1dab3cd15dfcca5a71c1d7cafb7dcb3ba13f016b7a9187f9bffc0b1143` |
| `scripts/ci-owned-jdk.py` | `5863588ca820e28fff6febaf6c52140dd828be4e6118774ecf33a8a97d9a33af` |
| `src/test/kotlin/decompengine/ci/OwnedJvmChild.kt` | `6cf1069b80131c34d15259e6107e160c0b8b9523ea88407d533c374585bcb399` |
| `src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorNativeSandboxPolicyV2OperationJournalTest.kt` | `10a57ec7b58e0d0426c6d20f8eba2d65044d7f674a628ebc0d34163470da0f36` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthorityTest.kt` | `af74c66e183bffe3767ba156a75611a86878045df973f2b049271529729d58ca` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationJournalTest.kt` | `5b1632dbb44f5861438f45cf52c77e9e031e5bdfd0040eeeea623403ae5fa9c1` |
| `src/test/kotlin/decompengine/repair/ModuleRevisionGraphTest.kt` | `a0ac6c7a15a22102ce5fae427a2edd5ef254a7b9d4dd1070d076546b5970a741` |
