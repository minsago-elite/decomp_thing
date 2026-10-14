# Clang loader closure correction001 — independent exact-source review

## Terminal: ITERATE — Gradle compile route calls removed Project.exec API

Reviewed source only. No imports/tests/JVM/compiler/native/qualification, network/acquisition/auth/model or Git/remote operations. Bounded pure Python ZIP/classfile decoding below only inspected bytes; no class executed. Only this report written. Root retains release/thread/Git authority. Prior package002 and lifetime reviews untouched.

Manifest build/clang-loader-closure-correction-001/manifest.json SHA079436c9a7aa4dcf890703465d8406521c8370135a5a9c579be258afa93c6d34: all six current source hashes/sizes, all17 retained evidence hashes/sizes and12 dependency hashes matched at inspection. Source pins:

- .github/workflows/generic-template-toolchain.yml: `27d5e2c0837c3d6952a3adbdf1e70f6ac704a23b9196cdfd37213b6cbaf8d906`.
- oracle/clang/18.1.3/build-record.schema.json: `05eaee655c9e3fbf00f692bdbd57750f5a825bc1e178c3db4dab2e05ae58007e`.
- oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle: `c1b4bb2b80a63be6d4f449388bc18fe95298440a4f0ee3fe94b381a0767ffa41`.
- oracle/clang/18.1.3/test_provisioning.py: `f9557da18e4068b54b74e636059764426664d56f55c05692fc725834ec09e819`.
- scripts/oracle/clang_18_1_3_loader_snapshot.py: `072f38c0755b1c2b33807039c09a949a67fd8436ddf901db4e54ae3deefbcf76`.
- scripts/oracle/provision_clang_18_1_3.py: `4c54d0b92c906bc50063204e4426f490093fe31638da6524d8c65c7fa12e9eb9`.

## Blocking finding R1

oracle/clang/18.1.3/clang1813-loader-smoke.init.gradle:27 and44 invokes `project.exec` for verification and capture. The checked-in wrapper selects Gradle9.6.1. Project.exec was removed from that public API; this script's dynamic calls therefore cannot supply the new mandatory compile route. Capture is needed before either compiler task, so this is a functional blocker to the advertised acquisition-independent compilation check, not merely a missing native qualification receipt.

Independent local primary API byte check, without JVM/tools: read retained distribution `/home/june/decomp_thing/build/gradle-user-home/wrapper/dists/gradle-9.6.1-bin/4ticwg1pgcbps2hj28r8so764/gradle-9.6.1/lib/gradle-core-api-9.6.1.jar`, SHA5291bad2382019eced03c7c519322e976b651b568c3a9ed6d7ccd02a2d75e6a1. Its org/gradle/api/Project.class SHA b21a4b355e01d933f51aa91ae3fe63b7ad6b28a3216841ea702c8cf69eb8e107 has119 declared methods and no exec/javaexec method. This matches the wrapper-selected API, rather than guessing from a prior Gradle version. No Gradle process was run. The prior project.javaexec replacement correctly avoids ambient smoke execution but introduces the same API-era problem for Python execution.

Use supported Gradle execution services (e.g. injected ExecOperations in a narrowly scoped task/service, or configured Exec tasks) while preserving the exact prepare/verify arguments and externally held manifest digest, execution ordering, bounded snapshot policy and absence of target/native execution. Add source/API compatibility coverage proportionate to this failure; actual Actions compile is still required. A test that merely asserts strings in the init script cannot establish that its Gradle methods exist.

## Finding adjudication and source fidelity

- **sKZJY authenticated loader source snapshot:** partial source correction. prepare captures exactly the Java harness and three Kotlin source paths, checks recipe-selected byte hashes before output, and compiler source roots point at the snapshot. verify checks externally retained manifest digest, exact source/JAR inventory and byte hashes before/after compiler tasks. This fixes the mutable-source architecture in the proposed compile route, subject to R1 and actual Gradle task/API validation. It is compile-only-unqualified, not independently approved immutable-host/JDK/compiler execution or full authenticated loader replay.
- **sL7Vn transitive helper/classpath closure:** exact imported Kotlin helper sources OracleArtifacts/OracleJson (including StrictJsonLimits) are now recipe-bound and packaged. Separate source set avoids main classes/resources/runtimeClasspath. Its declared dependency configuration resolves transitive JAR files and captures the entire selected set; compiler compileClasspath uses only captured JAR paths. This closes the declared compile dependency byte inventory, not the actual Kotlin compiler/plugin/JDK execution closure or trust in ambient Maven-selected binaries. No approved dependency authority is invented. Full loader runtime-classpath qualification remains unproved, and R1 prevents treating the route as operationally verified.
- **sMqZ- transport-only and sN0uz journal-only triggers:** corrected in both push and pull_request filters; helper/snapshot/build inputs are also listed. Source inspection suffices for these filter additions, not a new Actions run.
- **sN0u8 compile while acquisition paused:** an unconditional loader-compilation job is present and has no acquisition gate, but its new compile task hits R1. Therefore the required working compile gate remains OPEN until fixed and executed in Actions.
- **new sVQ0a proc-FD root relativization:** narrow source fix is correct. driver_record3327 and runtime target3358 relativize physical paths against rootfs.resolve(strict=True); all actual root consumers retain descriptor routing. The retained inert FD-root test covers driver and resource positive paths. Existing lifetime source guarantees are not widened into descendant snapshot or privileged execution claims.
- **legacy fixtures:** archive-keyring ordering fixture explicitly supplies retention/index dependencies and retains ordering assertions; overlap fixture creates package-payloads so its original overlap check is reached. These are test-setup corrections, not relaxed production authentication. Existing effectful controls remain in source and Actions discovery.

The smoke task still exists but deliberately throws an unavailable authenticated-execution error after compile. It does not fabricate successful loader output, authorize ambient javaexec, or silently skip qualification. Retiring the unsafe execution route is honest partial progress; it is **not completion** of the required authenticated A-loader smoke feature. Keep that requirement open rather than resolve it from this checkpoint.

## Retained evidence denominator

Final focused ten pure controls passed with zero forbidden attempts/skips; these exercise snapshot primitives, source mutations, dependency/manifest rewrites, extra JARs/links, bounds, recipe coverage, direct FD-root normalization and fixture changes. No compiler/Gradle API task was run. The retained broad245 diagnostic contains31 denied subprocess attempts in22 existing effectful methods and is not a passing full suite. The local pure runner's250-method discovery initially had three journal guard refusals in two methods; only those two were rerun under the root-authorized crash-point allowlist and passed. Those actual inert child/socket controls belong to author evidence, not fresh reviewer execution; historical refusals remain preserved. No feature/test deletion is inferred from the local exclusion list, which is not used by the workflow's ordinary discovery.

**Required next step:** narrow R1 source correction and exact freeze/review; then root-owned Actions compilation and existing full offline discovery, followed by separately authorized host/JDK/classpath approval and authenticated smoke/native/provenance qualification. No actual supported-host path or review thread is fully qualified by these compile-only/pure results.


---

# Correction002 additive independent rereview

## Terminal: CLEAR_SCOPED — R1 removed-API correction

R1 is resolved in the exact corrected source. No other blocking source defect found in this narrow delta. This is not actual Groovy compilation, Gradle task realization, Kotlin/Java compilation, immutable execution approval, authenticated loader smoke or native/production qualification. The original872052 ITERATE report remains the byte-exact prefix and all original evidence remains historical.

Corrected manifest build/clang-loader-closure-correction-002/manifest.json SHA5fa9cfe87f8ea440caa0f3da9d825368c1980472680191f55b959a19cddd1c6d. All six source hash/size rows, ten evidence rows and12 dependency hashes match. Only the init script and its exact test assertions changed relative to001:

- init script d992de308f7bad9c1e24e2225b5b7bcf8dad5de5369bad42ecd3f7b2c4974fb3.
- test_provisioning.py528d94287cc32d5594ef5438e01020f294209bb53f98d54a8a1e82f4d108fb61.

The init script now declares an abstract DefaultTask subclass with an @Inject abstract public ExecOperations getter. Its runCommand uses ExecOperations.exec(Action), configures ExecSpec.commandLine with the same list, and captures stdout only when requested. No removed Project.exec/javaexec call or internal project.services access remains. Task registration selects that type. The verify closure resolves the capture provider only at execution; both compiler tasks depend on capture. Snapshot prepare/verify arguments, external manifest digest, fresh-output refusal, dependency ordering, compiler pre/post verification and final verification remain unchanged. The unavailable authenticated smoke interface remains unavailable; no new bypass or approval flag was added.

Independent primary API bytes: reread the retained Gradle9.6.1 core-api JAR at the path and SHA5291bad2 recorded in the original section. ExecOperations.class SHA dd979a977bd0863273b063689a47ee71b29b54463d51d6f11ce751ee62436218 matches the author's pure classfile table and exposes exec(Action)->ExecResult. This is the public injectable execution service pattern rather than the removed Project convenience method. The checked class bytes contain the exact descriptor. No class/JVM/Gradle/script/test was executed by this rereviewer. This establishes the selected API exists, not that the complete init script has already compiled or run.

Retained focused result16a0f86f43ae958dc27deb853e653b79db32a9703bac9ac85bf7d6ee71b5ff70 reports ten pure controls passed with zero forbidden attempts. Author API check8aed3e4347f90e62db83bcd501cf74efacb4d04c2ece520ea78d5f7d7d47cc6b explicitly limits itself to class-byte compatibility. New source assertions prevent reintroducing project.exec/internal services and require the task injection shape. They do not substitute for Actions compilation; initial001 diagnostic failures and journal denominators are not relabeled.

The previous adjudication remains precise: both trigger additions and proc-FD relativization/fixture repairs are source-corrected; source/JAR capture architecture is statically accepted with R1 now fixed; the working compile gate still requires actual Actions evidence. Authenticated loader execution, trusted complete runtime/compiler/JDK closure and all approved-host/native/full-smoke requirements remain open. Existing effectful Actions tests were not removed or disabled. Prior package002 and packaging-lifetime reports are untouched. Root retains thread/Git/release authority.


---

# Correction003 additive workflow state-placement review

## Terminal: CLEAR_SCOPED — loader-compilation job state binding only

Manifest build/clang-loader-closure-correction-003/manifest.json SHA4f1241cd9778cbf774d4708b00f0523ee508cb948e69e4bbdaf8f1d1e06dd5b5 verified with all six source rows, five evidence rows and12 dependency hashes. Workflow SHA dc0630591b8c6b6a3aba09b6740fa73961a3bdd1065c5f5d88835bfb73bc6ba8 is the only source difference from002. Other five source hashes remain exactly002. Existing c17ac089 report, including001/002 sections, is preserved byte-exact as this report's prefix.

Reviewed workflow diff only: new loader-compilation job environment sets HOME, GRADLE_USER_HOME, TMPDIR/TMP/TEMP and all listed XDG directories under github.workspace/build/clang1813-loader-ci. JAVA_TOOL_OPTIONS sets JVM tmp/JNA tmp/home, Kotlin daemon runFilesPath and disables UsePerfData. These are JVM system/VM options, not forged approval identities. The shell allocation step follows checkout and precedes setup-java and setup-gradle, creates the selected directories0700, and quotes each path. The Gradle invocation retains --no-daemon and adds the supported Kotlin compiler execution strategy project property in-process. Together this routes the job's selected application/cache/tmp/home and potential Kotlin runfile state into the checkout build tree and avoids a separate Kotlin compiler daemon. It does not relocate or qualify setup-java's host JDK/tool installation or every internal Actions runtime file, and makes no such claim.

No changes to acquisition gating, source/JAR snapshot inputs, compiler task dependencies, authenticated-smoke unavailable guard, native qualification job, effectful tests, security assertions or other workflow jobs. The compile job remains independent of paused acquisition. The existing unavailable authenticated execution interface stays fail-closed. No new executable/toolchain/dependency authority is introduced by state placement.

Inspected retained static-check result56b8ec1e35730188d537d35b09475491e7afe880ec7d04b2a79dd33e647f219c and exact diff; no optional reruns/tests/JVM/Gradle/native/network/Git or source edits by reviewer. This is a source configuration review, not an Actions compilation/run or an actual state-write audit. Actual Actions task/API/Kotlin/Java compilation remains pending; complete host/JDK/classpath authentication and loader-smoke/native/production qualification remain open. Root retains release/thread/Git custody. Stop after this scoped verdict.
