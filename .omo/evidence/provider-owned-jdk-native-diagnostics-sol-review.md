# Independent CI owned-JDK and native diagnostics review

Verdict: **CLEAR for the exact CI fixture/diagnostic source and retained bounded evidence below.** No blocking source finding remains in this review. Actual full application/guardian/native DNS execution, required hosted checks and production Task6 qualification remain pending.

Read-only independent Sol source/evidence review; source author was stopped. Only this report was written. No source/Git/remote/Actions changes, new acquisition, test/JVM/native/namespace/provider/authentication/model/credential execution, privilege changes or descendants. Existing artifact hashes were independently recomputed; no additional tests were necessary.

## Exact binding

`build/ci-jdk-repair/source-freeze.json` SHA256 **`41c7e4cb4eec4985dbb2345b5c4faee1370c719164f0f26cb608b3c50ba9afff`**. Read its final handoff `build/ci-jdk-repair/handoff.md`, the prior setup-java assessment and retained native visibility diagnosis. Independently verified all10 frozen actual source hashes, all21 evidence hashes and both preserved historical freeze files: no mismatch.

Final handoff SHA256 `f714c17276e67252f178d575126043e5e52bf44c00ec1f034aab523eacfe043b` independently matched. All10 actual source pins were rechecked again at terminal review publication and remained unchanged.

| Reviewed input | SHA256 |
|---|---|
| `scripts/ci-owned-jdk.py` | `8ee03e5165a709b386774a4382515c1faee358ec29fcabe16d7a8cb6283eb3d1` |
| `scripts/ci-jdk/test_owned_jdk.py` | `8238fc17f484134bba1ad25ae8caae13ec3995fef000ec3b0892671a8efdd2eb` |
| `build.gradle.kts` | `97073094fa47bc70228b9041f647afb992112d937b5bf6e88ec089b391bd71bb` |
| `OwnedJdkFixtureSession.java` | `45e59c488b54a3dd6a00eb955eaf0917a7bafcf736fd7fdd960c3e1971d958c6` |
| LauncherSessionListener service resource | `ff63732a615be9ccfe0c78f47dd50dd23d1c87a66e3d3bc299926ed476571dba` |
| `AcpProviderNativeDnsContractTest.kt` | `02265536e625494c190c1ac55e4aed87c9ff48fc8dc903742294db10842a89ec` |
| `NativeDnsObserverDiagnosticTest.kt` | `548a4e9c359d1d55e52e73aa276fe7c1a282469f2301f27363dce9d9eaf28706` |
| `.github/workflows/acp-contract.yml` | `cece48bd801c8ce1128cb606b67e4ac1e0f2cae4da64eade92a1e230977ff8b9` |
| `.github/workflows/ci.yml` | `4f41d00f9e62da5cb3c50bed4460f23cd264d3469866d71152a09fdc20605310` |
| `scripts/validate-acp-contract.sh` | `d03cb790d51f58c07a9647d59f2417176516252f8b4107f761485646cd13faef` |

Independently confirmed unchanged Broker `9bcb01a14be5cde023565d864ac1246cce10632dc05bc735f52a39d688b3334a`, cleanup regression `645bc7005b2b29ab0d27a7b8a2dc0f5fce89cefb53ebacacf3d3a28b6868996e`, and Harness `938d80658e869357b169ecd41d2d504a9917b3cc019d298c37ad4aa8dd3bc30d`. Prior review artifact `provider-security-corrections-composed-sol-review.md` remains `08f708646ebb7057bf0bfef25392644315026f42ff1f5cd690c56515643976b0`, including its narrow final-wait CLEAR. Historical composed e489 remains a preserved earlier receipt, **not** a current global source identity after these CI edits.

## Owned JDK and actual Test JVM assessment

The wrapper consumes the already selected JDK read-only; it neither installs/downloads one nor attempts RUNNER_TOOL_CACHE/RUNNER_TEMP overrides. This matches the source-proven refusal in the prior setup-java assessment. Existing setup-java's runner-managed paths remain existing build-tool infrastructure; this review does not claim its installation writes were relocated into the repository.

New repair state is under a fresh owned0700 repository build child. Descriptor-relative NOFOLLOW traversal preserves links as link text, rejects special/set-id regular files, bounds work at20000 entries/4GiB/depth64, authenticates source entries before/open/after copy and later source revalidation, and creates separate single-link regular-file inodes. New copied directories receive safe modes; no source descriptor is chmodded. Launcher publication checks owned root/bin descriptors, regular/no-follow/single-link ownership, same bytes, same target device and different source inode, then descriptor-fchmods **only the copied launcher** to0755. Source root/content/modes/owners/inodes/sizes/mtimes are rechecked. Atime preservation and hostile same-UID isolation are not claimed. Full-JDK links remain ambient build-fixture data; they are not transformed into approved link-free production content.

Inherited JVM hooks are replaced for this CI invocation. Clone JAVA_HOME plus org.gradle.java.home, disabled automatic toolchain detection/download, explicit clone installation location and disabled persistent daemon avoid choosing the original launcher. The client, any single-use Gradle JVM and Test forks receive repository-local tmp/home/preferences/JNA/cache state and `-XX:-UsePerfData`; attach is disabled and Kotlin compilation is explicitly in-process. Known daemon-criteria selector presence is refused. No host launcher, tool-cache, proc policy or privilege setting is modified by the repair.

Gradle's existing `tasks.withType<Test>().configureEach` now sets public **executable during configuration**, before javaLauncher realization. It checks resolved launcher and installation home at task admission, preserves feature21 compilation/worker release settings, disables cached/up-to-date Test substitution for this fixture, and records the exact task selection. The same block applies to late-registered Test tasks. The implementation uses supported Gradle9.6.1 executable semantics researched earlier; it does not instantiate internal launcher implementations or substitute only the DNS child's launcher.

The minimal Java JUnit LauncherSessionListener returns immediately outside the explicit CI fixture. When enabled it executes inside each actual Test JVM before tests and binds ProcessHandle command and java.home to the expected canonical clone. It compares the named launcher's dev/inode/uid/mode/nlink with the **running kernel `/proc/self/exe` identity**, then checks the expected launcher hash and full PID-authenticated UID/GID status tuples including filesystem IDs. This distinguishes a byte-equal host launcher from the copied executable. The wrapper independently verifies exact receipt keys, expected clone identity/credentials, closed-session marker and task-to-selection correspondence; absent or mismatched actual worker evidence refuses success. Session closure is evidence of JUnit session completion, not a new generic native cleanup authority.

Workflow wiring covers required ACP, packaged web/jobs tests, both ordinary CI shards including their later isolated V3 Test tasks, bundled Ghidra tests and Clang tests. Existing non-Test distribution checks remain outside the wrapper. Required ACP script requires the owned selector/receipt, retains required flags/run ID, and still runs the reviewed trusted native checker task after tests. Artifact rules retain finite provision/final/selection/worker receipts without uploading the full JDK clone. Existing fixture0755 and production material0500 checks are unchanged; no production issuer/profile or network capability is enabled.

## Native identity and diagnostic assessment

Caller authority comes from bounded `/proc/<currentPID>/status` with exact Pid and all four Uid/Gid fields, rather than proc inode ownership. Proc-self inode owner is retained only as a diagnostic comparison. Target status is bounded and authenticated to PID with starttime observed before/after; malformed, unreadable, disappeared or changed target state after namespace EACCES becomes unknown. Unknown target **or any matching UID or GID** remains fatal. A missing status after EACCES is not treated as independent exit proof. Existing namespace-link ENOENT handling is unchanged. Distinct-credential denied records do not claim visibility for possible owned processes.

Denied observations retain only bounded numeric PID/starttime/credential tuples, namespace kind and fixed host/outer cleanup phase/classification. Exact duplicates deduplicate;16 distinct records/16KiB are hard ceilings, with overflow failing closed. The parser/control tests cover filesystem UID/GID matching, wrong PID, duplicate/missing/invalid/range-exceeding fields and unknown target. Namespace membership/teardown visibility is not relaxed.

Native wait records only fixed recognized stage/exit outcomes; arbitrary stdout is classified without forwarding. Top-level, wait, outer and inner execution failure paths retain the primary Throwable and attach cleanup failure rather than replacing the primary. Fixed category records distinguish execution and cleanup failure; arbitrary exception messages, environment, packets and model/provider content are excluded. The observed historical primary child failure therefore remains UNKNOWN; these new diagnostics improve the next run and do not reinterpret the old cleanup-only stack. Existing deadlines, capability/NNP checks, no address/connect admission, kill/reap/join/pipe proofs, host invariance and verified-only tree removal/receipt publication remain mandatory.

## What the retained controls prove

All following are source-author retained executions, independently inspected/hash-checked here; reviewer did not rerun them.

- **12 fake-owned-JDK controls** pass, log `bbb7fe8be1c784773d280e500d53ce2c24e9725d5695b8a189a87dcd1d4c0908`: source0777 remains unchanged, independent copied0755 inode, copied content/link text, symlink/special refusal, no source-inode fchmod, partial-open FD recovery, source/clone mutation denial, credentials and missing/wrong actual-JVM evidence refusal.
- **Real offline Gradle9.6.1** runs two actual Test tasks, `:test` and later-registered `:secondFixture`, with two passing one-test XMLs and no failures/errors/skips. Log `bb84b1ca45973174824e93a67a31c97fa7732a40bad914cd1171c2ac8b6ea4fd` records normal single-use Gradle completion and wrapper success. The tiny project copies the exact production selector block and frozen listener source, not a parallel reimplementation. This proves that public Test executable selection and listener work in real Gradle, but is not a full application/Kotlin/native run.
- Actual evidence fixture first creates an independent owned full-JDK copy and changes only that simulation launcher to0777. Wrapper consumes it into a second independent clone at0755. Provision records show source mode511/clone493 and distinct dev/inode identity; both actual JVM receipts bind command/home/kernel-checked dev56/inode5521977/uid1000/mode755/hash `1005aa1f1c6277efbce90d9fed547963e2bf28ba78f7dd4c81d1d8a4627495ca`, full UID/GID tuples and the two exact task selections. Final receipt confirms source unchanged and two actual Test JVMs. Original selected JDK was revalidated unchanged. This is an explicit **owned simulation** of the retained hosted0777 condition, not a newly observed hosted failure or host chmod.
- **Six pure native diagnostic controls** pass, log `e74dd42bf9609fbee970aff5d991c97feef58b14d6393d515264687f4b3e6da5`, verification `12bb15e77d53a88977a7599270cd71a397bd638eaffd600b8ca9d5950b7ff147`: current native test/diagnostic code compiles privately; controls cover credentials/refusal, primary/suppressed identity, record deduplication/overflow and fixed output formatting. No namespace, resolver or privileged native path executes in these controls.

Actual hosted full native DNS cancel/deadline and complete namespace destruction, guardian runtime, complete application suites, required Actions and automatic review remain mandatory. This source CLEAR authorizes no provider/auth/model call, production Task6 closed runtime/permit/composition, issue closure, effectiveness claim or release qualification. No unknown historical cause was filled in and no prior review was rewritten.
