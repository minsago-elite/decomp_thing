# Provider495 native delta: source and proposed verification review

## Terminal verdict

**CLEAR_SCOPED for the three source files; ITERATE for execution setup release.** No source blocker found in the requested capsule/budget/diagnostic delta. The proposed setup describes an appropriate inert test scope, but does not yet supply the new runner or an exact bounded launch recipe. This report does not authorize execution or claim compiled closure/native qualification. Root owns execution release.

Read-only source/artifact inspection only. No compiler, test, JVM, native DNS, namespace, proc, credential, authentication, model, network, CI, Git or remote operation was performed. No source was changed. Other owners' changes remain untouched.

## Exact bindings

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`.

| Artifact | SHA256 |
| --- | --- |
| build/provider-495-native-delta/freeze.json | 66dbf8f5c7b033b284e79f7a1f7bd4cf72756a9d02723c1cd514b01c6745327c |
| AcpProviderNativeDnsContractTest.kt | c7ed189813be1a42b88a554fddb20b67aff19550659e6b41e04587b8c2d9cc8b |
| NativeDnsObserverDiagnosticTest.kt | 7870c6db1eff8d833bc159cab868f315f69e10972bbb52a026e06a5d04a60fc6 |
| NativeDnsControlCapsuleBoundaryTest.kt | 61e087fb73778d28cb205bf2f39705b897395dcd2b2a53fffb09d387be142bf1 |
| proposed-jvm-setup.md | 2d0a11ddd1934a36cb649660559931f254b3f4fbd127bcdc81addd51dc67aaac |
| current NativeDnsObserverCapacityTest.kt | 2f43d218676c72e1e32fe5223be53cf674d327e642d73dea294cf5fa31d1dc24 |
| prior build/provider-native-capacity/verification.json | 758c80e05e51ce45da0827b39d3ee05194445585986cc960f1489d612a7dfd49 |

All 14 freeze entries rehashed and matched, including current three source files and frozen before/diff artifacts. No current-source equality to a remote merge tree is inferred.

Root-checkout retained diagnosis `build/provider-495-hosted-diagnosis/diagnosis.md` matches **62bd2ae0e694f7773a79a197bd7b2835403e9be263504937b47db65e5cba8a9a**. Its actual control-JAR class-reference evidence matches **9fa10b50c0b251c968ed8826a47fecf839d5acaf9ecece383a8867b04f0e2aff**; inventory matches **75fa1c6c84959465293778deaa3665a4ca660d7cff0302462a270db8aaef38e4**. Both captured control JARs were 111845 bytes, SHA40d505497d85c2f3132d0b0ee65fdf6655cba4fe87ffc6f68bf00ca5de0592ef, with 28 entries and missing referenced NativeObserverBudget/NativeObserverFailure/NativeVisibilityAccumulator. The fixed child classpath was capsule plus stdlib. Exact discarded JVM text remains unknown. The old diagnostic failed with OBSERVER_DEADLINE before its deduplication assertions due to an expired ambient global budget. These actual495 defects are distinct from TLS cleanup and live prelaunch hashing failures.

## Source findings

### Capsule selection

At native source lines736–763 the change adds four exact observer roots and selects each root's `.class` plus its `$...class` generated nested classes. It does not use broad NativeObserver/NativeVisibility prefixes or a host-classpath fallback. Existing AcpProviderNativeDns/NativeNamespace and AcpProviderDns/ProviderDns selection remains. Before JAR emission each of the four root classes is mandatory; a nested class cannot substitute for its root. The new inventory ceiling256 only refuses. Existing per-class bounded nativeRead, deterministic entry ordering, DNS resource and capsule/stdlib dispatch remain.

This covers the demonstrated three missing roots plus the new lease-owner root; in particular NativeObserverBudget's generated default-clock class and any generated lease class are selected. The four inert boundary methods cover root omission, nested substitution, suffix rejection and the explicit selection rule. Source reasoning cannot prove newly compiled bytecode closure. Root's later bounded class-file inventory must verify emitted root/nested classes and same-package references without launching the control.

### Exact-owner lifetime

Host nativeDnsCase acquires one lease and closes it in the enclosing final cleanup block after success or failure, preserving primary/cleanup failures through nativeKeepPrimaryFailure. Snapshot/capability/probe/dispatch failures after acquisition all pass through that block. Acquisition failure does not acquire another owner's lease. The owner refuses overlap; close clears only the same object, and repeated close is inert. No deadline is renewed: the same immutable endMillis and existing budget admission predicates remain.

Child main acquires before dispatch for both outer and inner roles, clears sink and closes its lease in finally, then invokes exitProcess only afterward on failure. There is no other exitProcess/System.exit in the source bypassing that final block. Valid child control flow has no competing lease mutation; no new thread-safety/concurrent-native-test guarantee is asserted. The boundary controls exercise exceptional release, overlap refusal, idempotent close, expired budget reacquisition and independent diagnostic state.

### Independent diagnostic semantics

All six existing diagnostic method names remain. The changed overflow test constructs its own NativeVisibilityAccumulator, retains 32 identical-observation deduplication, fills exactly16 distinct retained rows, rejects the seventeenth unproved observation with DIAGNOSTIC_CAPACITY and verifies storage stays16. It no longer calls mutable native globals, proc or reflection. This preserves those accumulator semantics while leaving nativeRecordDenied integration/native proc observation explicitly outside the inert test's claim. The other five controls retain credential tuples/classification, invalid-identity refusal, primary exception identity/suppression and fixed child outcome classification. Existing eight capacity controls retain deadline/work/byte/storage/visibility semantics independently.

## Setup correction before execution release

The proposed setup correctly specifies pinned offline JDK21/compiler2.4.0/JUnit inputs,512MiB heap, no attach/perf data, repository-local scratch/preferences, removal of ambient Java option variables, fresh output and exactly three inert test classes (6+8+4=18). Compiling the native fixture is not permission to discover or execute its two native tests or its control main.

**Required setup artifact:** provide the authored inert runner and exact command/environment/supervisor recipe before root releases execution. The currently retained NativeCapacityJUnit.kt only allowlists DiagnosticTest and CapacityTest (plus a separate broader inventory mode); it cannot select the new BoundaryTest unchanged. The proposal names an inert runner but does not include its source or exact selectors. This is a concrete unreviewed launch input, not a source defect.

The replacement should allowlist only fully qualified NativeDnsObserverDiagnosticTest, NativeDnsObserverCapacityTest and NativeDnsControlCapsuleBoundaryTest; use exact class selectors, never package/classpath scanning or inventory mode; assert per-class6/8/4 and aggregate18 discovered/started/succeeded with zero aborted/skipped/failed. It should use fresh classes first in classpath and pin the actual production/main/test dependencies it imports, so stale test/facade classes cannot shadow freshly compiled outputs.

The setup also needs finite wall and capture limits for compiler and JUnit, plus fixed kill/wait cleanup on timeout. `-Xmx512m` bounds heap, not execution duration or captured logs. These limits and the exact runner/commands are absent from proposed-jvm-setup.md. Root can materialize bounded compiler/JUnit phases (for example120s/30s and1MiB stdout/stderr each with a fixed10s kill/wait ceiling), pin every referenced file and retained log, and submit that setup for narrow review. No acquisition, native control dispatch, proc/namespace capability check, provider target, network or credentials belongs in that setup.

No fresh compilation/test/actual capsule construction has been observed. The retained12 static checks are structural evidence only. After setup correction, a focused18-test pass would qualify those pure controls; it would still not qualify actual native DNS, capsule launch, cleanup visibility or live provider behavior.


## Addendum: exact setup001 rereview — CLEAR_SCOPED

The original review above is retained verbatim (pre-append SHA2566fb00618755b2b2dcc76c62c950ff8ad1df5cfa7f0628f48d7a3b51b8d9f842d). Its setup ITERATE findings are resolved by the exact additive setup below. **CLEAR_SCOPED for one root-controlled pure18 verification launch using this frozen recipe.** Root retains explicit execution release; the reviewer did not execute controller, compiler, tests or JVM/native/proc/network/Git/remote/CI/auth/model operations.

Exact worktree-relative pins:

| setup001 artifact | SHA256 |
| --- | --- |
| setup-freeze.json | 4091db7eb69dade7e19bf14221a1e8d0612755a5a09bd81591fadf4c94cf5edb |
| controller.py | f2425ccd40baebb20f35167ce5a23fcb4182365a89bfa27a918ae772dd3b085d |
| source/Capsule495PureJUnit.kt | d4507b85b23f354c9e00d5706b4cab07cb6b03dcd60e8bc5994160978b4dd6bf |
| commands.json | 5f4b72a9c122288c0c35009fc765fe53bbb26febe82b1d18ed5c520bf4236dc0 |
| README.md | 087c6dcef828d6dc580b59c23d86ea8808f936d8eafce7d29a6b4395ffd979b6 |

Base directory is build/provider-495-native-delta/setup-001. All11 setup-freeze entries independently rehashed and matched. Copied source hashes retain original66db source identities; capacity source matches2f43d218. Commands bind current four source hashes/sizes and6614 reused input files/165967324bytes. This review parsed the full manifest and inspected its exact vectors; it did not independently reread every reused dependency byte. Controller validates all pins before launch and afterward, and refuses drift. The authored runner is a new exact reviewed input, replacing the old two-class/inventory runner route.

The runner accepts no selector arguments. It selects literal6/8/4 method names in only DiagnosticTest, CapacityTest and ControlCapsuleBoundaryTest. Before execution it verifies the discovered MethodSource identities exactly equal the18-member set with no parameters. Only explicit JupiterTestEngine is registered; engine, execution/discovery/session listeners and post-discovery-filter auto-registration are disabled. Extension autodetection and parallel execution are disabled. No native fixture/control class or main, package/classpath scan, old inventory route or external selector is selected. It requires found/started/succeeded18, zero skipped/aborted/failed tests, and zero skipped/aborted/failed containers before the fixed pass marker.

The compiler entrypoint is the pinned Kotlin embeddable compiler, consuming exactly the four copied fixture/control sources plus the runner; the test entrypoint is Capsule495PureJUnitKt only. Fresh execution/classes is first in the execution classpath; stable prior main/dependency directories follow, without the old native-capacity/test/runner outputs shadowing fresh classes. Explicit whitelisted child environment and repo-local HOME/tmp/cache/preferences remove ambient Java option injection. Both JVMs use512MiB heap, attach disabled and perf data disabled. Only the JDK launcher is explicitly included under /opt in this input inventory; this is reuse of the existing host JDK operational setup, not a newly proven complete immutable JDK byte closure or native/runtime authority.

Controller is import-inert and requires the exact approved setup-freeze SHA256 at its explicit execute-reviewed entrypoint. It creates a fresh one-use execution directory, validates frozen inputs before starting children, and stops on any unsuccessful phase. Compiler120s and test30s are absolute wall limits covering launch/capture/wait with a post-wait late-success refusal. Combined stdout/stderr per command is1MiB, read using a remaining+1 sentinel, with bounded retained bytes. Each child owns a new session. Timeout, overflow, interruption, nonzero, surviving group, IO or cleanup errors fail the attempt; necessary SIGKILL/reap/group-absence uses a separate fixed10s ceiling, and any cleanup intervention remains failure even if absence is subsequently established. No retry follows failure. Capture/stream/selector closure outcomes, exact argv, exit, log hash and cleanup facts are retained.

Overall polling/hash work has a300s controller deadline, each input hash pass60s, log hash5s; manifests4MiB, input census10000files/1GiB, streaming64KiB hashing with expected-size/stability checks. These are cooperative limits around ordinary OS operations; the README accurately discloses that blocked kernel calls cannot be forcibly preempted. Process-group absence is the declared cleanup scope, not a universal descendant or namespace proof. No broader native authority follows from these finite trusted JVM commands.

The source66db clearance is unchanged. Setup001 is now concrete enough for root's one authorized pure verification execution. Compilation/JUnit success is still unobserved; no fresh output, actual capsule construction/launch, native DNS, cleanup visibility or production/provider/live behavior is qualified by this rereview.


## Root-found missed setup001 authority flaw; setup002 rereview

The entire prior report is preserved above as exact997dcaa7482f342255841fb9c1cb3492f01374d1d80c7a11e2495a1445b0ec51 bytes. **Its setup001 execution acceptance is superseded and withdrawn.** Before any actual compiler/JVM/pure18 launch, root identified a missed blocking cleanup-authority flaw: setup001 finally called process.poll(), potentially reaping the leader, then could send SIGKILL to a surviving or reused numeric PGID. A post-reap numeric group observation is not retained destructive signal authority. The earlier review missed that defect. No actual18/JVM execution occurred under setup001 acceptance. Source66db and separate TLS diagnostic CLEAR scopes are unchanged.

**Terminal setup002 verdict: CLEAR_SCOPED** for the narrow cleanup-authority correction and root's one pure18 verification recipe, subject to root's explicit execution release. No compiler/test/JVM/native/proc/signal/network/Git/remote/CI/auth/model execution was performed in this rereview. Retained inert controls were inspected, not rerun.

| setup002 artifact | SHA256 |
| --- | --- |
| setup-freeze.json | 6890ae80dd48d63561f56b290d216cd0cc4c46ddbfdb6c383a633cdbf8b7bd9a |
| controller.py | e698cc8003a228703c62a92e9969bb54f159dae399a8907261d0f64c0095ef00 |
| commands.json | 5e04e8363b44bdec0e84dc07f449faabb97f922cfebfc4f1aa4f2cfc755414ac |
| source/Capsule495PureJUnit.kt | d4507b85b23f354c9e00d5706b4cab07cb6b03dcd60e8bc5994160978b4dd6bf |
| test_cleanup_authority.py | b0d564df6e4411a5058104af310c83b95ada8ddbd76d7d13eac649d236dfec3a |
| inert-receipt.json | 585e8ef06806ff45b3d17697e04126c7edb601a036272e6983c63d6ae28078db |

All listed setup002 freeze entries independently rehashed and match. Parsed setup001/002 command vectors, whitelisted environment, exact expected method list and bounds compare equal after normalizing only owned setup-directory names. Runner bytes are identical. The controller diff is the acquired-group/reap-state correction; selection/source qualification is not broadened.

The controller acquires the newly launched session leader's group identity before capture or deadline refusal. It has no poll call. Normal terminal wait marks arbitrary interrupted/failed waits as reapAuthorityUncertain; that state prohibits further destructive signalling. Successful wait leaves a reaped leader; its group receives only signal0 existence metadata, never a nonzero signal. A surviving/reused post-reap numeric group is sticky uncertainty and fails even if it later disappears.

On cleanup of an acquired still-unreaped child (returncode None with no ambiguous-reap flag), the retained direct child reserves its PID. A single SIGKILL to that owned group occurs before the cleanup wait; there is no destructive signal after that wait. Missing group acquisition, prior intervention, interrupted/ambiguous wait or post-reap uncertainty refuses authority. TimeoutExpired from the ordinary subprocess wait leaves the direct child unreaped; other unexpected wait exceptions conservatively prohibit signalling. No unreviewed alternate wait/poll/reaper path exists in this single-threaded controller. Inability to prove cleanup remains failure rather than a retry against a numeric group. Any intervention still fails the command; the next JVM is not launched after failure.

The retained eight fake-process/clock/kill-spy controls cover reaped surviving group, reaped absent group, acquired unreaped kill-before-wait order, unbound group, interrupted-after-reap no retry, sticky post-reap uncertainty, ambiguous wait without returncode and static absence of poll/original001 freeze preservation. The spy replaces killpg and Popen; their retained8-pass receipt is not actual process authority or a new JVM result. Fourteen retained static preparation checks similarly do not constitute Kotlin compilation or runtime qualification.

This narrow source fix resolves the root-found setup001 blocker without changing18-test selection,512MiB heap,120s/30s phase limits,1MiB combined capture,10s cleanup ceiling, pinned input reuse or native exclusions. Root may release only exact setup002; setup001 remains historical and must not execute. All earlier limitations concerning host JDK operational reuse, cooperative kernel-call bounds, declared group-only cleanup scope and absent native/provider qualification remain applicable.
