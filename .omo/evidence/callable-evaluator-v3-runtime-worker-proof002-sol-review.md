# Independent runtime worker-proof002 source review

**ITERATE.** Two concrete runtime defects remain: late successful cleanup observations can be recorded VERIFIED beyond the declared cleanup ceilings; post-cleanup pin revalidation can block on a worker-replaced FIFO before its type/deadline checks. Other inspected mechanisms below have no additional blocking finding in this review. This is source/pure-artifact review only, not current composed or native approval. Root retains integration, Git/remote and qualification custody.

## Exact checkpoint

Worktree `callable-evaluator-v2-evidence`, source prefix `oracle/acp/callable-evaluator-v3/source/`. Immutable evidence base is `build/acp-decomp-effectiveness/callable-library-v3/` in that worktree.

- Final `static-runtime-worker-proof-002/manifest.json`: **305e8ec027d45a26a40b0477ab03c971a0581578dccbf35888894be2f83cc326**.
- Preserved001 manifest: **1b3155562678c2450a7367885b7562920c731da12bf293e3d2da48ad46a99f03**; report **f92a1bbb4f8ab28e7eeeae3754fd9418f06bb40f05b44c484ea191336752bea4**.
- All seven002 source snapshots and all four002 evidence artifacts independently hash-match. All six001 source snapshots and eight001 evidence artifacts also match. The six preexisting002 owned files are byte-identical to001; only the visible schema is added to002 ownership.

| Frozen source | SHA256 |
|---|---|
| bounded_runtime.py | `122bbf6cc0c64dd3286cd1b685f00a53429e58dd6ba93249bb33c9b2c91bb610` |
| build_contract.py | `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85` |
| contracts/candidate-build-profile.json | `c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f` |
| contracts/visible-manifest-schema.json | `c3a64923081ee5cf614446832e40bd4d849494516bb3d43eb2cb089c5aafd743` |
| scope_gate.py | `1e82114d9a04d1b2f247e408604dcf4b47d69c06623cfa01da2d281d3a572c82` |
| tests/test_profile_limits.py | `a00a95ae6ca2499c4e6f78f8b52976b89d325bf2545a251722a29a057a7f1d75` |
| tests/test_runtime_worker_proof.py | `601b15e6b6797f0e492c4e9418038beb8608d61ed44294476257a24f3a2f4e1c` |

Approved plan/input pins independently match:

- ROOT `.omo/plans/callable-evaluator-v3-worker-exec-proof.md`: `b670e2de4fe5fbda4b06872234319f9121887d600b2341473d233d051df34ceb`.
- ROOT `.omo/evidence/callable-evaluator-v3-worker-exec-proof-plan-sol-review.md`: `2b3ee62d3a7c184e9145837b90b714756bd370ef2e96080df48e92b278d58978`.
- ROOT `.omo/plans/callable-evaluator-v3-ldd-elf-recipe-addendum.md`: `fd41f6c5b3d8a3bc0967b0933a5fe19f39e6d675b0fd6ea84453072a05e1c010`.

## R1 — final cleanup observations are not charged to their declared ends

**P2; frozen `bounded_runtime._run_scoped:901–915`.** The declared policy explicitly gives wait and subsequent absence verification separate5-second ceilings (`candidate-build-profile.limitSemantics.cleanup`, bounds.cleanupWaitSeconds/cleanupVerificationSeconds; plan:94). Source passes5 to process.wait at905, but never samples time after that wait before creating a fresh verification end at906. A delayed successful wait return can consume more than its5 seconds and still pass. During verification, the loop tests inventories before time (`:907`), and final inventories at910–911 have no elapsed-time check at all. A scan returning empty after the verification end can therefore set rootReaped/finalAbsenceVerified/cleanupVerified True.

This can admit completed worker evidence, rather than merely record slow failed cleanup: phase_elapsed is sampled before cleanup and phaseElapsedSeconds intentionally excludes the cleanup interval (`:893,947–963`); proof validation is then given the remaining phase budget from its new current time. A valid proof and otherwise successful controller can retain a worker exitCode and pass worker_execution_complete even though a declared cleanup stage finished late. A timeout argument is not proof that its successful return was observed within that bound. This finding does not assert that filesystem operations can be forcibly interrupted or that a real late wait occurred here.

Smallest correction: retain explicit stage ends, subtract preceding work in the same stage, and recheck the applicable monotonic end after wait and after all final absence observations before recording VERIFIED. Late success stays infrastructure unknown with exitCode None and cleanup unverified; preserve raw worker/wrapper facts and acquired-handle safety. Keep the original5+5 policy and no retry/resource increase. A future explicit remediation must not overwrite the historical missed bound.

Finite inert seams already exist in `test_profile_limits.ProfileLimits.simulate`/Process.wait and mocked inventories. Add (a) fake-clock advancement beyond5 on the cleanup wait's successful return, with the earlier wrapper wait immediate, and (b) an empty final inventory which advances the verification clock beyond its end. Both frozen predicates incorrectly permit cleanupVerified; corrected source must refuse completion and preserve bytes/status. No sleeping, process or namespace execution is necessary. Existing persistent-survivor/timeout controls (`test_profile_limits:266–295`) do not cover these late successful observations.

## R2 — pin opening can block before regular-file validation or deadline check

**P1; frozen `_pin_files:559–568`, called after cleanup at `_finish_worker_proof:764`.** The reader resolves the path and opens it O_RDONLY|O_NOFOLLOW|O_CLOEXEC at560 before fstat/type checks at562–564. It lacks O_NONBLOCK; its first deadline check is only inside the later read loop. Opening a FIFO for blocking read can therefore wait indefinitely before either refusal is reached.

There is a source-permitted worker path to that condition: `_contained_recipe:320–330,365–370` accepts a target file inside the sole writable cwd bind and does not require an additional RO bind for the executable. The monitor may observe the initial ELF exec successfully; afterward that worker can unlink its own pathname and create a FIFO there while its executing image remains valid. Once its processes exit, cleanup can be genuinely complete. Post-cleanup `_pin_files(launch['pins'], deadline)` then resolves and blocking-opens the replacement FIFO at the target pathname, hanging the trusted controller with no writer. It cannot reach its deadline check. Pin mismatch after reading is insufficient to handle this type substitution. No native worker or FIFO reproduction was run by this reviewer.

Smallest correction: open potential mutable pin paths with nonblocking/no-follow flags and reject nonregular type from the opened descriptor before any read, retaining stable descriptor/path identity and existing byte/deadline checks. Other pin-opening validation paths should maintain the same regular-file safety invariant. Do not solve this by removing post-run pin validation or accepting changed pins. An exact-file RO overlay for mutable targets is useful isolation but does not replace safe pin-reader handling of substitution.

Finite pure control: capture os.open flags and mock fstat to a FIFO/special-file mode; require O_NONBLOCK and refusal before os.read. Pair it with a contained-recipe control showing the admitted RW-work target shape, plus retained normal/changed/oversized pin cases. Existing `test_runtime_worker_proof:119–128` covers empty/mutated regular files and expired reads, not blocking special-file open.

## Mechanisms confirmed in the frozen source

**Proof versus launcher status.** `_prepare_launch:616–648` derives expected attempt/phase/report/reaper/outer-namespace/target identities from this launch, stores config and ordered pin commitments, and inserts the fixed monitor ahead of the preserved original worker argv. `_finish_worker_proof:733–785` requires private file/path/descriptor identity, ownership/mode/link count, bounded stable raw bytes, unchanged launch pins/config and actual parser output. LauncherExitCode remains independent. Worker exitCode is set only with terminal proof and the full successful controller chain; partial exec remains representable without terminal completion.

`worker_execution_complete:27–136` closes binding/expected/pin entry keys, checks canonical pin digest and target/reaper linkage, binds phase, requires all existing launcher/scope/capture/wait/reap/cleanup/absence facts, refuses provisioning/timeout/overflow/infrastructure failure and invalid streams, hashes at most1024 raw proof bytes, replays the fixed parser, and compares exact termination/normalized exit/hash. Normal exit139 and SIGSEGV -11 remain different. This does not turn an arbitrary caller-authored dictionary into authenticated kernel evidence: the trusted producer, inaccessible report channel and receipt-store binding remain necessary.

**Acquisition-bound cleanup authority.** `_admit_scope:675–730` validates private gate start identity, exact unit and kernel limits, acquires the cgroup directory, rereads limits through that descriptor and rechecks path inode/gate identity/membership before writing admission. `_scope_fd`, `_kill_owned_scope` and scope_processes use the acquired descriptor; cgroup.kill is opened relative to it. cgroup.procs and session inventories only establish absence. `kill_exact` always refuses numeric PID signalling. `_run_scoped:845–853` acquires a direct-child pidfd before any wait/poll/reap, retains it through cleanup, and uses pidfd_send_signal. Handle-close failures invalidate completion. No stale PID snapshot is promoted to signal authority.

Pre-admission/Popen/no-handle uncertainty remains unknown rather than fabricated absence. This review does not claim every such failure can be cleaned successfully, or authorize retrying failed cleanup. Actual cgroup, pidfd, systemd and descendant behavior remains native qualification work.

**Mount/channel/Python separation.** `_contained_recipe:274–371` closes bwrap options, requires fresh namespaces/no capabilities/clear environment, refuses direct-host work, reuse/extra status-FD features, broad or protected control trees, runtime/monitor shadowing and writable aliases. RO overlays after the sole RW leaf remain present even inside cwd; later RW binds that hide them and work hardlink aliases refuse. Existing /probe,/work,/caller,/library.so/workspace semantics and compiler argv remain preserved by the recognizer and retained pure controls.

Report root/attempt directory/file are private0700/0600 with exclusive no-follow creation (`:374–390`) outside all permitted worker mappings. Gate launch uses fixed Python -I -B with fresh private pycache_prefix and HOME/TMP/cache under that unmounted private attempt (`:634–641,838–841`). Fixed contract/parser source is compiled directly rather than taken from sibling pyc. Gate verifies isolated bootstrap, private directory/config, caps/NOFILE/outer namespace, waits for admission before opening the exact zero-length report, explicitly makes4 inheritable and closes other nonstdio handles before exec (`scope_gate:52–119`). No inherited-FD forwarding through systemd-run is assumed.

**ELF/ldd and provisioning boundaries.** Worker/reaper/monitor must be regular executable non-set-ID, with no file capabilities and explicit ELF bytes (`:215–233`). Generic script execution remains refused. The separately reviewed A1 fixed Bash ELF/ldd-script/cache recipe remains the sole disclosed inspection exception, with A3 closure authority separate; runtime does not introduce a generic shell or host fallback. Provisioning is a separate fixed public monitor compiler route and channel-free; provisioningOnly can never satisfy worker completion. No source-native, loader, API-entry or internal-function observation is claimed.

**Profile/visible contract.** Original CPU30/AS2GiB/NOFILE64/FSIZE16MiB/CORE0, aggregate memory512MiB/swap0/tasks32 and phase/capture/temporary-filesystem limits remain immutable and explicitly disclosed. No aggregate CPU limit is falsely claimed. Monitor overhead shares existing phase/task budgets. Proof/control metadata bounds are finite; visible schema's profile.const independently equals the exact candidate profile, required visible keys remain closed and build_contract.verify_visible independently binds profile digest and prompt bytes. R1/R2 are implementation gaps, not permission to increase these limits.

## Retained pure verification and coverage

001 `pure-checks.json` **a16891b09510eaadcff4a83bfd9a1ebc0f114c735340631dea71cbb28acbc637** and log **0021f74f6369574033608316743cd4f81ef4502ace7d1c097060c701940993f0** report118 tests, zero failures/errors/skips/forbidden attempts. Module counts are20 identity+31 link-input+14 profile+9 runtime+33 proof-parser+11 consumer. Its before/after maps independently equal the six owned plus21 exact dependencies. The runner **c905fc05dab89e67e9fea3cb6508915b5208475a1931aec9ce4fe103ef160374** installs native-denial and ctypes.dlopen rejection before discovery. These are actual retained pure results, not a rerun by this reviewer or native proof. The preserved initial failure remains an AST-wrapper adaptation diagnostic, not success.

002 adds only six focused schema controls: exact profile equality/valid manifest and four refused mutations. Retained schema result **46795fa4281d04b769942c49c3a22ea65b45779f1d1212740509fd6417ff8dfe** reports6/0 forbidden. Runner **abf08592991b8e57761d3c2feade716c4abdacade1d764095297abe760df2db5**, report **9152a6f722868403771e35257c17c31d2c01300bf3881713ff2a9ac715134f79**, delta **db15c9e47e5a10bc13d97dc1f00ede1f752efac6d9ee3b1285211c7a2b1dbd2d** all hash-match. The schema delta records its historical before hash/nonprofile equality; current exact const/closed shape was independently inspected. No full118 current-composition rerun is inferred from the six controls.

## Current drift and preserved A1 reviews

All seven current owned files still match002 at the final observation. Of001's21 integration dependencies,17 still match; these four differ:

| Dependency | Tested001 SHA256 | Current observed SHA256 |
|---|---|---|
| evaluate_candidate_v3.py | `3e7f50b74af4239acabe84795222cbdc414104fd06ba0ed0d9b2293d4f544e9c` | `5470048943eea8b7198334a4b4ae431ea245a26c844f4e136350a81e9277cd86` |
| tests/qualify_worker_exec.py | `da0d2797db7e6850cf7a98345649149d9c5c6b911413bc1020347f238fb57ab0` | `6975b1d6166154370b05dcf596500282adb9eb11ae390aa7da61ce7ac7ac08ec` |
| tests/run_static_tests.py | `e4f6ef488819f2633d98579457efdc086da29075998fc6c0326ca534b9573b2c` | `30bea0fb1ff8cbc588189504b8a3c220d66dfeff8a525110611620ef13e18efd` |
| tests/test_worker_exec_proof.py | `5dca4e16dc8ce684723acc71ef0eef75d2be3a9317b40a8d129f05620a4745fa` | `470d7248f5b93b64cee91b18c127d4a7eebd2ca5b8c3dec9ce17d0aa13dd3426` |

These concurrent changes are observations, not review or a demand to revert them. No historical test result is relabeled as coverage of current evaluator/qualification/parser-test composition. A1 reviews remain byte-preserved:

- `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-sol-review.md`: `7a37d5e82dff116c9bab2d3187d2ac7569eeffcf3ebf6dd1fc844ab3fbd95d4e`.
- `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-followup002-sol-review.md`: `e347d597b76c34686df23fe0e4ce6bb8ab67144479462216c25c29a9f944f699`.
- `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-correction003-sol-review.md`: `2614ff826da57d74ce64304af60e6aacf36fd72415d80a51e875065a58b53c51`.

## Required next checkpoint

Root should assign R1/R2 to the sole runtime owner, retain this original freeze and controls, add the finite pure regressions and request review of a new exact corrective delta. Separately bind current evaluator/A1/A3/C/parser composition and the static test inventory. Actual monitor/Bash/ldd/helper/compiler handoff, ptrace/proc/report denial, cgroup cleanup, local/hosted public controls and full private matrix remain unqualified and separately authorized. No issue/parent or preparation authority is advanced here.

Review performed source/evidence reads, AST parsing and hashing only. No source edits, tests, native/process/CLI/policy/namespace execution, Git/remote/CI/auth/model action, attempt cleanup or descendant. Only this additive report was written.
