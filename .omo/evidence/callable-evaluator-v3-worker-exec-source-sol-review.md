# Independent static worker exec source review

**Terminal verdict: ITERATE** on held manifest SHA256 **`bdf26b2f6b2b23be3158759f4bdf60bd0e398f2ed2caf566a592ca71d2693e2f`**. The monitor's central static control flow follows the approved plan, but the new qualifier has an unsafe scope-member cleanup race and incomplete negative-control admission/coverage, and the parser performs over-bound hashing. These require correction before this seven-file checkpoint is CLEAR.

GPT-6.1 Sol only, independent of source author; no descendants. Worktree `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`. Root retains source/Git/remote/native custody. Only this report was written. No C compiler/syntax-only check, executable/helper/candidate/native prototype, namespace/proc probe, bwrap, provider/auth/model, CI or Git/remote operation was run. C remains uncompiled and the qualifier unexecuted. Pure Python counterexamples below used held source functions with all OS/runtime effects replaced by inert stubs; none invoked the actual qualifier or monitor.

## Exact binding

Manifest: `build/acp-decomp-effectiveness/callable-library-v3/static-worker-exec-001/manifest.json`. Independently rehashed all7 current source files, their byte-identical snapshots, all15 evidence files and the guard dependency. No mismatch. Approved plan `b670e2de4fe5fbda4b06872234319f9121887d600b2341473d233d051df34ceb` and its independent plan review `2b3ee62d3a7c184e9145837b90b714756bd370ef2e96080df48e92b278d58978` remain the design authority, not evidence of implementation qualification.

All source paths below are under `oracle/acp/callable-evaluator-v3/source/`:

| File | SHA256 |
| --- | --- |
| `worker_exec_monitor.c` | `746277d7d06a3a0a3ac660743d92d4c4eb7da48e1fb325c7464c4d7c94633e93` |
| `worker_exec_proof.py` | `53d28b293737877daa877cc144279c5018711dd0191de2de2903834e3213f84b` |
| `contracts/worker-exec-proof-schema.json` | `18f72edb31daef0b12bc06b38dcc5f996b237c81289f5f54005442d2a2d9c56c` |
| `toolchain-001/build_worker_monitor.py` | `f8841784ac45449f996cad3df97d9db30b98d03a89e76da85c282f4ab7d3ff79` |
| `tests/qualify_worker_exec.py` | `ce518217b75ba0db69958531d76bb13d5bea52f82ce89cd15847ad8d6cd8787c` |
| `tests/test_worker_exec_proof.py` | `5dca4e16dc8ce684723acc71ef0eef75d2be3a9317b40a8d129f05620a4745fa` |
| `tests/worker_exec_barrier_harness.c` | `2d7c4e90d7ecece6aa0f85f8214b73a3a294579afebc03e5db7ea739503b8d6e` |

## F1 — qualifier cleanup can acquire and kill an unrelated replacement PID

**Blocking safety defect.** `tests/qualify_worker_exec.py:402–405` reads a list from `cgroup.procs`, then calls `_kill_pid(_identity(pid))`. The identity used as kill authority is therefore obtained *after* the membership snapshot. `_kill_pid` at `:165–180` checks that newly supplied starttime around pidfd acquisition, but never establishes that the process now bound by that pidfd is in the retained scope. `_scope_pids` authenticates the cgroup object and its listed PIDs, not the later replacement process.

Concrete schedule: an owned PID appears in `cgroup.procs`; it exits; Linux reuses that PID outside the scope; `_identity(pid)` returns the replacement's starttime; `_kill_pid` opens the replacement pidfd, sees the same replacement starttime and sends SIGKILL. The PID-reuse check succeeds because its reference identity was manufactured too late. The separately retained root-launcher identity does not have this particular gap.

An inert execution of the held `_kill_pid` AST with stale scope PID12345 and an unrelated stable replacement start222 produced the mocked calls `pidfd_open(12345)`, `pidfd_send_signal(9,SIGKILL)`, `close(9)`. No scope-membership predicate was consulted, and no real pidfd or signal call occurred.

**Required correction:** bind scope-member kill authority to the acquired task, with verified retained owned-scope membership and identity around pidfd acquisition, or use an equivalently authenticated bounded cgroup-kill mechanism. Do not turn a stale PID list into a fresh unrelated process identity. Inability to establish ownership must fail cleanup, not signal that process. Add an inert stale-membership/PID-reuse counterexample proving no signal to the replacement, alongside the normal owned cleanup case. No host-wide process census is needed.

## F2 — named post-exec negatives pass without any worker exec evidence

**Blocking qualification defect.** The shared `run(...unknown=True)` predicate at `tests/qualify_worker_exec.py:497–500` requires only `not observed` plus scope admission and cleanup/final absence. Lines539–540 use it unchanged for `kill-monitor`, `stop-monitor`, `timeout`, `flood` and `descendant`. An unrelated failure before the worker exec satisfies every one of these named controls.

The pure counterexample extracted that exact held nested `run` function, replaced runtime/IO functions with inert stubs, and supplied:

```text
scopeAdmitted=true
cleanupVerified=true
kernelScope.finalAbsenceVerified=true
workerExecVerified=false
workerTerminationVerified=false
infrastructureFailure=true
reason=unrelated-pre-exec-wrapper-failure
stdout=b''; stderr=b''
```

All five controls reported `passed=true`. This is not an actual native result; it proves the source predicate accepts an insufficient result. Earlier positive controls do not establish that a later named fault was reached. The qualifier could claim the complete public control set while omitting precisely those executions. Missing/nonexecutable-target preflight refusal is a separate legitimate no-exec case and should remain separate.

**Required correction:** give these real post-exec negatives explicit per-control expectations. Require the authenticated initial worker-exec fact, the expected failure/termination/output/deadline facts appropriate to that control, and full owned cleanup. A generic setup error must fail them. Preserve partial exec facts on infrastructure unknown; do not turn them into a process-comparison result. Add pure tests showing each intended result passes and unrelated pre-exec failure fails. Keep missing/nonexecutable targets and explicit post-admission setup controls distinct.

## F3 — planned PID1 alias and descendant channel attacks are missing

**Blocking coverage omission in the new qualifier.** `WORKER_SOURCE`'s `attack` branch (`tests/qualify_worker_exec.py:57–66`) tests the worker's literalFD4 and the immediate monitor parent's FD4/ptrace/process_vm access. It does not inspect or try to acquire the visible PID1 report aliases/path authority. The `descendant` branch merely holds output open; it does not perform a channel attack. Both ordinary `protected-channel-attacks` and the surrogate release use the same limited `attack` action.

The approved plan's delayed-reaper qualification explicitly requires worker/descendant proc-FD reopen/write attempts after release. Its rationale is protection against another visible holder, including renumbered aliases and old-root/proc handles. The new source's complete-table barrier and held-stage inventories are valuable, but they do not substitute for those required native denial controls.

**Required correction:** extend only the public synthetic worker/qualifier controls to exercise the relevant PID1 alias/report/path reopening and a real descendant's monitor/reaper channel acquisition attempts, with correct saved monitor identity across the fork. Keep enumeration/attempt counts finite and distinguish allowed stdio/eventfd handles from forbidden report/path authority; do not blindly require every PID1 FD open to fail. Check exact denial/no-report-mutation outcomes and retain full cleanup. Do not add a production monitor bypass or run these native controls during the static correction. Add pure controls for their selection/result predicates and source bindings.

## F4 —1024-byte refusal happens after unbounded proof hashing

**Blocking bounded-work gap.** `worker_exec_proof.py:155` calls `hashlib.sha256(raw)` before the byte-length refusal at `:158`. Oversized bytes therefore consume work proportional to their entire length even though the parser promises the1024-byte proof bound. Caller-side bounded reads are still mandatory, but this pure public parser's own refusal should not hash arbitrary over-limit input first.

The inert one-over control supplied1025 bytes and replaced only SHA256 with a recording stub. The stub was called with1025 bytes before the function returned `status=unknown, reason=proof-byte-bound`. Larger existing byte objects follow the same path. No large allocation or native action was needed to demonstrate this ordering.

**Required correction:** check type/length before hashing, splitting or JSON decoding. Over-bound data can retain a null hash or an explicitly bounded diagnostic representation; do not fabricate the full-data SHA256 from a prefix. Add a one-over test whose hash/parser spies must remain uncalled, plus exact1024-byte-bound behavior. Preserve legitimate partial exec handling for admitted bounded input.

## Static monitor/protocol assessment retained

No separate blocking C control-flow finding was established in this review. This is an inspection result, not compile success or proof of the actual kernel capability:

- Protection (`worker_exec_monitor.c:314–360`) checks fixed soft/hardNOFILE64, retained report metadata/identity/write-append mode, dumpability0/readback, NNP, SIGCHLD disposition and stdio. It closes extra bootstrap FDs and checks the complete own table, including out-of-range inherited handles. The report is not worker stdout or a nonce-based authenticator.
- Visibility/barrier (`:166–313`) binds fresh procfs/localPID/parent/reaper image, user/mount/PID namespace relations and exact pre-worker process set. It compares every PID1 FD's device/inode to the report, blocks renamed aliases and nonallowlisted directory/namespace/control handles, retries disappeared entries by a new scan, and fails access/identity/bounds errors. Accepted PID1 FDs are matching stdio and at most one kernel eventfd. Stable identity is checked around scans and immediately before the sole worker fork. The source/closed-option one-way reaper argument remains necessary; this is not justified by a transient scan alone.
- The single worker fork (`:476`) is dominated by that barrier and target validation. The child closes allFDs>2 and checks FD4EBADF before PDEATHSIG/TRACEME/SIGSTOP and original absolute execve. The protected monitor remains separate. ELF-only/non-set-ID/no-file-capability target policy is retained; the separate Bash/metadata recipe cannot make scripts acceptable here.
- Exact initial child stop, enabled kernel EXEC event, retained target inode and closed child table precede exec proof (`:479–497`). Detach uses signal0; direct-child native wait status determines termination. EXITKILL is not claimed after detach. Failure kills/reaps only its retained direct child; outer owned-scope cleanup/deadline remains mandatory. No internal load/API/callback claim is emitted.
- Fixed buffers,4096-byte metadata,256 proc entries,64 FDs/66 FD-directory entries,100 scans/1-second barrier and512/1024 wire ceilings are explicit. C record writes guard snprintf lengths and partial-write failure. Actual EINTR/IO/LSM behavior and fixed source-to-binary correspondence remain native/source qualification obligations, not results of string assertions.
- The parser/schema enforce closed wire shapes, exact attempt/phase/target/reaper binding, local PID/bounded barrier tuple, exact EXEC wait word and raw terminal normalization. Normal exit139 differs from signal11; core-bit handling stays separate. Valid partial exec without terminal yields unknown/no exitCode. Unknown/trailing/duplicate/order/noncanonical/malformed records cannot yield completed termination. F4 concerns work performed before byte refusal, not a demonstrated forged verified termination.

## Provisioning, surrogate and evidence limits

The builder is import-inert, fixed-public-source and channel-free, and emits `provisioning-only-unqualified` with empty dependency inventory. It cannot self-promote to an accepted monitor pin. Complete A3 compiler/link/header/loader/runtime closure and runtime completion integration are separately owned and changing; they are not globally frozen by this seven-file manifest. Per-phase original argv/environment/path equivalence and the fresh containment route still need composed review.

The qualification-only PID1 harness has fixed release/hold/deny-trace modes, real FD4→7 duplication, directory8 and control/ack handles. Its H/A/B schedule closes4 first, then the remaining forbidden handles; the hold mode extends beyond the nominal barrier, and deny-trace uses a finite public seccomp launcher. The monitor itself has no test bypass or proof-forging mode. The qualifier separates this surrogate from normal bwrap controls, bounds retained scope/process/output/receipt work, and parses the protected report after cleanup. These sound design choices do not cure F1–F3. Timing/actual proc permission/topology/FD-forwarding and source compilation remain unobserved.

The source-author retained final result `10dce6ac53379b932672cf467f569e71b4d036c8beb0c39be2cb3c2652a96718` and log `dabb11ec975c97a575651a6cb149a5d3123910d4a59ebbc4b2fc65d1f69a6858` report33/33 pure tests, no skips/errors/failures and zero forbidden attempts, with actual fastjsonschema2.22.2. Their pins match. Earlier failed runner/arithmetic logs remain preserved, as do later27/32-test intermediate successes. The33 tests cover parser cases, an independent finite barrier model, source-order assertions, import/provisioning safety and qualifier selection. They do not execute either C file or prove the missing result predicates and ownership race; this review's bounded pure counterexamples cover those omissions without rerunning native or mutable composed dependencies.

**Final disposition: ITERATE.** Correct the four concrete findings in the held owned files, retain original manifest/history, freeze new exact bytes and obtain independent rereview. Then separately authorized C compilation/source checks, actual local/hosted primitive controls, full24 reference/control preflight, distinct implementation/acceptance reviews and final immutable sealing remain mandatory. No all-unknown shortcut or new acquisition/privilege/model/CI execution is authorized by this review.
