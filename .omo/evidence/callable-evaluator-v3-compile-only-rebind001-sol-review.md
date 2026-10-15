# Independent compile-only rebind001 setup review

**ITERATE: one exact post-waitid wall observation gap remains. Do not release this001 controller for compilation.** The fixed workload, ownership and unqualified-evidence boundaries below are otherwise preserved by this source review. Root will coordinate a minimal additive correction and review before execution. No C compilation or native action was performed here.

## Frozen input binding

Worktree `callable-evaluator-v2-evidence`; setup prefix `build/acp-decomp-effectiveness/callable-library-v3/compile-only-rebind-001/`.

| Input | SHA256 |
|---|---|
| manifest.json | `8586b8d8cf972828cfc5029626f2202757f9168b886c4153af7868f468805f43` |
| setup.json | `c3ee5efe664e26430ac680b48ff5d6f63b4315a2457f6adf16c2ef726bcd5ae6` |
| compile_fixed_public.py | `3180bfb53da994bdbbbccbc05846b29033eb6f182bbb2a8bc00d5904af5112c0` |
| launch.json | `7b8c0b272d32b9eac3b6cea66c371ad212f8cf20daffa311aa8e051d78dcd3e2` |
| test_controller.py | `a1eb406f25d9651c53d89f3e11c43ad537e4e5953670f01854104dd3ef42ce2e` |
| result.json | `dab1cc61062a39a32814751172c72c78b97811d46f09e6ad1ac0531f6f07feec` |
| tests-002.log | `b0a00746e59d1250072f8997f3d77e0b7841ea79a7ea9dc58571757b795a2f16` |

Independently recomputed all12 manifest-listed file lengths/hashes and all seven current public source hashes: all match. Accepted source manifest **e34367e3b80b341387720bdb1e736307c8dbd6a2568755ba9ee0a72e3e2f9dc8** and production runtime **604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07** also match. Old compilation setup **0066f5f6f6b2ec7556ddda567bb87878c3182245bfc39aba472e86b24dbdc62c** remains unchanged. C inputs are unchanged from their accepted source checkpoint. Current output/ and fixed monitor manifest were absent when inspected; that is not proof of a future execution outcome.

## Required correction — late successful WNOWAIT observation can pass the wall bound

**P2, frozen compile_fixed_public.run_stage:103–108.** Source samples the stage wall clock after selector/read processing at103, then calls child_unreaped(process) at104. If that non-reaping waitid observation returns successfully after end and reports the child exited, the branch at107 immediately sets capture=True and breaks without a post-waitid deadline sample. Cleanup then starts its separate5+5 stages. With recorded exit0 and otherwise clean teardown, passed at165–166 can be true even though the final phase observation occurred after its80/30-second stage wall end.

WNOWAIT/WNOHANG avoids waiting for a still-running child and preserves signal authority; it does not prove the user thread observed a successful return before its wall end. Scheduling or a delayed observation can cross that end. This finding is source control flow, not a real waitid experiment or claim of a kernel hang.

Smallest fix: sample the same fixed stage end immediately after the successful child_unreaped call and before capture/admission/break. At/late observation must record the existing wall failure, keep capture incomplete and passed false, then perform the same owned cleanup without new execution time, retry or signal authority. Preserve the original child ownership rules and original/cleanup failure facts.

Finite inert control: extend run_fake's mocked os.waitid observation to advance the fake clock past the fixed stage end while returning the exact owned exited-child identity. The held001 path can incorrectly pass; corrected source must refuse, retain captured bytes and still send at most the one pre-reap owned group kill followed by one wait. Include equal/just-after end and timely control. Existing test_absolute_wall_checked_after_select delays selector only, so its11-pass result does not cover this post-observation gap.

## Fixed commands and repository-local side effects

fixed_stages:30–44 exactly selects two public-source compile stages, with no caller-selected argv, source or workload:

1. Fixed `/usr/bin/python3 -I -B -X pycache_prefix=<output>/cache` invokes accepted build_worker_monitor.py with fixed output/monitor/worker_exec_monitor and monitor-build.json. That unchanged builder's sole compiler route is accepted channel-free provision_worker_monitor, preserving fixed GCC C11/O2/Wall/Wextra/Werror and RELRO/NOW/noexecstack flags for worker_exec_monitor.c.
2. Fixed `/usr/bin/gcc -D_GNU_SOURCE -std=c11 -O2 -Wall -Wextra -Werror` compiles only worker_exec_barrier_harness.c to output/harness/barrier-harness.

No output binary or qualifier is invoked. Launch.json explicitly uses env -i and Python isolation/private pycache; HOME/TMPDIR/TMP/TEMP/cache, output directories and receipts stay inside this worktree. Child compiler environment is explicit. Inner accepted provisioning retains its authored PATH/LANG/LC_ALL/TMPDIR and existing managed-scope policy rather than inheriting an invented aggregate qualification from the outer environment.

Outer walls are80/30 seconds, per-stream caps1MiB/64KiB; per-process CPU30, AS2GiB, NOFILE64, FSIZE16MiB and CORE0 are explicit. Inner helper-build60s/tasks32/memory512MiB/swap0/cleanup5+5 remain separate. There is no aggregate harness CPU/memory/tasks or hard aggregate disk quota claim. The output diagnostic inventory caps128 nodes/depth8/64MiB, receipt writes cap5MiB, and output/free-space/type failures refuse rather than erase evidence.

The fixed output directory is created exclusively before any stage and then retained; any existing output or fixed monitor manifest refuses reentry. This acts as the no-retry attempt marker after workload admission. There is no deletion, retry loop or alternate output generation in the controller. Source-reviewed builder side effects under public-source exec-proof-receipts and toolchain-001/worker-exec-monitor.json are disclosed separately from output inventory; outer inventory is not falsely said to contain those paths.

## Owned signalling, cleanup and inner-scope limits

Controller resets SIGCHLD to default before Popen and is the sole single-threaded reaper. run_stage uses a new private session/group and does not call Popen.poll. child_unreaped uses WEXITED|WNOHANG|WNOWAIT on that direct child. It revalidates non-reaping ownership and exact PGID/SID before its only SIGKILL. An unreaped child reserves the leader PID/group identity; ECHILD or ambiguous ownership refuses destructive signalling. The one group kill is before the first wait/reap; all post-reap operations are signal0 absence queries, never another destructive signal. Late/failed/ambiguous reap cannot restore kill authority.

Wait cleanup has one absolute5-second end, passes only remaining time and refuses a late successful reap. Only a timely reap starts a separate fixed5-second verification end. Group-absence observations and final stream/selector closes are sampled against it. Unknown/late cleanup cannot satisfy processGroupCleanupVerified/passed; raw captured bytes and primary/cleanup failures are separate facts. These paths match the intended finite outer ownership design, subject to the stage observation defect above and actual unrun kernel behavior.

Outer private-group absence cannot prove termination of monitor-builder's separately managed inner systemd scope. main checks the accepted unqualified inner provisioning receipt after successful outer execution and requires its cleanup/final scope absence facts before proceeding. If the outer stage fails, result explicitly keeps monitor inner scope unverified unless an accepted inner receipt is retained; no group-only claim upgrades it. This is a compile-only input/output exercise, not worker proof or effective runtime closure.

## Finite pin observations and retained controls

Saved setup contains58 observed file pins plus51 explicit absent candidates=109, below the declared128 candidate bound. Payload is66,131,451 bytes per recorded pass; largest pin is47,315,560-byte cc1, below64MiB/file. verify checks fixed setup/controller/source/runtime/stages/limits, pin count/summed bytes and exact current pin equality plus absence candidates; at most five verification passes occur in the fixed successful two-stage path. Safe nonblocking/no-follow descriptor readers validate regular type/size before chunked bounded payload reads. This review inspected saved pin metadata and code; it did not independently hash host compiler/header/runtime files or launch discovery.

These are explicit file observations, not authenticated complete header search/effective include/Python import/link/loader selection closure. Setup/README and final result expressly withhold completeToolchainClosureAuthority, nativeQualifierExecuted, candidateAcceptanceAuthority and aggregateHarnessCgroupQualified. A successful compile would remain provisioning-only-unqualified with empty monitor dependencies; no final seal/accepted preparation follows.

Retained tests-002.log records11 inert tests OK; result states zero compiler launches/produced-binary executions/real native actions. Source inspection confirms process/waitid/PGID/SID/signals/selector/clocks are mocked, real process/native operations are guarded, and no compile entry is invoked by test import. Controls cover pre-reap kill ordering, ownership loss, ambiguous/late reap, late absence/close, stream bound, selector late return, fixed workload and pre-read JSON bounds. They prove these branch behaviors only. No tests were rerun here, and the post-waitid late success still requires its new control.

## Disposition

ITERATE for the single103–108 stage-clock defect; preserve this manifest/setup/controller/launch and11-control evidence. Root should bind and review a minimal additive corrected generation before execution. This review grants no compiler/native release and makes no claim C compiled, actual namespace/cgroup/proc behavior qualified or full24 acceptance completed.

Only source/evidence/hash inspection and this additive report were performed. No tests, actual compiler/C/JVM/native/proc/process/CLI/policy/Git/remote/auth/model/CI action, source edits, attempt cleanup or descendants. Earlier reviews remain unchanged.
