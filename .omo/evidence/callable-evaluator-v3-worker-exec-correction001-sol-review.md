# Independent worker-exec F1–F4 correction rereview

**ITERATE on the checkpoint: original F1–F4 are source-corrected; one remaining surrogate cleanup deadline defect (F5) must be corrected before qualifier clearance.** This is a narrow correction review with the unchanged C/harness/schema/builder bound to their earlier source assessment. It grants no compilation, native/proc/namespace execution, production authority or current composed approval. Runtime corrections remain separately pending.

## Exact checkpoint and preservation

Worktree `callable-evaluator-v2-evidence`; source paths below are relative to `oracle/acp/callable-evaluator-v3/source/`.

- Correction manifest `build/acp-decomp-effectiveness/callable-library-v3/static-worker-exec-correction-001/manifest.json`: **4c5a4bf9a4d4a10a76714eb2139f3082d02130afabf2a8ccef4c3cd3d388a31e**.
- Original manifest **bdf26b2f6b2b23be3158759f4bdf60bd0e398f2ed2caf566a592ca71d2693e2f** and original review `.omo/evidence/callable-evaluator-v3-worker-exec-source-sol-review.md` **316e47cf9beafa4ae1f7724be2b11c6fc6115e89ecdf649033b0ddc82d6043e3** independently hash-match. All seven historical snapshots and15 original evidence files remain unchanged. The historical guard was an observation, not a globally held dependency.
- All seven corrective source snapshots, all seven current owned sources and all19 corrective evidence entries independently match byte lengths/hashes. Exactly three Python files change; C monitor, C harness, wire schema and monitor builder are byte-identical to the original checkpoint.

| Frozen source | SHA256 | Change |
|---|---|---|
| worker_exec_monitor.c | `746277d7d06a3a0a3ac660743d92d4c4eb7da48e1fb325c7464c4d7c94633e93` | unchanged |
| worker_exec_proof.py | `bb7ec2289dbe9eeea2e19416fc1e166d75dbc888651f8ad5cc03a76f7c6dbc93` | corrected Python |
| contracts/worker-exec-proof-schema.json | `18f72edb31daef0b12bc06b38dcc5f996b237c81289f5f54005442d2a2d9c56c` | unchanged |
| tests/test_worker_exec_proof.py | `470d7248f5b93b64cee91b18c127d4a7eebd2ca5b8c3dec9ce17d0aa13dd3426` | corrected Python |
| toolchain-001/build_worker_monitor.py | `f8841784ac45449f996cad3df97d9db30b98d03a89e76da85c282f4ab7d3ff79` | unchanged |
| tests/qualify_worker_exec.py | `6975b1d6166154370b05dcf596500282adb9eb11ae390aa7da61ce7ac7ac08ec` | corrected Python |
| tests/worker_exec_barrier_harness.c | `2d7c4e90d7ecece6aa0f85f8214b73a3a294579afebc03e5db7ea739503b8d6e` | unchanged |

## Original finding disposition

### F1 — acquired cgroup object replaces stale member PID signals: corrected

Qualifier `_verify_scope:238–264` opens and retains the admitted cgroup directory FD, binds device/inode, checks exact unit/limits and gate membership/start. `_kill_scope:267–289` checks that retained object, opens cgroup.kill relative to it with no-follow, checks the interface and parent metadata, then writes only fixed `1\n`. The cleanup loop (`:529–533`) never converts a member PID into a fresh kill identity. The scope inventory is absence evidence only. Missing/denied/drifting kill interfaces fail without a scope-PID fallback.

The remaining `_kill_pid(root)` is for the separately recorded direct Popen child and is called only while process.poll is None; it is not fed scope enumerations. No claim of general numeric PID signal authority is introduced. Actual cgroup.kill/LSM/systemd support remains unrun.

Read actual inert controls at `test_worker_exec_proof:479–515`: normal acquired-object write, stale replacement PID with identity/pidfd/signal spies prohibited, changed retained directory refusing before open/write, and PermissionError refusing without per-PID fallback. Source assertions at517 are supplementary, not the sole proof of the changed function behavior.

### F2 — setup failure cannot satisfy named postexec faults: corrected

`_initial_exec:602–638` first gates raw type/1024-byte length, then closed runtime binding/pin validation, exact runtime phase/output caps, launcher/scope/cleanup/reap/absence facts, true exec, real bounded byte streams, file-identity/pin facts, and raw parser replay matching hash/status/reason/exact exec/terminal claims. Arbitrary authored dictionaries are still not a producer/channel authority: this qualifier consumes the actual runtime return/raised bounded_result under separately qualified closure.

`postexec_control_passed:653–701` has explicit named predicates, not a shared unknown-pass branch:

| Named fault | Required facts beyond authenticated initial exec and full owned cleanup |
|---|---|
| kill-monitor | Exact reach bytes; partial exec/missing terminal; nonzero wrapper; complete capture/wait; no timeout/overflow; no scored worker exit. |
| stop-monitor | Exact reach bytes; deadline; incomplete capture/wait; no overflow; no terminal; missing-terminal reason. |
| timeout | Exact reach bytes; deadline; incomplete capture/wait; no overflow; partial proof or exact SIGKILL terminal. |
| flood | Exact output cap and authored prefix/x payload; outputExceeded; no timeout; incomplete capture/wait; partial or explicitly allowed native kill/pipe-exit facts. |
| descendant | Exact real descendant-denial and reach bytes, native main exit0. Either fully completed0 with cleanup or deadline/incomplete capture with cleanup; setup failure cannot supply the required authenticated exec/terminal. |

All reject nonempty stderr, wrong phase/type/cap, malformed proof/claims and missing cleanup. Actual public fixture reach bytes are diagnostic evidence from a hash-bound authored worker; they never replace protected exec proof. The worker emits before attempting its fault, but failed kill/stop calls return an incompatible terminal so the named predicate refuses them.

The nested qualify.run actually selects these predicates with postexec=True (`:728–731,775–776`). Legitimate missing/nonexecutable target preflight refusal and post-admission setup surrogate controls remain separate. Read real pure fixtures/predicate mutations (`test_worker_exec_proof:408–438,525–567`), including all five prior pre-exec counterexamples, absent effect bytes, bad flags/caps, false exec, bad hash/pins, provisioning and descendant term/denial failure. These now causally exercise the predicates, rather than merely asserting source fragments.

### F3 — PID1 alias/root and actual descendant attacks: corrected source coverage

The authored public C string now contains a real bounded channel routine (`qualifier:66–119`), used by direct worker and forked descendant. It verifies the saved monitor start identity before/after, requires literal FD4 absent, attempts monitor report reopen/write, ptrace and process_vm; then examines all64 PID1 FD slots, including4/7/8. Matching stdio and at most one kernel eventfd are allowed. Unknown extra holders fail even if acquisition is denied; report aliases attempt real acquisition/write. PID1 root/proc reopening must deny or identify this same sandbox view, never an old host root/proc authority. It performs no host process census.

`descendant:121–139` forks an actual child, preserves the original monitor PID/start from before fork rather than replacing it with getppid, closes/renumbers its sync pipe away from4, runs the same attacks, emits its exact denial line and passes its status back before parent exit. The hold variant deliberately retains output after that handshake. Parent/child wait/pipe paths remain inside outer finite phase/scope limits. Direct and descendant controls use `channel_control_passed:642–651`: full runtime completion, reparsed canonical protected report, native exit0, exact denial bytes and empty stderr. Any report mutation or absent denial fails; forged stdout cannot substitute for protected raw proof.

Both actual named production-route controls are selected (`:758–761`), and surrogate release now launches descendant-channel (`:403–407`) and requires its exact denial bytes plus verified exit0/released barrier (`:569–571`). The monitor C has no new test bypass. Pure controls (`test_worker_exec_proof:569–594`) exercise valid/mutated/missing-proof/denial predicates and source selection; they do not run C, forks or proc attacks. Actual denial, identity visibility, synchronization and report nonmutation remain native gates.

### F4 — bounded refusal precedes hashing: corrected

`worker_exec_proof.parse_proof:148–158` validates trusted expectations, then type and1024-byte bound before hashing/splitting/JSON; over-bound input returns null proofSha256. Exact bounded input retains its complete hash, not a prefix hash. Qualifier `_initial_exec:608–611` likewise rejects over-bound raw bytes before immutable binding hash work. Existing normal139/SIGSEGV/partial exec semantics and wire schema remain unchanged.

Read real one-over/exact-cap hash/parser spies and qualifier binding-validation spy at `test_worker_exec_proof:448–477`: the1025-byte path invokes neither hash nor record parse; malformed exact1024-byte input receives only admitted bounded hash work. No large allocation or new execution was performed by this reviewer.

## Remaining F5 — surrogate can claim cleanup after its final verification end

**P2, qualifier `surrogate:527–542`.** `process.wait` may return successfully after kill_deadline; the code does not recheck that deadline before granting a fresh5-second verification interval. More decisively, verification checks monotonic time only before `_scope_pids`, then sets cleanup=True immediately after an empty inventory. If that inventory returns after absence's end, the result still claims verified cleanup and can set passed=True (`:592`) with valid surrogate proof/release facts. There is no final monotonic sample after the observation. This is the same class of observation bug as the separate pending runtime finding, in independent qualifier code; a runtime-only fix cannot repair it.

The contract describes distinct bounded cleanup wait and verification ceilings. A timeout argument and a pre-call clock test do not prove successful observation occurred within those ceilings. The source defect is a false timing qualification, not a claim that a real blocked scan or native leak occurred here.

Smallest correction: preserve the stage end(s), reject late wait success, and sample the verification end again after the final empty inventory and all cleanup proof observations before recording cleanup=True. A missed bound stays failed/unknown and cannot be upgraded by subsequent late teardown. Keep existing5+5 limits, exact ownership and no fallback signals. Preserve primary failure and secondary cleanup facts.

Finite pure seams: mock successful process.wait to advance a fake monotonic clock beyond kill_deadline, and independently mock `_scope_pids` to return empty while advancing beyond the verification end. Retain an otherwise valid released/exit0/denial surrogate proof: the current predicate can pass; corrected source must keep cleanup/passed false while preserving proof/bytes. This requires no C compilation, process, cgroup or sleep. The47 retained tests do not exercise surrogate cleanup timing. Do not release native controls on the strength of the four corrected findings while F5 remains.

## Evidence and dependency scope

Retained `result-004.json` **fd519aecce6defa96e6caf0bc409c78893dc9f24178776778bb3faa0ecd120a0**, log **ba9d84142fa94e909760844106edc022c4dce13b947270384b9d145af8b8d859** and runner **68b23cb21a8018f9e85243ec8285fd2e1a6a5a341e6248bb8e0641b96703bb8c** match. Log records47/47 pure tests, zero failures/errors/skips and zero forbidden attempts; fastjsonschema2.22.2 is explicit. Earlier45/46 runs remain historical, not substitutes for final evidence. No test was rerun here.

The final runner snapshots these three dependencies before/after as exact bytes; receipt maps agree and each retained dependency snapshot matches. Owned source hashes are bound by the subsequent held manifest/current-snapshot comparison; the result file does not separately record before/after hashes of all seven owned files, so this review does not invent that stronger test provenance claim.

| Exact tested dependency | SHA256 |
|---|---|
| bounded_runtime.py | `122bbf6cc0c64dd3286cd1b685f00a53429e58dd6ba93249bb33c9b2c91bb610` |
| build_contract.py | `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85` |
| tests/run_static_tests.py | `30bea0fb1ff8cbc588189504b8a3c220d66dfeff8a525110611620ef13e18efd` |

All seven current owned sources and these three dependencies still match at the review observation; no drift within these ten paths was observed. Other evaluator/runtime/A1/A3 state is not globally frozen or qualified by this checkpoint. In particular the separately retained runtime review remains ITERATE for its own two findings, regardless of matching dependency bytes. The qualifier report **65129d48fbe3d5a94d9205e3f143cbcd7e19a7a0003712ec139cfbed1221f41b** is a source-author handoff, not approval.

Original monitor/protocol static assessment remains scoped to unchanged pins. C remains uncompiled; harness/worker C remains unexecuted. Public native local/hosted capability controls, source-to-binary binding, all24 private scenario/control/mutant preflight, distinct acceptance review and immutable sealing remain root's separately authorized gates. No parent issue or native capability is marked complete.

## Disposition

Original F1–F4 source corrections accepted within this exact freeze; checkpoint ITERATE for F5. Preserve original review/history and correct only the narrowly owned surrogate timing path plus finite pure controls under root coordination. No source/test/compiler/C/JVM/native/proc/auth/model/Git/remote/CI/policy action or descendant was run; only read/hash inspection and this additive report were performed. All prior A1 and worker-exec reviews remain unchanged.
