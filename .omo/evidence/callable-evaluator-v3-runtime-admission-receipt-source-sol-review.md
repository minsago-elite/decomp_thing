# Independent Sol review: unconditional runtime admission and receipt lifecycle

**Verdict: CLEAR for the exact frozen three-file correction.** No blocking finding within the reviewed policy/refusal and owned-receipt lifecycle scope. This is static source clearance, not native/runtime qualification or execution release.

## Exact checkpoint

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Input | SHA256 |
|---|---|
| `build/runtime-admission-receipt-correction-001/source-freeze.json` | `ea4b7525d763790897bb5f5bd921ab51c20ae059fc3095d74940e426e99a3f75` |
| `source/bounded_runtime.py` | `038379a2840db54fedfc872de04c637980b387f5ad0b561772abf00f3f5d14fe` |
| `source/scope_gate.py` | `60d2ee157cd7b4a04124c22279a4c219a93c0f2b510f72ce2bfbd759ffba190a` |
| `source/tests/test_runtime_worker_proof.py` | `f766b6d5c426c533b584b4cabadf5072ccf9e6cc37cccba02e5c281b8e21e45d` |

Source prefixes are `oracle/acp/callable-evaluator-v3/`. All owned-source sizes/hashes, after snapshots and freeze-listed evidence hashes were rechecked. Inspected exact before/after diffs, full affected functions and retained19-control results. AST comparison/syntax inspection only; no target/test/gate, signals/proc/native/compiler/qualifier, auth/model, acquisition, Git or remote execution. Only this additive review is written. Root's static-runner MODULES addition is coordinator-owned and excluded from this source clearance.

## Unconditional policy guards

All37 production Assert nodes are removed:7 runtime and30 gate. Independently compared all30 old gate predicate ASTs with the operands of current unconditional negated refusals; every predicate is preserved. Runtime's seven checks were inspected manually: private directory/JSON containment; matching gate PID/start; unified cgroup-record shape; scope path/unit; kernel limits; complete admission write. The De Morgan/inequality rewrites preserve failure conditions. No optimization flag can remove these new if/raise guards.

Gate validation still precedes admission/report access: isolated/no-bytecode interpreter and exact cache prefix, private owned directory identity, exact config/mode/argv, narrow fixed-source provisioning recipe, NOFILE/capabilities/PID namespace, complete gate write, exact admission bytes, then private empty single-link report device/inode and explicit inheritable FD4. Existing descriptor count/numeric bounds and closing policy remain. No new compiler/source-selection bypass, profile limit increase or authority upgrade appears.

## Receipt ownership, consumption and closure

`_create_worker_receipt:383–402` adds original receipt-root device/inode; `_prepare_launch:807–810` binds the newly created empty Python-cache identity. These are private invocation facts, not discovered prior-directory authority.

`_reclaim_worker_receipt:405–532` requires the report FD already closed and affirmative cleanup/root-reaped/final-absence plus kernel-scope final absence. Normal workers additionally require the actual complete execution/proof predicate, exact attempt UUID and report device/inode matching the consumed receipt. The sole channel-free provisioning case requires its complete admitted controller/capture/wait/cleanup result without inventing worker proof. Unknown/partial/unconsumed state returns retention before deletion.

The path is restricted to the exact root and32-hex attempt leaf. O_DIRECTORY/O_NOFOLLOW retained root/attempt/cache FDs are checked against original identities and private uid/mode. Enumeration admits only the fixed4/5-entry layout and stops on the first unexpected entry. Non-cache entries must be private owned regular single-link files; symlinks and arbitrary subtrees refuse. Consumed report identity, size<=1024 and exact in-memory raw bytes are rechecked through a bounded nonblocking FD; post-read identity must match. Cache must have its original identity and be empty. No recursive deletion or symlink target following occurs.

All entries are prevalidated before deletion starts. Each unlink is relative to the held attempt FD after fresh directory/entry checks; cache and attempt rmdir also recheck identities. Replacement, unexpected content, failed close or deletion produces refusal/retention instead of blind cleanup. A late OS failure may leave a partial fixed-layout removal: `removedEntries` records that fact; the code does not claim rollback, and in-memory proof/behavior bytes remain retained. Private ownership and stopped producers remain required; these checks are not a new atomic arbitrary-filesystem mutation boundary.

## Ordering and evaluator-leaf seam

`_run_scoped:1073–1205` preserves acquired-handle process cleanup, root reap and separate bounded final absence verification before proof handling. Source/raw proof is consumed into result, streams and owned launcher/scope handles close, then the report FD closes and is marked None before reclamation. `public_result` preserves captured stdout/stderr/proof bytes while excluding the private `_receiptCleanup` field; it does not expose a new public-schema authority field.

Reclamation refusal is secondary infrastructure failure. Without an existing primary error it raises a bounded-result exception; with a primary error it attaches receiptCleanup rather than replacing that primary. Existing process-cleanup failures still refuse. Phase time is rechecked after reclamation, so late metadata cleanup cannot create a passed process. No receipt is reclaimed merely from exit0, a pathname, an unknown scope, or an unconsumed proof.

For the previously reviewed evaluator's worker-leaf seam, `cleanupVerified`, `rootReaped`, `finalAbsenceVerified`, `scopeVerified`, `scopeAdmitted` and kernel-scope final absence retain their worker/process meaning. Receipt-filesystem failure can leave those already established absence facts true while infrastructureFailure makes process acceptance unknown. The evaluator may then safely reclaim its separate worker leaf after consumption; it must not mistake that for successful receipt-directory reclamation. Unknown worker absence or controller/report close failure prevents its affirmative cleanup gate. No public receipt claim is minted from the private reclaimer.

## Evidence and remaining gates

Retained focused004 records19 pure synthetic tests, zero failures/errors/skips/forbidden attempts. Controls include optimize=2 admission/kernel identity/limit/short-write refusals; optimized gate policy and FD handoff; unchanged recipe/source bounds; actual proof consumption/closed-FD ordering with mocked launch; complete provisioning cleanup; unknown/open/unconsumed retention; replaced directories/proof/symlink/cache and unexpected payload refusal; deletion errors; primary failure preservation; and prior stale-PID/acquired-handle controls. Earlier failed/intermediate logs remain evidence, not final pass claims. No tests were rerun in this review.

These fixtures establish branch behavior only. They do not qualify actual kernel/namespace/loader execution, exhaustive filesystem races, full24 positives/mutants, complete actual machine-input closure, hosted gates or final seal. Old production-native receipts do not qualify these new runtime/gate bytes. Final composed source/dependency/runner freeze and root-controlled verification remain required; scope does not include the coordinator's runner edit or unrelated source.
