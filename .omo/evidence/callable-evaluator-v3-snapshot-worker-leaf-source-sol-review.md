# Independent Sol review: evaluator snapshot and worker-leaf lifecycle

**Verdict: CLEAR for the exact held evaluator/test source pair, subject to the explicit trusted runtime cleanup seam below.** No blocking finding within this narrow correction. This is not a composed-runtime freeze, native qualification, filesystem-boundary qualification or execution release.

## Exact review inputs

Worktree: `/home/june/decomp_thing/.claude/worktrees/callable-evaluator-v2-evidence`.

| Artifact | SHA256 |
|---|---|
| `build/evaluator-snapshot-leaf-correction/source-freeze.json` | `20f7a32aa73a7cf063e2321bb92ef94be482f376dad8a54e86bc1547d31823de` |
| `oracle/acp/callable-evaluator-v3/source/evaluate_candidate_v3.py` | `6c326c36bd7aead6e1702a262e39dc585226f87cd4734fb9ee67f6bc409fdad6` |
| New `source/tests/test_candidate_leaf_lifecycle.py` | `834956ebe2ec6229942161e3c86cb7d3d36a1c78be98cb0f2d867d6e3418035f` |

Both source sizes/hashes and freeze hash were checked; syntax was parsed only. Inspected the full affected evaluator flow, current probe/export receipt shapes, tests and retained eight-test log. No evaluator/test/native/helper/compiler/qualifier was run and no source, runtime, pin/profile, auth/model, Git or remote state was changed. Only this additive review is written. The runtime is actively owned/edited elsewhere and is not implicitly pinned or approved by this receipt.

## Checks and producer coverage

- **Consumed source identity:** `_evaluate:484–490` reads the candidate through bounded `read_regular`, validates those bytes and writes them to fresh invocation output `candidate-source.c`, then passes that snapshot to `compile_sequence`. Report identity at551 is `hashlib.sha256(raw)`, not a later reopening of the mutable input path. The original path can change after snapshot capture without changing the reported identity of this evaluation. Existing isolated-leaf input copying and RO input mounts remain. This relies on the existing trusted private output namespace; it does not introduce authority to rewrite the controller snapshot.
- **Invocation ownership:** `WorkerLeaves.own` retains an O_DIRECTORY/O_NOFOLLOW/CLOEXEC FD and initial device/inode for a freshly created leaf. `new_worker_leaf` continues to require the canonical private owned parent and creates a new UUID child. No old UUID directory is discovered or adopted. ContextVar scopes nested invocations independently and resets the previous context before final cleanup.
- **All evaluator producers:** `run:242–257` tracks every compiler, GCC assertion, expected-preprocess and scenario runtime call. Both declaration probes at496/500 are explicitly wrapped. Export inspection at532 is wrapped and both `execution` and `sectionsExecution` receipts participate when returned. Current export implementation can return only the first receipt when it stops before launching the second; if it proceeds to the second, first-producer complete execution has already been required. Exceptions without positive cleanup leave safety false; a bounded-result exception can establish cleanup independently of process/API success.
- **Sticky uncertainty:** `call:284–292` sets false before invoking a producer and combines its evidence with prior safety by AND. Missing/false cleanup evidence, a later unknown, or an unknown exception cannot be overwritten by a later clean result. Passing semantic status is not deletion authority. Conversely a failed worker can be reclaimed only after affirmative cleanup facts.
- **Consumption order:** `evaluate:461–468` closes the scope only after `_evaluate` has returned its completed report or abandoned evaluation through an exception. Compile outputs remain present for downstream copy/probe/assertion/inspection/runtime consumption; declaration/inspection/raw process evidence and report are retained before reclamation. No individual producer return triggers deletion. Leaves with no attempted producer contain controller-only work; leaves with unknown producer cleanup are retained.
- **Bounded, non-following reclamation:** `close:303–331` checks the held leaf against its pathname identity, enumerates the held directory itself with one fresh FD, admits at most256 flat entries (one extra observation detects overflow), and refuses any directory/special entry before unlinking. Entry stats and unlinks use the held dirfd with no symlink following; symlink targets/canaries are not traversed. Entry identity is checked again before unlink; the named leaf identity is checked again before rmdir. Replaced named leaves and unexpected subtrees are retained. Expected OS/value failures are secondary and held FDs are closed even on refusal, preserving the primary evaluation outcome.

## Required runtime and ownership seam

Reclamation trusts `_cleanup_proven:265–269`: exact dict with `cleanupVerified`, `finalAbsenceVerified`, `rootReaped`, `scopeVerified`, `scopeAdmitted` all literally True, plus dict `kernelScope.finalAbsenceVerified=True`. These must be affirmative facts from the trusted runtime for that producer's actual admitted scope and acquired launcher, including all relevant descendants and within its cleanup deadlines. Worker stdout, numeric exit code, an unrelated attempt, missing scope facts or launcher-only absence cannot mint them. Worker-exec/termination or API success are not required for deletion when cleanup itself is positively proven.

The active runtime owner was notified of this dependency. Final composed freeze/integration must bind the final runtime/gate and preserve these meanings for every producer. This review does not approve a concurrently mutable implementation or infer those facts from the eight synthetic fixtures.

FD-relative operations prevent following symlink targets, while pathname/entry replacement checks are observations, not an atomic arbitrary-filesystem replacement barrier. Their authorized operating context remains the private invocation-owned parent plus verified stopped producers; no live unknown worker or independent untrusted mutator may still own that leaf. The code explicitly retains unknown cleanup and does not claim a new production filesystem boundary. No recursive cleanup or reclamation of other invocations is authorized here.

## Retained controls and limitations

`build/evaluator-snapshot-leaf-correction/tests.log` records8 passing pure controls: consumed-snapshot hash despite original replacement; verified flat reclaim/external symlink canary; missing/false cleanup flags; sticky unknown; primary exception preservation; positively proven exception cleanup; unknown subtree/replaced leaf retention; and both inspection producer receipts. Source review additionally covers all actual call sites and final consumption ordering. Tests were not rerun, nor treated as native/race/filesystem qualification.

This scope deliberately preserves unexpected trees, over-limit entries, replaced leaves and unknown cleanup rather than recursively deleting them. Final static test inventory/source-copy integration remains coordinator-owned. Any later producer added to these leaves must participate in the same sticky accounting; final actual native qualification, full24 controls and immutable generation/seal gates remain separate.
