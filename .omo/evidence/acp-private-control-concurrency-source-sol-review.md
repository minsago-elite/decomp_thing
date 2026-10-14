# Independent private-control concurrency source review (#1508)

Status: CLEAR for the exact final standalone source and focused evidence below. Historical ITERATE findings are retained and superseded by the final re-review.

Reviewed AGENTS.md, approved plan SHA256 `59b20924924ca96edfe838fb3977854c4b518a70fce3e683bee2a2502abd525a`, and its independent plan review. Read-only inspection of source/test diff; no source, Git, GitHub, provider, model, authentication or CI operations performed. Only this review artifact was written.

Exact inspected files:
- LinuxBubblewrapBoundary.kt SHA256 `87ae728735c8a6a62567d2be9b369030ca41e32416acfb9d3f3b6a41f3baf280`.
- LinuxBubblewrapBoundaryTest.kt SHA256 `8e7fa600a920d98d25203d0a1f9599f4979f9e517e43db4d10ff06e84117ff5d`.
- AcpAgentHarnessTest.kt SHA256 `e53470f516de3c82d1f26021b72893b0087d25d89946fa9a1ef013f0588548c4`.

## Finding requiring correction

The diff removes @Synchronized from PinnedPrivateTree.deleteAndProve (around line 2556), although unlinkExactRoot remains synchronized on the same object. This removes prior mutual exclusion over currentName, deleted, cleanupFailure and descriptor-bound tree mutation. The approved plan calls for removing the PinnedControlDirectory method-monitor inversion; its rationale does not extend to this separate tree method, whose requireCurrentTree/parent.requireChildParent path does not acquire the registry monitor. Source owner confirmed this was an accidental broad textual edit and will restore it. This source hash is not cleared.

## Core source inspection

No additional blocking source defect found in the reviewed registry/scope logic. PinnedControlDirectory objects provide exact record identity; LIVE/PROVED_DELETED transitions are registry guarded, and a fresh Any token avoids numeric epoch wrap/reuse. Scope maps use exact objects, resolve owner exemption once to an admitted record, retain unchanged identities, and close only newly acquired entries on failed refresh. Proof transition follows quarantine unlink, zero link count and both name absence checks. Failed cleanup remains LIVE; prior failure survives later exact remediation.

Scope admission owns root and mount descriptors before publication; capacity is checked before allocation. Creation checks active root leases before mkdir. Shared recursive physical coverage authenticates descendant mount roots against exact mount IDs and translates namespace paths through mountinfo. Source-root relocation/replacement fails authentication. Scope checkpoint and descriptor overlap checks use one registry transaction. Fast eligibility is recomputed on refresh; cross-mount same-filesystem controls disable the shortcut; nested source mounts disable it. Slow checks use physical coordinates and both admitted/current locations. Independent mount events remain sticky and finish retains complete mount table comparison.

Registry poison is a single bounded sticky fail-closed bit and gates manifest, root/descriptor authority, staging, and creation admission. It does not claim successful cleanup/remediation of an unpinned object. Persistent scope ownership is bounded at 128*(128+2)=16,640 descriptors, plus existing registry/staging ownership; refresh opens only new identities, at most 128 in the serialized transaction. Close detaches membership under registry lock and releases descriptors without cancellation. LinuxDescriptor.close is terminal and nonthrowing, preserving cleanup iteration. No callback/process wait/hash/copy is newly enclosed in a whole-invocation lock and no timeout increase appears in the diff.

## Meaning of current regressions and remaining evidence

The new deterministic native-independent test actually pauses two manifest threads after scope admission at readIdentity outside the registry lock. While both remain held, it deletes a retained control, creates/deletes 140 real historical controls, and leaves one new LIVE control for refresh. It then requires exact digest equality and baseline FD recovery. It separately proves replacement preservation, failed cleanup protection and prior failure provenance, 128 scope admission, pre-allocation scope refusal, lease denial before mkdir, and idempotent close. These are substantive controls, not aggregate counts.

The callback regression adds an explicit release latch and records two simultaneously active callbacks before release; both futures must remain unfinished. It retains successful receipt assertions, authorized source modifications, forbidden canary integrity, verified cleanup and stopped processes. This source structure proves the intended overlap if the exact final test passes.

Current additions do not yet demonstrate the approved deterministic publication/quarantine/unlink transaction seams, nested-mount root lease admission in both orders, refresh/partial-create failure injection, or record ABA behavior. Existing generic bind/host staging and hostile-mode/mount tests do not by themselves qualify those new scope behaviors. Source owner confirmed these gaps and is adding targeted controls. Focused results must bind to the final hashes after the synchronization correction and any tests. A prior passing harness XML observed during review is not substituted for the pending final evidence.

The retained exact 9cfc cause remains separate from the earlier fae lower cause, which remains UNKNOWN. This review does not qualify DNS B composition, provider/authentication behavior, hosted contract, parent #238, or production acceptance.


## Final re-review: CLEAR

The tree synchronization finding is resolved: PinnedPrivateTree.deleteAndProve again has @Synchronized, matching unlinkExactRoot. Re-reviewed the corrected production diff and added deterministic seams. No blocking source finding remains at these exact SHA256 hashes:

- LinuxBubblewrapBoundary.kt: `bf0075a4178db1f2ed02ecf770e581a69482ea01f7cd43b42a053cbee79e6868`.
- LinuxBubblewrapBoundaryTest.kt: `62484cddbad86f8daa9d9d2e1afaea734b92045ed8bf105085ae51647bd72305`.
- AcpAgentHarnessTest.kt: `e53470f516de3c82d1f26021b72893b0087d25d89946fa9a1ef013f0588548c4`.

Production changes since the earlier inspected freeze are the restored tree monitor and test observation/UUID seams. Observer and UUID fields are private, null by default, and introduce no runtime configuration or public mutation authority. The internal stage enum alone cannot install an observer. Observation points are inside actual registry transactions and do not replace real syscall/lifecycle work. The post-unlink observation precedes transition; injected failure there leaves LIVE protection rather than manufacturing deletion proof. The creation pre-pin injection conservatively poisons subsequent admission. Fixed UUID is a UUID object rather than arbitrary pathname input. Test cleanup resets both fields.

Inspected final deterministic tests and their assertions. Publication, pre-quarantine and post-unlink pauses assert registry ownership, observe a peer checkpoint BLOCKED, then release and demand success. Refresh injects failure on the second addition after the first actual descriptor retention, requires exact FD baseline and then successful retry. Same-name A deletion/B recreation verifies distinct record objects and that B's mode mutation still fails a checkpoint. The nonreused Any epoch makes a numeric wrap seam inapplicable. Tests cover 128 active scopes and controls, refusal with no FD growth, renamed/replaced root admission failure, and cancellation-safe scope close. An isolated subprocess lowers real RLIMIT_NOFILE to force partial scope admission failure and proves FD recovery; it then injects unpinned mkdir failure and verifies the unresolved entry remains while manifest/path/descriptor/new-control admission all fail.

Native tests use actual same-filesystem bind mounts and cross-filesystem tmpfs nested mounts. Scope-first registration is refused through original and nested alias parents before mkdir; control-first scope/hash admission is refused with FD recovery. Persistent same-filesystem cross-vfsmount addition refreshes the live set and explicitly asserts fast=false; cross-filesystem positive admission also succeeds. Existing hostile mode, replacement, retained relocation, mount restore, bind rename, cancellation, 4096-file scale and 64MiB integrity controls remain substantive. Partial-copy cancellation independently proves cleanup, preserving a negative cleanup test after legitimate churn became positive.

Final retained XML was read and its hashes independently recomputed:

- `.omo/evidence/acp-private-control-concurrency/final-focused-boundary-tests.xml`: `9623c11a649d6c8ea84bc0b3c2c2fff9c4cc62c15e0b97aea098fca509a0cd6e`; 4 tests, 0 failures/errors/skips, 37.416 seconds. Native test 32.008 seconds under unchanged 45-second budget; live concurrent launch 2.602 seconds. Output confirms real nested mount and persistent refresh controls, 4097 manifest entries, 64MiB integrity, partial-copy cancellation and mount restore/bind rename. Deterministic churn test 2.270 seconds; isolated poison test 0.532 seconds.
- `.omo/evidence/acp-private-control-concurrency/final-focused-harness-overlap.xml`: `455ad6e71ed38a9fd2af32408d032302e32b41301d2cb910253d9ca7a9e3f148`; 1 test, 0 failures/errors/skips, callback-overlap testcase 3.128 seconds. Inspected assertions require two simultaneously held callbacks, unfinished invocations before release, successful receipts, authorized edits, forbidden canary preservation, verified cleanup and stopped processes.

This clears the independent standalone source/security review and focused test evidence for this freeze. It does not replace final required hosted contract or automatic review gates, approve a different hash or DNS composition, close parent #238, or establish provider/authentication/production qualification. The earlier 9cfc diagnosis remains exact to its retained cause; fae's lower cause remains UNKNOWN. This reviewer ran no additional tests or CI and made no source/Git/GitHub changes.
