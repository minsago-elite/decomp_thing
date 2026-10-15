# Independent A1 correction003 rereview

**CLEAR for the exact003 static leaf-lifecycle correction of followup002 F1.** The original001 review and002 ITERATE remain intact. This is a new scoped review, not retrospective approval of002, current global composition, native qualification, operational A3 pinning or authenticated worker-result authority. Root retains integration/execution/cleanup custody.

## Frozen evidence and source identities

Root `build/v3/static-worker-proof-consumers-003/manifest.json` SHA256 **8f9e8ecd6e142f386cee593f8070d3e09c0f3e7fc32e650f0bdccbab3b923381** independently matches. All nine manifest-listed source/evidence files match. Its prior manifest is002 **474c2f8a33f4253d0a1562191fb7e0661bf032efe914b8675e151f1bb3217ee8**;001 remains **53c88f348e06a74252b406b317178cfb2dc04d8b9e31314aefa84a000883fd2d**.

Preserved reports independently hash-match:

- 001 `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-sol-review.md`: **7a37d5e82dff116c9bab2d3187d2ac7569eeffcf3ebf6dd1fc844ab3fbd95d4e**.
- 002 `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-followup002-sol-review.md`: **e347d597b76c34686df23fe0e4ce6bb8ab67144479462216c25c29a9f944f699**.

|003 source path under oracle/acp/callable-evaluator-v3/source|SHA256|
|---|---|
|interface_gate_v3.py|`9238e9bcb93a0ef188a8defb8393b5a5f1b90cb7c40b43e7fa2ac04dfad92c54`|
|toolchain-001/build_helper.py|`c1fc436023aebfebd2a93b62364de7819d380e86f4df6b2035f0d6729806e2a0`|
|toolchain-001/pin_helper.py|`f97a36c30e2956b4810c7a5ed956d4e3f83e600a675ae3527a055b774604e578`|
|tests/test_identity_graph.py|`0a48ee2f00e97c4f3be079443b711dc82b65f266fd872994324b104b2d3bdbf2`|
|tests/test_worker_proof_consumers.py|`8e1ccfa2ba2f0384d3bc82a105443d6a0740dc6ae6a0ebedd1d815a13f6b001f`|

## F1 correction and exact control flow

`interface_gate_v3.owned_worker_leaf:63–119` uses `mkdtemp` without an automatic destructor/finalizer. It captures path/device/inode/uid/mode immediately. `build_helper.build:70–86` and `pin_helper.pin:68–82` both use this shared lifetime and register only their own actual `bounded_run` call/result through `leaf.run`.

`__exit__` deletes only if the retained leaf identity still matches and either (a) trusted local control flow has not entered the runner, or (b) this runner's result has exact true cleanupVerified/rootReaped/finalAbsenceVerified and nested kernelScope.finalAbsenceVerified. Missing/false/malformed absence, absent result, and changed identity refuse deletion. This cleanup decision is deliberately distinct from accepting a successful exchange: full authenticated completion remains separately required for publication.

- **Returned failure:** each consumer constructs its original incomplete-execution exception with the runner result as bounded_result. The leaf records cleanup facts on that same result and exception, retains unknown-live work, and returns False from __exit__ so the original exception propagates.
- **Raised failure:** leaf.run marks launch entry conservatively before invoking the runner, captures only that raised exception's bounded_result (or None), and rethrows it. No earlier inspection result survives an exception with no result; that branch resets self.result to None. Unknown absence therefore retains the leaf. The context manager adds facts without replacing the original exception or its existing bounded_result.
- **No process / prelaunch:** argument evaluation invokes contained_command before entering leaf.run, so a recipe rejection has launched=False and may delete its never-launched matching leaf. An entered runner which refuses before creating a process is conservatively treated as potentially launched unless its own result proves absence; no-process uncertainty is not upgraded to success. There is no cleanup retry, process signal, fresh timeout or alternate launch in this helper.
- **Stale identity / unknown absence:** changed device/inode/uid/mode or lstat failure prevents deletion. The retained original identity remains available for root's later decision; a replacement at the same pathname is not erased.
- **Secondary deletion failure:** identity/deletion errors are recorded as a bounded secondaryError. With a primary exception, it remains the exception and its result object is preserved. Without a primary, a new explicit cleanup-incomplete refusal carries the result and leafCleanup facts. Existing publication logic is not asserted transactional across binary/dependency/receipt; process-proof publication and filesystem leaf cleanup remain distinct facts.

The normal fully verified path still removes its leaf. Unknown process outcomes still cannot enter successful output publication. A later filesystem deletion failure after verified build publication is separately surfaced to the caller; build files/receipt may already exist, and this correction does not make publication and leaf deletion transactional. No source/mount/timeout/output/aggregate-task limit or controller-tree protection was relaxed. AST comparison finds no changed preexisting interface_gate function: probe/probe_command, export argv/input declarations and completion delegation remain identical to002; only imports and the new lifecycle class are added there.

## Retained controls: what actually passed

`pure-results.json` SHA256 **f541838c009d9c843595f52cd2bd0e804bb55bdda6c25eb7f43a4a5a76df6351** reports37 tests=26 prior+11 consumer methods, zero failures/errors/skips, zero forbidden subprocess/native attempts, and identical before/after hashes for all five owned sources and ten dependencies. Those maps independently equal the manifest. `run_pure.py` remains **dc22390dd8a5c30ec3a2391aec43a1c7c62baf99a2c5affd9ae8cd23e135f410** and installs its execution-denial audit hook before discovery. This reviewer inspected retained evidence/source only; no tests were rerun.

The two new shared-leaf methods (`tests/test_worker_proof_consumers.py:29,61`) exercise returned/raised primary identity preservation, unknown retention with no deletion, injected deletion errors without losing primary/result, successful/prelaunch removal and stale-inode replacement refusal. The existing build and inspection methods (`:102,215`) now also exercise the actual consumer integration: returned and raised unknown cleanup/absence retain the leaf, no new fixed receipt/output is published, and deletion faults preserve their incomplete-execution primary and bounded_result. The successful build control continues to require full completion before staged publication and verifies leaf removal. The actual pure mount renderer still requires only the leaf RW with RO input overlays, including an input under the leaf.

Coverage is bounded: source inspection, rather than an extra retained case, establishes the no-primary deletion-error refusal and conservative runner-without-result branch. No assertion of a new native no-process experiment or every filesystem failure variant is made.

The completed_result fixture now authors compact raw exec/term bytes, bound launch pins/expected identities and their hashes instead of relying only on booleans. The observed completion implementation additionally replays those bounded raw bytes through its fixed parser and compares terminal facts. The fixture remains synthetic; authored proof/hash/identity fields do not grant kernel/channel authority. ELF-shaped publication and mocked read_output compatibility fixtures also remain inert contract controls. Neither receipt mocks nor the37 count qualifies an actual compiler/helper/Bash/ldd/runtime execution.

## Dependency binding and drift

All ten current dependency files below matched the003 observations at read and final write. These are explicit dependency observations of this pure checkpoint, not a global source freeze or a new composition/native pass. No current drift was observed within these15 inspected source paths; unrelated concurrently owned files were not held or reviewed.

|003 dependency observation|SHA256|
|---|---|
|bounded_runtime.py|`122bbf6cc0c64dd3286cd1b685f00a53429e58dd6ba93249bb33c9b2c91bb610`|
|build_contract.py|`64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85`|
|worker_exec_proof.py|`bb7ec2289dbe9eeea2e19416fc1e166d75dbc888651f8ad5cc03a76f7c6dbc93`|
|contracts/helper-schema.json|`2d0d222b4192332ae9ce9c9bcc70aab7bc0b9d5539103ac3c3b82c6292f038a4`|
|record_identity_probe.cpp|`0cc97a9eeb4eda5bb09f2a600eabee867299b756fe8364f02deeb7d77e85cb57`|
|tests/test_builtin_types.py|`3ebce53833f421ff51a7fc539c0d8ce67c8d9aae64eaf14ff48c6cfedcdbf0a8`|
|toolchain-001/pin_environment.py|`fb650456d802e5dd5195668a1efc8a88ef914cb59582c8b58ea54b7aa6181e82`|
|toolchain-001/link_inputs.py|`a1fb0950e2500747a5f01c6319d45a522323ecbcc33b535e7ef262241f338f1e`|
|toolchain-001/monitor_inputs.py|`812586a70c2eecaccde6f94238ffd1f5aa3d7a4bbaa20aecbd6ad104584ccaf6`|
|contracts/candidate-build-profile.json|`c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f`|

Additional retained003 evidence: report **fa81f5300627d64a39342c4b00e1e098ba417909e9d10cfefefdf3097a1c9de7**, delta-from-002.patch **4bec91bb97af52764ae01062b60d8b55fe41d989eb9277af82442f1bd835c846**. The prior approved plan/addendum scope and all001/002 limitations remain in effect. A3 closure, monitor/controller integration, actual visibility/namespace/process cleanup, real helper/inspection handoff, full private matrix and hosted qualification remain root's separate gates.

## Disposition

No remaining blocking finding in this exact003 correction. F1's unconditional unknown-live deletion and primary-error masking are corrected. Preserve prior evidence; root may integrate only with separately reviewed runtime/A3/strict-evaluation work. No source edit, test, native/process launch, Git/remote/CI/auth/model action, existing attempt cleanup or descendant was performed. Only this additive review was written.
