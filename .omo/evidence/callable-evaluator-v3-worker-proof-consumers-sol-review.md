# Callable evaluator v3: independent A1 worker-proof consumer review

**CLEAR for the exact static A1 consumer checkpoint only.** This approves the static proof-consumer wiring and intended API declarations, not the resulting writable-tree/mount composition. This is not a composed runtime/A3 approval, operational machine pin, monitor/namespace/ELF qualification, native result or final preparation authority. The runtime read-only-mount dependency observation below must be resolved by its owner before composition. Root retains all integration and qualification custody.

## Exact reviewed pins

Root `build/v3/static-worker-proof-consumers-001/manifest.json`: **53c88f348e06a74252b406b317178cfb2dc04d8b9e31314aefa84a000883fd2d**. All8 retained source/evidence files and all5 current owned source hashes independently match:

| Path under oracle/acp/callable-evaluator-v3/source | SHA256 |
|---|---|
| interface_gate_v3.py | `23d43dd5dd6c1343bbc5bb1cce6609958d784c27666f496a555b6bcfaa2c379d` |
| toolchain-001/build_helper.py | `d4df8dd4439583e9b602e993349f47f82f5d02b005d8c8bcef184639dae4dfdb` |
| toolchain-001/pin_helper.py | `981cda9cf8ed9f833d37a4b80fa30390d1b307deb8d1e88aed0f0f7d050e90bf` |
| tests/test_identity_graph.py | `02555e66988f4f533d17282f0941de03c37bbfb3a35fa45897376556b1f43011` |
| tests/test_worker_proof_consumers.py | `2fc1948b2adbd295ba65b3f4648a823e25a23a0b54edfc1ada64ca51727588bf` |

Root plan **b670e2de4fe5fbda4b06872234319f9121887d600b2341473d233d051df34ceb**, independent plan review **2b3ee62d3a7c184e9145837b90b714756bd370ef2e96080df48e92b278d58978**, and fixed ldd ELF recipe addendum **fd41f6c5b3d8a3bc0967b0933a5fe19f39e6d675b0fd6ea84453072a05e1c010** were read and hash-verified. Earlier A1 correction/source/reviews and preparations001/002 remain unchanged. Dependency hashes in this checkpoint are observations of concurrently owned source, not a global freeze; link_inputs changed during review, and bounded_runtime later changed too.

## Consumer proof requirements

`interface_gate_v3._complete_execution:54–56` delegates to the runtime's single full `worker_execution_complete` predicate. The observed b4e8d8… runtime predicate requires both workerExecVerified and workerTerminationVerified **and** every existing launcher identity/scope/admission/capture/wait/cleanup/reap/final-absence fact. It also refuses provisioning-only records, timeout/overflow/infrastructure failure, nonzero/noninteger launcher status, incomplete kernel absence, malformed proof/hash/file-identity/pin facts and inconsistent exact native exit/signal/raw-wait normalization. Both raw byte streams or valid public hex streams remain necessary. This source connection does not attest that a supplied dictionary is kernel evidence; the protected runtime producer/channel and receipt-store authority remain separately reviewed dependencies.

Probe descriptor enrichment still rechecks exact source/helper bindings and completion before accepting a closed supported descriptor. Helper build and dependency pinning require full execution proof; a wrapper-only0 or missing worker terminal cannot publish successful evidence. `build_helper` preserves bounded_result on failure and never writes the receipt after incomplete execution. `pin_helper` rejects an old build receipt before inspection. Public receipts retain worker facts rather than falling back to wrapper status.

## Commands, inputs and bounds

AST comparison against root `static-identity-correction-001` confirms **probe_command and probe are structurally identical**, including /probe, /work, arguments, mappings, environment, timeout/output and input revalidation. Original helper compiler argv is unchanged. Readelf dynsym and section invocations retain their exact original argv and phase limits; the new calls explicitly pass the exact library as `read_only_files` at its existing absolute path. Helper compilation explicitly passes its source file, original cwd/environment and existing helper-build bounds. No host-direct fallback is introduced by these consumers.

Pin-helper inspection replaces direct script execution with the specifically approved exception: logical `[/usr/bin/ldd, same-tool]` and actual `[canonical-Bash-ELF, admitted-ldd-script, same-tool]` are stored separately. `inspection_recipe:27–48` requires canonical regular Bash/script/cache paths, each supplied admitted hash, ELF magic and precisely `#!/bin/bash\n` without shebang arguments/env dispatch; every supplied dependency digest is checked. Tool/script/cache are explicitly declared as read-only inputs. The same existing elf-inspection seconds/output limits and fixed environment apply. Full completion and exit0 are required, A3 binding equality and file bytes are rechecked after execution, and dependency/script/cache pin identities are retained. No AT_EXECFN or kernel-shebang equivalence is claimed. Bash/loader/library/cache closure and the actual script behavior remain A3/native proof obligations; four ELF magic bytes and matching local hashes alone are not that authority.

## Pure tests and their actual meaning

Retained `pure-results.json` SHA256 `a6456fe4cc7157f50415008ab26a0916d0bb081a9c55d26eabe707b078812e63` reports32 tests=26 prior+6 new,0 failures/errors/skips and no forbidden native/subprocess attempt; all before/after source hashes match its checkpoint. `run_pure.py` installs a Python audit hook denying subprocess/exec/spawn/fork/system/pty paths before test discovery. This reviewer inspected source, mocks, AST and hashes only and did not rerun tests or native commands.

The six controls causally exercise absent exec/terminal proof, export/helper/pin containment API arguments, no output after failure, exact ldd logical/actual argv and bounds, input mutation and unsupported shebang rejection, and preinspection refusal of wrapper-only build receipts. Existing declaration tests changed only the necessary inert completed-result fields and real inert files/fixed environment for the new renderer. Their all-zero proof hash and `ELFinert` bytes are explicitly synthetic fixtures, not authenticated receipts or valid native ELF evidence.

The A3 loader did not exist in the attested dependency snapshot. Tests inject an inert pre-admitted binding; they neither execute the real loader nor prove its origin/closure. This is a legitimate static consumer contract test, **not** operational pinning or successful composed inspection. Postexecution binding/byte checks are visible in source but not thereby qualified against an actual A3 runtime.

## Cross-owner runtime observation: resolve before composition

In the observed frozen dependency `bounded_runtime.py` b4e8d8bbdcbb8e89740a0c152714fc289b7133147a0a0c124d0e7afa12b347bc, `contained_command:126,134–137` first mounts cwd writable and then skips any declared read-only file inside cwd. Consequently A1 correctly supplies the explicit read-only tuple, but a library/helper binary under that work directory is still writable in that composed recipe. Mocking contained_command cannot prove otherwise.

This was sent to root for the runtime owner. Preserve individual file read-only binds even within the writable work mount (or an equivalently reviewed exact-file recipe) and add a pure renderer control checking the emitted sub-file mount. Do not fix this by widening A1 mounts, marking the input immutable in a mock, or asserting that the whole work tree is read-only. The concurrent runtime was later observed at3939dc3c… with the same skip still present; this is a time-bounded dependency observation, not a demand that the entire worktree remain globally frozen. This report does not grant composition while that condition or A3 loader/closure remains unresolved.

Root subsequently confirmed this observation is routed to the runtime owner and authorized a separate corrective delta covering isolated Python bootstrap/pycache and the helper-build writable-parent recipe. Those changes were not part of manifest53c88 and are not approved retroactively by this report. Review the new exact delta independently; the old source/proof snapshot above remains historical.

## Disposition and custody

Scoped static A1 source CLEAR; runtime/A3 composition and all actual monitor/Bash/ldd/compiler/helper/native controls remain pending exact integration review and root authorization. Existing timeout/output/cleanup bounds, private source separation, distinct execution versus API claims, complete24-scenario/controls/mutant acceptance and final seal requirements remain unchanged. No source/Git/remote/CI/auth/model/native command, actual JVM/ldd/Bash/gcc/helper, or descendant was run by this review. Only this additive report was written.
