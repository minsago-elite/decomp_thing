# Independent A1 F1 consumer followup002 review

**ITERATE: one new leaf-lifetime failure-path correction is required.** The isolated leaf and publication changes address the earlier writable controller-tree concern, but the automatic cleanup on an unknown process outcome needs correction before this checkpoint is cleared. This is a static A1 source review of manifest002 only. It grants no current composed/runtime/A3/native qualification or operational receipt authority.

## Immutable scope and evidence

Root `build/v3/static-worker-proof-consumers-002/manifest.json` SHA256 **474c2f8a33f4253d0a1562191fb7e0661bf032efe914b8675e151f1bb3217ee8** independently matches. All nine files named by its `files` map match their hashes, including all five source snapshots. All five current owned sources also match those snapshots at this review's observation:

| Source path under oracle/acp/callable-evaluator-v3/source | SHA256 |
|---|---|
| interface_gate_v3.py | `23d43dd5dd6c1343bbc5bb1cce6609958d784c27666f496a555b6bcfaa2c379d` |
| toolchain-001/build_helper.py | `aaa0b1503c1f1374d757c02debabaf7d528c72985773d624c068fd529dd51227` |
| toolchain-001/pin_helper.py | `6850ba45be4f53e46b3e78091e93074dabfb6ee7777cd0bf4a05366e06136aaa` |
| tests/test_identity_graph.py | `31c53c8bfb650fbb0dc438159b11fa6811e4633dcf2591a15cb8e4685b82e459` |
| tests/test_worker_proof_consumers.py | `7a35902e0a0dbc888626657f85ab8eb5eb4476a90b81cc98839791e7cc30e7b3` |

The prior review remains byte-preserved at `.omo/evidence/callable-evaluator-v3-worker-proof-consumers-sol-review.md`, SHA256 **7a37d5e82dff116c9bab2d3187d2ac7569eeffcf3ebf6dd1fc844ab3fbd95d4e**; prior001 manifest **53c88f348e06a74252b406b317178cfb2dc04d8b9e31314aefa84a000883fd2d** is historical. Plan **b670e2de4fe5fbda4b06872234319f9121887d600b2341473d233d051df34ceb**, plan review **2b3ee62d3a7c184e9145837b90b714756bd370ef2e96080df48e92b278d58978**, and fixed Bash/ldd addendum **fd41f6c5b3d8a3bc0967b0933a5fe19f39e6d675b0fd6ea84453072a05e1c010** were hash-verified against this review's read.

Retained `pure-results.json` **9d9911a021caa28c5bc50453eb1d06dc993585730579607f99cef1d0cf2e47ab** reports 35 tests =26 prior+9 consumer, zero failures/errors/skips and zero forbidden native attempts; its before/after maps match the manifest and each other. `run_pure.py` **dc22390dd8a5c30ec3a2391aec43a1c7c62baf99a2c5affd9ae8cd23e135f410** installs the subprocess/exec/spawn/fork/system/pty audit denial before discovery. These are retained pure results, not an independently rerun suite or an authenticated worker result. No tests or native programs were executed by this review.

## Finding F1: unconditional cleanup destroys an unverified-live work leaf

**Required correction, bounded to the new A1 leaf lifecycle.** Frozen `toolchain-001/build_helper.py:74–90` and `pin_helper.py:73–87` enclose the launch in `TemporaryDirectory`. Its context exit recursively deletes the directory on normal return, incomplete-result refusal, and exceptions from `bounded_run` alike. Neither path conditions deletion on `cleanupVerified`, root reap and final process/scope absence. In the new helper build this is precisely the directory the worker can write, and in both paths it is the worker cwd/TMPDIR.

This does not publish false success: `_complete_execution` still blocks publication. It does delete the work mount while the runner may explicitly be unable to establish that its users are gone, loses useful failed-attempt state, and invokes recursive cleanup outside the runner's bounded process-cleanup protocol. A deletion error can also replace the original exception carrying `bounded_result`, hiding the primary controller facts from the caller. This is a source control-flow finding; no surviving process or native reproduction is claimed.

Concrete inert seam: mock `bounded_run` to raise a sentinel exception carrying `bounded_result` with `cleanupVerified=False`, `rootReaped=False`, `finalAbsenceVerified=False` and kernel scope absence false; capture its supplied cwd. Both frozen functions necessarily leave their `with` block and attempt deletion before the sentinel reaches the caller. The existing identity test at `test_identity_graph.py:201–205` already injects an incomplete cleanup flag, but asserts only receipt refusal. The new consumer negatives likewise assert no publication, without checking leaf retention or cleanup-error precedence. Thus the 35 retained passes do not cover this failure.

Smallest correction: use an explicitly owned attempt leaf without an unconditional automatic finalizer. Delete it only after trusted controller facts establish absence, or a trusted prelaunch state proves no launch occurred. On unknown/cleanup failure retain the exact leaf identity/path with the original bounded result for root's later ownership decision; do not silently retry process cleanup or widen mounts. Preserve the primary exception/result if filesystem cleanup itself fails and retain secondary cleanup facts separately. A successful verified run may still remove its leaf as it does now.

Finite pure controls should cover both consumers: returned incomplete cleanup/absence, raised cleanup-unverified exception, successful verified cleanup, and injected directory-cleanup failure with original exception/result preserved. Assert no fixed output or receipt publication on the unknown paths, retained leaf identity/path on unverified absence, and unchanged controller source. These controls require no actual process or namespace launch.

## Corrections that are visible and sound within this scope

- Build/inspection now allocate exclusive private leaves below `source/worker-work`; neither requests a writable controller `toolchain-001` or source tree. Helper compiler flags and source remain fixed, with disclosed `-MF` and `-o` stage destinations and cwd/TMPDIR changed to the leaf.
- Build snapshots source/schema digests before launch, requires the shared full completion predicate, and rechecks source/schema before bounded output reads. `read_output:17–45` opens no-follow/nonblocking, requires owned regular single-link nonempty bounded files, compares descriptor identity/size/times before/after the read, and checks the declared ELF64/x86_64 header and program-header extents. The read limit is the existing `fileSizeBytes`; no limit increase is introduced.
- Fixed controller destinations are written only after the proof predicate and both staged reads succeed; each file is replaced from a controller-created temporary file with explicit permissions. This is per-file atomic replacement, not a transaction covering dependency file, executable and receipt. This review does not invent a transaction or concurrency guarantee.
- `interface_gate_v3.py` is byte/AST unchanged from001: probe/probe_command, /probe and /work argv, export inventory argv, input bindings and the full completion delegation are retained. No wrapper-status fallback is added.
- Pin inspection keeps exact logical ldd argv and explicit canonical Bash/script actual argv, pre/post A3-binding equality and byte revalidation, tool/script/cache explicit RO inputs, fixed environment and existing inspection limits. The leaf is separate from the control directory. A3 closure/producer authority and actual Bash/loader behavior remain separate prerequisites.
- The added real pure renderer control inspects emitted mounts, requiring only the leaf as RW and RO subfile overlays even for inputs inside it. It directly addresses the old cross-owner skip observation; mock containment calls alone did not do so.

The inert publication fixture is an authored 120-byte ELF-shaped header/program-header buffer, not a runnable helper or compiler result. The identity compatibility test deliberately mocks `read_output` with `NOT EXECUTABLE`; that test proves only receipt plumbing. Its all-zero proof digests and the inspection fixture's `ELFinert`/script/cache bytes are synthetic controls, not admitted operational closure. Nothing in this review treats them as native proof.

## Current dependency differences: no silent composition claim

The following current source dependencies differ from their manifest002 observations:

| Path | 002 dependency observation | Current observed SHA256 |
|---|---|---|
| bounded_runtime.py | `f3788d0e792dd2189538625300b90df688498b2a74e81c2a60472680ab5982a1` | `9a6541a0f6d77cb9a6bd1f5f2903ad55fbea167da03d7cd17da09df202d7773a` |
| build_contract.py | `7edfc36da8ff107770ae3727340ab8e377ad86b55267ce71d89a3dc9b2a07fd6` | `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85` |
| toolchain-001/monitor_inputs.py | `9e0a7b51bee9f8c4bd623ecdb22d7bb493797a71b3f6d0491d598de2efcf6531` | `812586a70c2eecaccde6f94238ffd1f5aa3d7a4bbaa20aecbd6ad104584ccaf6` |
| contracts/candidate-build-profile.json | `d7d1d7588b260b9dfa720cd0fc34828c53dbb2adcfeb46ccb02c5a0646db57f7` | `c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f` |

The other six dependency observations still match. These differences are recorded rather than required to revert; concurrent owners control them. The current runtime's RO-file renderer visibly appends RO overlays after the RW cwd bind (`bounded_runtime.py:176–191`), and its `_work_directory` rejects protected controller subtrees. Its current cleanup path can raise a `bounded_result`-carrying cleanup failure when process absence is unverified (`:833–857,903–905`), illustrating the real failure interface F1 must handle. These are separately pinned current observations, not reconstructed manifest002 source or a fresh composed pass. In particular the current full predicate has additional proof-binding validation absent from the synthetic002 receipt mock; the retained 35-pass result cannot be reused as a pass of that changed composition.

## Disposition

ITERATE solely for F1, then independently review the exact corrective delta and retained pure controls. Preserve001/002 source and evidence. Root retains integration, execution and cleanup custody. No source/Git/remote/CI/auth/model/native command, actual JVM/ldd/Bash/gcc/helper, test execution, descendant, or attempt cleanup was performed. Only this additive review was written.
