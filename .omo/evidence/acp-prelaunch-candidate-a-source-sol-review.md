# Candidate A — independent source review

Verdict: **CLEAR_SCOPED** for the frozen root-only optimization source. No concrete source blocker found in the reviewed delta under root's explicit callback amendment. This is not compilation, native/race qualification, measured speedup, production release, or permission for another measurement.

GPT-6.1 Sol; no descendants. Source/data/hash inspection only, no compiler/JVM/native/test/auth/network, Git or remote execution. Only this additive report written. Root retains execution and checkpoint custody.

## Pins and isolation of change

Worktree `.claude/worktrees/wf_ce026d1b-c24-68`; root-reported baseline `3db91b788268590d3d9eda3904424a0f5fc76c87` (not independently queried through Git).

- Freeze `build/acp-prelaunch-candidate-a-source/source-freeze.json`: `99f5fb2a7630977aeada1a883d684757b705bfc627074c7517fd07e3c2301c57`.
- Handoff: `80fc2dce2d5abab2581a3c54b0656c8d932e9a09d6e53c207359957aaed6cbb7`.
- `LinuxBubblewrapBoundary.kt`: `5e37b86ce25dea78ee85922166100ac987f30508aea9f89f9603ef7f94a3e752`.
- `LinuxFilesystemSyscalls.kt`: `16e8b7e668928bb426a278db5b3c6ed863f7de565b616ea80a56cece66c62c6c`.
- `LinuxFilesystemSyscallsTest.kt`: `09a49b8938364a4c3d75165525cacd5d5cec3ffd951d4cf428743f66977cce0b`.

All three current hashes matched. Independently reconstructed both prior production texts by removing the added helper/primitive and reversing the sole currentRoot call change: exact baseline hashes `8b742d19941a01ed4d5d11f49a4bc15232ae1536ffb0b478af4aa7b8b83762aa` and `c91ff9894be863fe3f15a7cd66ac59b68578a84c270dc461089cfb948497b697` matched. This read-only reconstruction did not run the author's verifier, which writes a freeze. Generic `hostPhysicalLocation`, `withHostPhysicalPath`, control admission, physical-alias handling, registry transactions and existing callback callsites/arguments are therefore unchanged.

Design basis is root `.omo/evidence/acp-prelaunch-root-check-performance-sol-design.md`, SHA `32d93d3afa4cee139f513ac9a7bd75afaa20bbbe7db84fc7756d2e54f0a3069e`, and retained ABI receipt `c9e587f7a477be40c980151efa4e86d0d18b504a9d2ed009a14f1ffd9a00b474`. The original design's per-retry real callback proposal is expressly amended below; it is not implemented and must not be claimed.

## Source conclusions

| Area | Evidence and conclusion |
| --- | --- |
| Exact optimization boundary | Boundary 2288–2349 adds only exact-existing-root reauthentication; currentRoot 2483 is the sole substituted caller. Both fast-eligible and slow scopes still call currentRoot. Other descriptors' slow physical path remains generic at 2568. No pathname validity cache, check thinning or new admitted input class appears. |
| ABI/how layout | Syscalls 165–199 gates Linux, exact amd64/x86_64/aarch64 names and both pointer/native-long widths 8 before invocation. The fixed JNA declaration at 1021 uses NativeLong number/dirfd/size/result, String path and Pointer how. Native-order Memory(24) is cleared, with 64-bit fields at 0/8/16; flags are existing O_PATH|O_NOFOLLOW|O_CLOEXEC, mode 0, resolve 0x0e, syscall 437, size 24. These match the retained reviewed Linux LP64 ABI basis. Unsupported ABI returns to strict walking, not an unreviewed raw syscall. Actual libffi/JNA/native behavior still requires compilation and supported-host controls. |
| Retry/refusal | Syscalls 202–212 has one shared eight-attempt budget for EINTR/EAGAIN, immediate errno capture, success only on nonnegative result, and exhaustion refusal. Only ENOSYS selects kernel fallback. EPERM/EACCES/EINVAL/E2BIG/EXDEV/ENOENT/ENOTDIR/ELOOP and other errors throw; no resolve flag is weakened. No fresh per-retry deadline or hard syscall interruptibility is claimed. |
| Ownership | Retained source descriptor remains under whileOpen across all comparisons. `/` anchor remains owned through lookup. Memory.use owns native how storage. Returned FD identity construction is inside try/catch with terminal close on identity failure; successful descriptors are used/closed through requireSame. Outer finally closes the anchor on success, failure or fallback. Strict fallback reuses that anchor and closes each prior component; missing tails and rejected symlink/non-directory components fail without leaving the next FD owned. No new external cancellation is invoked in the narrow raw-FD acquisition gap. This is source reasoning, not an executed FD-leak proof. |
| Name/type/root semantics | Boundary 2293–2308 retains identity-before, unique mount-id selection, descriptor readlink, normalized absolute bounded pathname within mount, and exact reopened key/mount/directory/regular comparison. Final O_PATH symlinks are explicitly refused by requireSame; intermediate symlinks fail kernel resolution or strict walker. Regular-file roots remain supported; `/` and other kinds use the strict walker. After identity key/mount/mode comparison, physical coordinates are built identically; currentRoot still checks admitted key/mount/mode/name. |
| Registry/authority checks | Mount event latch, exact mount snapshot, live control identities, generation reconciliation, rollback, poisoned registry, overlap checks and physical coordinates remain baseline code. BENEATH/NO_SYMLINKS/NO_MAGICLINKS does not add NO_XDEV/IN_ROOT/CACHED or prohibit previously admitted ancestor mount traversal. Mutable names still get a fresh constrained resolution at every existing root-authentication site. |

## Exact callback amendment

Root explicitly authorized preserving baseline callsites/check arguments, with **no new external callback inside the registry monitor**. currentRoot continues receiving `NO_SANDBOX_CHECKPOINT` at Boundary 2496,2506,2551; its helper uses that supplied check, and the eight retries add no real callback. External cancellation remains observed at its existing sites, not once per retry. Original design line 93's before/after-each-attempt real checks are superseded only on this explicitly narrow basis.

A blanket statement that external callbacks never run under the monitor would be false. Existing stored `cancellationCheck()` at 2516 executes from synchronized checkpoint/requireDescriptor; scope open at 2609–2615 also calls supplied check under the monitor, and callers at 5516/5767 supply the invocation callback. Those are preserved baseline sites, not additions by Candidate A. Root confirmed this is a no-NEW-callback amendment, not authorization to refactor the broader locking/cancellation contract. Neither implementation nor this review establishes per-retry real-deadline checks or a hard bound on filesystem/C stalls.

## Authored tests and remaining qualification

All three new tests (SyscallsTest 137–213) are **uncompiled/unrun**:

- Pure ABI matrix checks accepted names/widths and refused 32-bit/x32/non-Linux cases. It tests the predicate, not an actual unsupported-platform composed fallback.
- Pure retry control tests mixed EINTR/EAGAIN eighth-attempt success, eight-attempt exhaustion, representative refusal errnos and ENOSYS-only null. It does not drive the actual root helper through its strict fallback or inject an identity failure after native FD acquisition.
- Native primitive test requires a supported lane, compares regular/directory/final-symlink descriptor kinds, and refuses intermediate-symlink/missing paths. It deliberately fails rather than silently passing through unsupported fallback. It does not call manifestRootPhysicalLocation to prove final-link rejection, test cancellation after acquisition, or census FDs on injected failure.

Before runtime acceptance, required qualification must compile the exact frozen sources and execute all seven SyscallsTest methods, both actual supported lookup and forced ENOSYS/unsupported strict fallback, regular/directory/root-only and final/intermediate/magic-symlink cases, permission/ABI/race errors, and ownership cleanup after identity failure/late cancellation. The new controls alone do not cover all those cases.

Existing Boundary tests contain disjoint overlapping manifests, registry churn/ABA/rollback/cancelled close, failed cleanup/poisoning, native bind aliases, late callback exposure, sticky restored mount events, file replacement and bind/ancestor rename. They are relevant composed controls, but were not rerun against this candidate, and do not by mere existence prove deterministic coverage of every new native/fallback seam. Full hostile/overlap qualification and no-skip required native evidence remain gates. `scripts/validate-acp-contract.sh` still requires a nonempty SyscallsTest suite and zero aggregate failures/skips; it does not independently assert the new exact seven-method population, so retained method-level JUnit evidence must demonstrate that population rather than reusing an old class report.

Supplementary inspected snapshots: BoundaryTest `6ab86b5e0a430c1311f7114137303e08c831281c8bccbc032f5f95701cd21dcb`; contract gate `d03cb790d51f58c07a9647d59f2417176516252f8b4107f761485646cd13faef`; Gradle `ddd281eef04fcf3e33312c739316d610d312e7f47a954c62292497bb5d2ba5a9`; CI workflow `f70852da97769162b4413279a9765711ef13f9ad2483630be027d19c3eba8c71`.

## Interpretation

For the previously measured stable non-root fixture R=64,D=7,K=269, the candidate predicts root temporary opens/closes of 2K=538 instead of (D+1)K=2152, while preserving semantic checks. Forced strict fallback predicts the old 2152. These are source-derived counts, not a measured candidate result or speedup. The R9 baseline, one-file timing and native-provenance caveats remain unchanged. Root may prepare the required scoped compilation/qualification; no full closure/provider qualification or optimization release follows from this source verdict alone.
