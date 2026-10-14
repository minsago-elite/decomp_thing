# Clang rootfs lifetime checkpoint

Issue1480 remains open. Acquisition is paused; no archive/native/OCI qualification is claimed. This checkpoint preserves authenticated rootfs publication and held-directory authority, with root-wide procfd slashdot traversal.

176 offline provisioning tests pass. Independent Sol review is CLEAR for final T1/T2 source hashes. Privileged/native tests were not repeated after the marker correction; modeled helper controls and actual FD closure cover the changed branches. Prior actual doas smoke is historical and does not qualify this final snapshot.

## verification.md

SHA256 `722da9fd7b1d26585bb24cc60efdf3820fc7b692ffda6aec518aea38b005a64f`.

# Clang rootfs lifetime corrections

Base HEAD: `895d15d0f2b2ae51f3e7cdcd273052c659e9657b`

Live planning state was read on 2026-10-14. Issue 1480 and milestone 23 were open. The captured API responses are `issue1480-live.json` and `milestone23-live.json`; the issue acceptance criteria remain incomplete, so this work does not close it.

## Rootfs directory lifetime

Scenarios: a same-UID process substitutes the created rootfs pathname before the caller pins it; a privileged helper returns malformed identity output after creation; parent directories originally at modes `0700` and `0750` pass through the privileged authority handoff and return to their exact original owner/group/mode.

Offline invocation: `python3 -B oracle/clang/18.1.3/test_provisioning.py`

Actual privilege invocation: the bounded Python program captured by `doas-lifetime-end-to-end.log`, which imports the production module and maps its hosted `sudo` argv to local `doas -n` without changing either fixed helper program.

Binary observables: the fixed create helper opens the retained no-follow parent descriptor, verifies its full identity and safe original permissions, transfers ownership to root, removes group/world write permission, verifies root authority, then creates and opens the child. The caller holds the exact returned child inode before a fixed helper restores the parent. Recovery runs after every attempted create command, including invalid helper output, and permits an absent child only when no child identity was returned. Offline replacement raises `ProvisionError` without reaching the canary. The actual `doas` run reports `restored=yes root_uid=0 pinned=yes` for both original modes.

All root-wide normalization and cleanup `find` calls address a held descriptor root with a trailing `/.`, so GNU find traverses the directory contents. The bounded traversal control is `find-procfd-cleanup.log`.

## Rootfs tar publication lifetime

Scenarios: relative, absolute, and output alias spellings succeed; existing, symlink, and escaping destinations fail closed; source content/path replacement fails authentication; after the privileged helper returns, replacement of the published leaf with a different same-sized `0444` inode is rejected.

Offline invocation: `python3 -B oracle/clang/18.1.3/test_provisioning.py`

Binary observables: the root helper opens the source through a retained parent, copies and hashes exactly the recorded bytes into a root-private inode, links it exclusively, and returns its `(st_dev, st_ino)`. The caller opens that returned pathname without following links, requires the exact helper inode and root-owned `0444` metadata, hashes the held descriptor through exact EOF, then requires the name still resolves to the same inode. The hostile same-sized substitution test raises `ProvisionError` and retains the authenticated source. The actual `doas` run reports the expected SHA-256, UID 0, mode `0444`, exact bytes, and `same_uid_write=refused`.

## Verification

- Full short offline suite: 173 tests, zero failures/errors/skips in 7.376 seconds. `offline-suite-final.log` SHA-256 `aba4db54dfaa7dd7079ef1610a639d5558d8c4ac18c17a3acaceb3ca80f90f31`.
- Actual bounded local privilege run: `doas-lifetime-end-to-end.log` SHA-256 `49113d73ff63ad1580dde78f5624fe0c3bd3cb303d6aefce3e57aca05160d7a0`.
- `git diff --check` produced no output and exited zero.

Frozen source SHA-256 values submitted for independent rereview:

- `scripts/oracle/provision_clang_18_1_3.py`: `14b77f9c4bb19c6655566b23f3daadcf75b1975d8ea6857d2c2136e2fbf51bcf`
- `oracle/clang/18.1.3/test_provisioning.py`: `89445538f7a3dd263a7a6ccf22ce5e2c8d0bb4bbd5f6eac51772223e621b5d8f`

No acquisition, native compiler run, OCI qualification, fake clock, trust change, expiry bypass, budget relaxation, Git mutation, or GitHub mutation was performed. The acquisition pause and version-specific Tom Stellard key expiry refusal remain unchanged.

## independent-review/third-freeze-report.md

SHA256 `1566a3bdc7b65eb41b9296bf65f7da257b001e28782d22cf265a225ea637ce12`.

# Third Clang rootfs lifetime review

**Status: CHANGES NEEDED** for script `14b77f9c4bb19c6655566b23f3daadcf75b1975d8ea6857d2c2136e2fbf51bcf` and test `89445538f7a3dd263a7a6ccf22ce5e2c8d0bb4bbd5f6eac51772223e621b5d8f`.

Earlier reports and evidence remain intact. This review executed no privileged command, bootstrap, native compiler, or archive acquisition/generation. All created fixtures were inside this directory and removed. Root metadata/ownership operations in the new authority control are explicitly mocked; its FD leak observation is actual and all attributable leaked descriptors were closed by the control.

## Findings

### T1 — P1: recovery can release authority acquired by another invocation

Locations: `ROOTFS_DIRECTORY_CREATE_PROGRAM` initial validation and unconditional `if not success` restoration; `ROOTFS_PARENT_RESTORE_PROGRAM` unknown-child recovery; caller's `helper_attempted` recovery decision.

The create helper enters its restoration finally even when its initial expected-parent validation fails before it calls fchown to acquire authority. Consider two callers opening the same ordinary writable parent and recording the same initial metadata. Caller A's helper takes parent ownership and begins its protected mkdir/open interval. Caller B's helper then observes A's root-owned locked parent, rejects the stale expected metadata, and its finally restores the original caller ownership and mode. That unlocks A's parent while A still depends on its exclusive authority, restoring the original real-directory substitution interval. There is no serialization or attempt-specific ownership marker.

The independent control executes the exact embedded create helper with a modeled root-owned locked parent and a stale original expected tuple, mocking only fstat/chown/chmod for privilege. The helper rejects at its initial validation and never acquires a root lock, yet records chown back to UID/GID1000 and chmod0700. The exact restore helper also releases an untagged root-owned parent when passed unknown child(-1,-1) and an absent leaf, so the caller's fallback can produce the same cross-attempt release.

Evidence: `third-freeze-controls.json`, `stale_create_unlocks_other_authority` and `unknown_child_recovery_unlocks_untagged_authority`.

Required correction: serialize the complete parent authority handoff/recovery lifetime or establish verifiable ownership of the current lock for each attempt. Do not restore a parent before this helper has acquired its own authority. Unknown-child recovery must operate only within the invoking attempt's exclusive authority; root ownership alone does not prove that ownership. Add a concurrent/stale-attempt control demonstrating that another invocation cannot unlock an in-progress creation.

### T2 — P2: restoration failure skips descriptor cleanup

Location: `create_pinned_rootfs_directory` outer finally; recovery exception raise occurs before its descriptor-close loop.

If the recovery helper raises, the finally block raises `ProvisionError` immediately and never reaches the subsequent loop closing root_fd and parent_fd. A failed operation therefore leaks its held descriptors. The actual bounded control returns malformed create output, makes the recovery command fail, and observes one new still-open parent descriptor3 after the function raises. The control closes that descriptor afterward. A failure after root_fd acquisition can leak both descriptors.

Evidence: `third-freeze-controls.json`, `recovery_failure_fd_leak`: before[], after[3], commands create/recovery, error `could not restore rootfs parent authority after privileged creation`.

Required correction: put descriptor closure in an unconditional inner/outer finally that runs even when recovery reports failure, preserving the recovery error and closing each owned descriptor once. Add that rejected-recovery FD-lifetime control.

## Confirmed corrections from the prior review

- Parent fchown is now followed by chmod0710 and an authority metadata check before leaf creation. This closes the prior pre-chown chmod0777 race during a single uncontested authority interval; T1 concerns losing that interval to another invocation's recovery.
- Caller group membership is checked; the worker's actual production-function doas smoke reports correct restoration and exact held root inode for parents originally0700 and0750. The smoke log SHA256 is `49113d73ff63ad1580dde78f5624fe0c3bd3cb303d6aefce3e57aca05160d7a0`.
- Malformed helper results now invoke recovery; the independent focused invalid-result test passes. Recovery success is not silently assumed after its command fails. T1 and T2 concern ownership and cleanup on that failure branch.
- Publication now returns the root helper's device/inode, opens the destination without following links, holds and validates the exact root-owned0444 inode, hashes exact recorded bytes through EOF, and checks its final named binding. The same-sized post-helper replacement regression is rejected, retaining the source.
- Root-wide normalization now uses procfd slashdot. The independent actual nonprivileged normalization control sets the canary mtime from1234567890 to42 as requested. Earlier actual cleanup traversal control remains valid.
- Unsupported preserve-fds argv remains removed; the corrected single-owner binding rejection path remains intact.

Four focused offline tests were independently rerun: root path substitution, invalid helper result recovery, relative/absolute/alias publication, and source/post-helper publication replacement. All4 passed, no failures/errors/skips,0.007s. Worker full suite evidence reports173 tests passing, log SHA256 `aba4db54dfaa7dd7079ef1610a639d5558d8c4ac18c17a3acaceb3ca80f90f31`.

## Scope

Acquisition pause remains false-enabled (`UPSTREAM_SIGNATURE_ACCESS_ENABLED = False`), strict key-expiry refusal and sandboxed-probe fail-closed behavior remain. No native/OCI qualification is inferred. The parent lock temporarily grants group search with0710 while taking ownership; original mode is restored on healthy completion. This review addresses the stated same-UID filesystem actor boundary and does not assert cross-UID confidentiality of that temporary mode change. Final-path checks establish the artifact binding at validation time, not perpetual immutability of entries in a caller-owned directory.

A corrected exact freeze and proof for T1/T2 are required before CLEAR.

## sol-source/summary.md

SHA256 `7089f8c1e27dc7c4e1d2d4994f57b814dc28de71190eb0b134b5970b564265b2`.

# Source correction and offline verification

CREATE failure now retires its per-attempt marker before restoring parent ownership while holding the parent flock. Marker retirement failure skips parent restoration. A delayed helper therefore cannot use a previously acquired marker to release a successor attempt’s authority.

Added executable-helper regression coverage using real descriptors and simulated privileged metadata: failed creator marker retirement ordering; fail-closed marker retirement failure; stale CREATE and RESTORE refusal; recovery refusal with an unacquired marker. Added wrapper regression checking actual parent, marker, and root descriptors report EBADF after recovery failure.

Verification: python3 -B oracle/clang/18.1.3/test_provisioning.py — 176 tests passed in 7.217 seconds. git diff --check passed. No privileged, acquisition, native qualification, Git, or GitHub mutation performed. Offline suite output is offline-tests.log.

SHA256:
- `f40324f7f40d4c9172911356c9cfa34eebde402b5bcd40f8bd75b6b50c75f87d` `scripts/oracle/provision_clang_18_1_3.py`
- `350d6eafd6749b260f299c35a4abe0eceb7cf9924d7ac855944b9ae18c487b18` `oracle/clang/18.1.3/test_provisioning.py`

## sol-source/offline-tests.log

SHA256 `5d6e8f4c16470e1dbf0c4421d71e934540b5a9e873227715725e501c0cf419e8`.

## sol-review/report.md

SHA256 `561e4ba80d91070f923a526f433d3aaf9c5477e9576fe5ad65af9bc3e57ef128`.

# Independent T1/T2 marker authority review

Status: CLEAR for the scoped T1/T2 corrections at these exact SHA256 hashes:

- Script: `f40324f7f40d4c9172911356c9cfa34eebde402b5bcd40f8bd75b6b50c75f87d`
- Tests: `350d6eafd6749b260f299c35a4abe0eceb7cf9924d7ac855944b9ae18c487b18`

No remaining scoped findings. Review was read-only for sources and Git. Only this evidence directory was written. No privileged command, native execution, archive acquisition, or Git/GitHub mutation was run.

T1: Create's `parent_acquired` prevents stale initial-validation failures from restoring a parent it never acquired. Each attempt's held marker is validated by inode identity and must be root-owned mode000 to authorize locked-parent recovery. Both helpers serialize their mutations using parent flock. Crucially, failed creation retires its marker before releasing parent authority under that flock; if retirement fails, it retains the parent lock ownership. This closes the earlier intermediate-snapshot bug where failed A's root marker could authorize delayed recovery over B. Successful recovery likewise retires the marker before releasing parent authority. Same-UID pathname substitution cannot change the held marker inode or manufacture its root-owned state.

Independent `marker_control.py` executes the exact two embedded helpers using simulated metadata and records the failure-A, successful-B, delayed-A-recovery sequence. A's delayed recovery rejects, and B's parent and marker remain root-owned. Evidence: `marker-cross-attempt-control.json`. Privileged metadata and flock operations are modeled; this is not a real privileged or concurrent qualification.

T2: Caller defers recovery and marker-cleanup exceptions until after closing root, marker and parent descriptors. Independent execution of the new actual-FD regression confirms all three descriptors reject fstat with EBADF after rejected recovery.

Four focused tests independently passed, 0 failures/errors/skips, 0.008 seconds: marker retirement/stale helper rejection; unknown marker recovery refusal; recovery failure actual FD closure; malformed create-output recovery. Full output: `focused-tests.log`.

Partial restoration failure may leave the parent root-owned and require operator repair; the implemented path fails closed and reports recovery failure. A hostile same-UID actor can cause denial by manipulating its writable objects; this review establishes no cross-attempt authority release through the reviewed paths. This is scoped approval of T1/T2, not native or OCI qualification.

## sol-review/marker-cross-attempt-control.json

SHA256 `602ed917c99af634d5cf8badfcf39fd5fe7beab54dec88634e50582033460452`.

## sol-review/marker_control.py

SHA256 `feb167af06a081bb740421117259edcd7b2f61ea529f29f1067456de1d1aee0a`.

## sol-review/focused-tests.log

SHA256 `23aa5914792e0d3be3e48df0edd15ae4658725161ccbebb523b250de62edc864`.

