# Independent runtime003 corrective rereview

**CLEAR for this exact runtime003 correction of runtime002 R1/R2 and the added actual recipe-file pin producer.** The runtime002 ITERATE and all historical snapshots/results remain preserved. This is static source/pure-artifact acceptance, not current whole composition, C compilation, native capability, accepted preparation or candidate authority. The qualifier's independently owned F5 remains separate/pending.

## Exact frozen scope

Worktree `callable-evaluator-v2-evidence`; source prefix `oracle/acp/callable-evaluator-v3/source/`; evidence prefix `build/acp-decomp-effectiveness/callable-library-v3/`.

Runtime003 manifest **74ed6295aa471cf0a591f8f217266d074b607b97f8a33aa07a79e9c305ae150e** independently matches. All seven snapshots and eight evidence files match their hashes. Exactly runtime and its two test modules change from002; the other four owned files remain byte-identical.

| Frozen source | SHA256 |
|---|---|
| bounded_runtime.py | `604ca58765507a1d8b83d46c20a8dc8fedafeed5992ad6a3788e52d8610bea07` |
| build_contract.py | `64d60a10e9359fc590cd662d1c49740a7a34a26ea2ee43bc05626790073f0c85` |
| contracts/candidate-build-profile.json | `c700c1b0a18a63279006bb0efe00b953ef419c2fe984809d99144f4da197c03f` |
| contracts/visible-manifest-schema.json | `c3a64923081ee5cf614446832e40bd4d849494516bb3d43eb2cb089c5aafd743` |
| scope_gate.py | `1e82114d9a04d1b2f247e408604dcf4b47d69c06623cfa01da2d281d3a572c82` |
| tests/test_profile_limits.py | `1aabc8724a1b81b6f0e0e82e5547dd168b98a735c69f44ebd0e99a2d853a6e83` |
| tests/test_runtime_worker_proof.py | `7ea3ee8f13dadbaf3e16f99cca6517b1465574544638ab3f13ddbb8cd95d5ff3` |

Original runtime002 review **dc82a6572acb3d252dce0df4ec2b4b5d623f57070d90f03ec29f7187939a7915** remains unchanged. Prior001 manifest **1b3155562678c2450a7367885b7562920c731da12bf293e3d2da48ad46a99f03** and002 manifest **305e8ec027d45a26a40b0477ab03c971a0581578dccbf35888894be2f83cc326**, all their recorded evidence and source snapshots independently hash-match. Strict-consumer review input **75a5345907faf6f767ea55138894353bc9bfc29a632f9aeb8acc48a69ee83f97** also hash-matches; this rereview does not replace that owner's consumer assessment.

## R1 — fixed cleanup ends and post-observation checks: corrected

Frozen `_run_scoped:932–976` anchors cleanup before selector close. The wait end is cleanup_began+5, so selector close and acquired cgroup/pidfd kill work consume that same window. Only the positive remaining duration is passed to process.wait; no wait is entered after exhaustion. After successful return the code records the actual reap/wrapper status and samples time again; late success refuses.

Only a timely wait creates one subsequent verification end, wait_observed+5. Since wait_observed is before cleanup_began+5, the verification end is before cleanup_began+10; unused wait allowance is not transferred and no scan/kill renews either window. Inventory checks run before and after their actual observation, followed by a final check before absence/cleanup become true. Poll sleep uses only remaining verification allowance. A late empty inventory cannot pass the former shortcut.

Stream/controller and acquired handle closure occur before the final verification-end observation (`:987–1019`). A missed end clears cleanup/finalAbsence and nested scope absence, latches infrastructure failure, and prevents worker completion. Successful late wait retains rootReaped only as an observed historical fact; it does not invent timely absence. Report parsing/closure remains separately charged to the existing phase budget (`:1020–1043`), not a new cleanup grace. Handle failures, missing process handle, interruption/timeout/output failure and unverified cleanup remain fail-closed. Existing acquired cgroup-relative kill, unreaped-child pidfd acquisition, report separation and no numeric-PID signal fallback are unchanged.

The retained fake-clock controls (`test_profile_limits:305–322`) causally exercise late successful cleanup wait and final empty inventory, preserving wrapper status/stdout/stderr while requiring no cleanup/absence/worker exit;2s preceding work leaves exactly3s wait;5s preceding work prevents a second wait altogether. These are real source-path mock controls, not native or sleeping tests. This resolves both timing schedules proposed in002 R1 without quota changes.

## R2 — regular-file batch admission and safe opens: corrected

`_pin_files:561–619` now streams and admits the complete supplied batch before any of that batch's payload opens. Each input consumes the existing256-entry allowance before deduplication; resolved canonical paths require nonempty regular metadata and the existing16MiB/file ceiling. Duplicate metadata must agree. The count×per-file policy bounds total admitted bytes with no new allowance. Deadline checks bracket admission and reading.

Every pin payload open uses O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC. Its opened descriptor must still be regular and match the admitted device/inode/mode/size/mtime/ctime before any read/hash work. Chunked reads cannot exceed admitted size or the existing file cap; descriptor and pathname metadata must still agree afterward, and a final deadline sample precedes return. A FIFO/special replacement cannot block in the former plain open or reach payload reading. Missing/symlink/replaced/oversized/empty entries refuse; no prefix hash is promoted into a full identity.

`_nonprivileged_executable:215–245` uses the same nonblocking/no-follow descriptor safety, rejects nonregular/set-ID/inaccessible files before its fixed4-byte ELF read, reads file-capability metadata from that descriptor, and obtains the complete bounded byte commitment via _pin_files. The retained initial descriptor is compared again with the pin row and metadata. This covers the separate executable-reader path as well as post-run pin validation. Protected controller/report metadata and fixed source-module loading retain their existing trust boundary; this is not a claim that arbitrary filesystem syscalls are interruptible or that every unrelated trusted-source read has been replaced by this reader.

The actual inert control `test_runtime_worker_proof:130` injects a FIFO descriptor replacement, captures flags and forbids payload reads; it exercises both readers. It also refuses an invalid later batch element or an expired deadline before any payload open. Existing empty/mutated/entry-cap controls remain. The source explicitly keeps accepted RW-work executable recipes, so safe post-exec pin validation addresses the actual002 R2 path rather than hiding it behind an inert immutable-file assertion.

## Actual recipe-file producer and consumer seam

`_prepare_launch:630–646,665–687` adds each actual explicit file mount source from the validated closed recipe to the same common pin batch. Only exact system-root and owned cwd directory mounts are excluded; there is no inferred recursive private tree. Caller, shared object, source/header/intermediate/helper/cache files are included when those mounts are actually present. Canonical physical source rows join launchInputPins and its canonical digest; the existing post-cleanup revalidation covers them. Original worker argv/guest mappings/environment and RO overlays remain unchanged.

`test_actual_prepare_launch_pins_all_explicit_recipe_files_for_consumer` (`test_runtime_worker_proof:148`) invokes actual _prepare_launch and actual _pin_files on authored files and exact contained recipe declarations. It passes those produced SO/caller rows into the actual `_bound_runtime_inputs` with an independently reread admission map; it neither inserts a fabricated library row nor replaces the producer with a dictionary mock. A separate source/header recipe is likewise actually hashed. Same-byte SO replacement at a new inode refuses the original physical admission; changed/missing SO also refuses.

The fixture explicitly mocks fixed host executable/A3 selection and omits the two host launcher inventory entries. Its public ELF-looking placeholders and zero binding hashes are inert, not actual accepted machine/loader closure or native executables. Source inspection confirms `_bound_runtime_inputs:301–318` compares profile, physical admission rows, exact content digest and caller target identity. Its separate full consumer authorization/preparation rules remain another review's scope.

## Partial failure facts and exact error semantics

The same bounded result retains wrapper return, partial raw stdout/stderr, initial phase failureClass/timedOut and later cleanup/proof facts. A primary phase failure with successful cleanup is rethrown as that original exception. If cleanup also fails, existing source raises the cleanup exception carrying the shared bounded_result; Python exception context retains the original phase exception. Thus this review accepts preservation of partial/primary facts and fail-closed status, **not** an invented guarantee that the top-level exception object always remains the original. No new field silently replaces recorded wrapper status with worker status, and no late cleanup upgrades an existing failed attempt.

The27 controls cover late observations and retained raw facts; they do not separately inject every descriptor-close/dual-failure variant. The corresponding source paths were inspected. No actual process cleanup, retry or live attempt remediation was performed.

## Retained verification, exact dependencies and current drift

Runtime003 `pure-checks.json` **fea063da660aa09b564b7798f851eef58fcbbb226c94a58c5015fc1bba496762**, log **89adad7942e06a7f2bc5cfb44260063c5bd898174c85b87e54b8099f2d3b1b7b** and runner **fea9980befd432e3ca66a0acef0a57f9126fc2352eaf103de6b618f806ad3ecb** independently match. Actual retained log reports27=16 profile+11 runtime methods, zero failures/errors/skips/forbidden attempts. NativeDeny and ctypes.dlopen rejection are installed before discovery. All seven owned plus five dependency before/after maps independently equal the manifest. The initial26 receipt/log remains separate history; the final27 includes the reduced-remaining-wait control. This reviewer reran no test.

| Exact tested integration dependency | SHA256 |
|---|---|
| evaluate_candidate_v3.py | `ff929649380c8c58ffb81a34088bfe95931b1609856e8edb7551f6d5e105999c` |
| interface_gate_v3.py | `9238e9bcb93a0ef188a8defb8393b5a5f1b90cb7c40b43e7fa2ac04dfad92c54` |
| tests/run_static_tests.py | `30bea0fb1ff8cbc588189504b8a3c220d66dfeff8a525110611620ef13e18efd` |
| toolchain-001/build_helper.py | `c1fc436023aebfebd2a93b62364de7819d380e86f4df6b2035f0d6729806e2a0` |
| worker_exec_proof.py | `bb7ec2289dbe9eeea2e19416fc1e166d75dbc888651f8ad5cc03a76f7c6dbc93` |

All seven owned current files and five listed dependencies match at the review observation/final write; no drift within these12 paths is observed. `post-test-dependency-observation.json` is the frozen empty observation, not a promise that unrelated concurrent files cannot change. No historical118 result or schema6 result is relabeled current composition.

Separate consumer-pair manifest `static-process-f1-002/manifest.json` **15c657fcbb2c20279c9df52a96262ef65ebd8e67373ebf3bf841cda3d9e33180** was read/hash-checked as independent context and records47 pure passes. Its full artifact/source review is outside this terminal runtime gate; the verdict rests on frozen27 and the inspected actual-producer seam, not inflated aggregate counts. It does not cure the separately owned qualifier F5 or grant native execution authority.

## Disposition

No remaining blocking source finding in this exact003 runtime delta. Runtime002 R1/R2 are resolved in this generation;001/002 reviews and all A1/C reviews remain unchanged. Root must still bind the final evaluator/A1/A3/C/qualifier composition and independently clear qualifier F5 before considering the separately authorized compilation/native controls. Actual local/hosted kernel/namespace/ptrace/report/loader/cleanup behavior, complete matrix, preparation acceptance and immutable sealing remain unqualified.

Read/hash/AST/source-artifact inspection only. No source edit, tests, compiler/C/JVM/native/proc/process/CLI/policy/namespace execution, Git/remote/CI/auth/model action, attempt cleanup or descendant. Only this additive report was written.
