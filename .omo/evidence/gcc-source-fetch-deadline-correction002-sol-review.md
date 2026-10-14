# GCC fetch deadline correction 002 — independent source review

Verdict: **CLEAR_SCOPED** for the three captured #89 / PR1519 findings. No source blocker found in this narrow standalone-CLI correction. Fresh hosted qualification and actual OS signal/network behavior are not established by the mocked controls.

Reviewer: GPT-6.1 Sol. Read-only source/evidence/hash inspection; no tests, actual signal/timer/exit/network/native, compiler/JVM, Git/remote, authentication or model operations. Only this report written. Root retains checkpoint, remote and execution custody.

## Exact pins

All paths relative to `.claude/worktrees/gcc-source-build-ownership/`.

- Freeze `build/gcc-fetch-deadline-correction-002/freeze.json`: `7fbe77aae6b2b105fbeda65e3a08d1bbe837125482c0aaae2f8ac34ba0c0723d`.
- `scripts/fetch-gcc-oracle-source.py`: `ce51521da9ad3f308638558834320d62e6a6a1b1649f7d2476d2c76a8c53db9c`.
- `tests/oracle/test_fetch_gcc_oracle_source.py`: `9cc390d386e308163570cb00b17fcf565304b98b424f7dc3055854c0b569e987`.
- Unchanged verifier dependency `oracle/gcc/verify_source_lock.py`: `438730ba4964832bb8f577aac0116fb7e0f5fe02b31fe9e406f86155491360ee`.
- `pure-results.json`: `110a66c9ff0939edf0dea73b79d35b79799dbd0f1a41332e0c843fb47ac22957`.
- `clean-stage-results.json`: `90c1273576e1ebdcf29e7b399d82b73ad44360d93c1280b285f35adf24cf0c6a`.

Read all three exact bodies in root `build/active-review-checkpoint/after-b5-895-review/findings.md`, SHA-256 `8289f230d75bbcfb4024da17c870a46803966725d5fc7739ff578349364f131f`. Independently matched the two current sources, verifier dependency, and all thirteen freeze-listed evidence/source-copy files, including final clean-stage copies. Prior 001 remains a historical checkpoint, not replaced approval evidence.

## Finding adjudication

| Finding | Source and retained control | Result |
| --- | --- | --- |
| sTpe8: missing build parent in clean checkout | Test `setUp`, lines 53–54, creates the repository-local build directory before every TemporaryDirectory. The retained minimal-stage runner copies only three required inputs, checks build absent both before import/discovery and immediately before running the exact suite, then checks it was created. | Corrected; retained 19/19 clean-stage cases, no skips. |
| sTpfB: spent attempt timer leaves nested unwind unbounded | `FetchClock._expired`, lines 67–80, computes `total_end-now`, rearms that remaining original total before raising the attempt exception, and never resets the total end. Actual total expiry uses the expressly root-authorized standalone `os._exit(124)` route without I/O/finalizers/new cleanup budget. Lines 183–197 in tests inspect the timer from response `__exit__`; 218–244 cover terminal expiry during unwind, no new grace, and impossible mocked-exit return refusal. | Corrected within stated Unix/Python delivery limits. |
| sTpfH: inherited blocked/pending SIGALRM | Entry, lines 88–98, requires main-thread Unix APIs and rejects inherited blocked/pending SIGALRM and nonzero existing timer before replacing handler/arming. Teardown, lines 106–119, marks closing, blocks SIGALRM, disarms, performs one zero-time coalesced-signal drain, restores disposition, then restores mask. Entry-arm failure uses this same restoration path. Tests 199–216 cover no ownership mutation on refused entry and exact teardown ordering. | Corrected for sole CLI alarm ownership; no general shared-process takeover. |

## Timer/mask and ownership assessment

The attempt callback's rearm happens inside the handler, before response/file/TemporaryDirectory unwinding. Therefore those potentially expensive nested contexts are not intentionally run under a spent one-shot. At total expiry there is no Python exception-cleanup window to extend; unverified staging can remain and is never automatically treated as verified cache. An already verified atomically published target may remain, as before.

Teardown does not unblock and deliver an owned kernel-pending alarm to the previous/default disposition: SIGALRM is blocked before disarm and drain, and the previous mask is restored last. The closing latch makes a late owned Python callback harmless during this short restoration sequence; a successful return still runs the absolute `check()` after restoration. Acquisition changes no inherited mask, refuses existing ownership, and cleans up an arm failure after handler installation. The zero-time drain is finite and has no retry loop. This is a standalone main-thread CLI policy with no concurrent actor mutating/sending its alarm; it is not a composable in-process signal manager or a guarantee against arbitrary asynchronous external interference.

The retained controls mock signal APIs and `_exit` before exercising actual guard logic. The total-expiry test's raised fake BaseException permits test cleanup; it is not evidence that real `_exit` runs Python finalizers. Real OS delivery, kernel-pending/CPython-dispatch races and C-extension interruptibility were not exercised. Python handling can be delayed by C code or uninterruptible kernel operations; no absolute C-stall/whole-machine preemption guarantee is invented.

## Preserved contract and verification scope

Constants remain two attempts per official endpoint, 20 seconds per attempt and 120 seconds per artifact. Remaining-total retry sleep and decreasing `read1` socket timeout remain. Source URL/HTTPS, length, digest, signature/key/revision verification and no-overwrite publication are unchanged; verifier dependency is byte-identical. Verified cache reuse still verifies bytes, and concurrent/corrupt cache paths are not overwritten. Late verification/publication/cleanup/output/teardown observations cannot return success. Full CLI signature/archive/final provenance work is not newly covered by a single 120-second global bound: the total remains per `fetch_artifact` call.

The two retained runs each record 19 tests, zero failures/errors/skips, unchanged source pins and no forbidden audited attempts. Logs match the result digests. Their runners and test setup substantiate mocked signal/exit/network boundaries and the initially absent build-parent control. This reviewer did not replay them. These are focused deterministic retained passes, not a fresh hosted CI result or real network/signal qualification.

Root may proceed with the narrow source checkpoint and required hosted verification. No merge, issue closure, timeout increase, authentication/trust waiver, cache authority expansion or new execution is authorized by this report.
