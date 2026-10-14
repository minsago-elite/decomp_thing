# Issue 89 real-signal controls 001 — independent review

Verdict: **CLEAR_SCOPED** for the four retained benign-child signal regressions. No source blocker found. This adds actual scaled Unix/Python signal evidence to the prior mocked controls; it does not qualify production 20/120-second elapsed behavior, HTTP/network execution or arbitrary C/kernel preemption.

GPT-6.1 Sol. Source/AST/data/hash inspection only; no replay, signals/exits, child/native/network/JVM/compiler, Git or remote operations. Only this report written; root retains custody.

## Exact pins

Worktree `.claude/worktrees/gcc-source-build-ownership`:

- Freeze `build/gcc-fetch-real-signal-controls-001/freeze.json`: `2b5eb5bbc0d52d03a638caa35deb59728e908f365dd39b8bcbeb68543d4743dd`.
- New test `tests/oracle/test_fetch_gcc_oracle_signal_deadline.py`: `6c5bcd328622fa379dabe5176ebe6b2c4483bee5ee8d13786b4188261240069f`.
- Unchanged production fetcher: `ce51521da9ad3f308638558834320d62e6a6a1b1649f7d2476d2c76a8c53db9c`.
- Retained results: `7d6ce11bb5c6536572ca8824ae6ecae032ec8953dd61bd3f74902bc8035e1da9`; log: `9b0cc48775127137d3d927b3369ad964a13d1a3ab93d407a41c8e4756b5f9109`.

All freeze-listed source/evidence hashes matched, including frozen test copy. Independently reconstructed all four child-script hashes from AST string literals and matched each result's expected return, exact marker, empty stderr, absolute Python/source paths, minimal environment and recorded timeout. Retained result is four tests, zero failures/errors/skips, 0.913687478 seconds; no rerun performed.

## Coverage and controller

| Actual retained child | Supported conclusion |
| --- | --- |
| ATTEMPT_UNWIND_TOTAL_ARMED; exit124; 0.371825s | Production FetchClock, with test-only 0.1/0.3 globals, receives an actual attempt alarm. BlockingExit checks the dedicated attempt exception and a live one-shot ending no later than original total plus 30ms sampling tolerance. Actual total alarm terminates the sleeping unwind via fatal124 before its finite2s fallback. |
| SUCCESS_STATE_RESTORED; exit0 | Actual previous handler, zero timer, original mask and no pending alarm are restored after successful guard teardown. |
| INHERITED_ALARM_UNCHANGED; exit0 | Child establishes actual blocked-only and blocked+pending pre-guard states; guard refuses without changing handler/timer/mask/pending state. Only the child's own PID is signalled. Test-owned zero-time drain consumes its pending alarm before unmasking. |
| EXISTING_TIMER_UNCHANGED; exit0 | An actual preexisting2s timer and handler remain owned by the test after guard refusal; test-owned finally disarms it. |

Each fixed script is launched synchronously through `subprocess.run`, isolated `-I -B`, closed stdin and explicit HOME/temp paths below repository build. Child import uses a non-main run name, so no fetch/main execution occurs. Child audit hook is installed before import and denies the network/resolution and process-launch paths relevant to these fixed scripts. The scripts create no descendants; this is not a general security sandbox claim. Completed run results imply direct-child collection through subprocess.run; no independent process-group/FD census receipt exists. Timeout handling relies on subprocess.run's direct-child kill/collection contract, not a new custom process supervisor.

Per-child communication timeout is `min(3, remaining aggregate)`; aggregate admission is20s, and the runner also rejects elapsed>20 after completion. The aggregate is cooperative between cases/postchecked, not an independent hard parent watchdog over spawn/filesystem/cleanup. The4096-byte diagnostic assertion is post-capture, not a streaming allocation cap. These limits are acceptable for the four fixed benign scripts/finite sleeps, and must not be represented as arbitrary untrusted-process containment.

## Platform, reliability and limits

Linux missing any required API fails explicitly. Non-POSIX or another platform lacking required APIs is explicitly unsupported/skipped; required Linux qualification cannot silently convert missing support into a pass. Non-Linux POSIX with all APIs is allowed to exercise the contract rather than automatically skipped.

The accelerated timers are intentionally scheduler-sensitive: a pause spanning the0.1→0.3 window can deliver the first callback only after total expiry, preventing the attempt marker; a pause between getitimer and monotonic sampling can exceed the30ms tolerance. Successful teardown's0.1s arm likewise can expire on a heavily stalled worker. Thus one local pass does not establish flake-free hosted scheduling. Such failures remain failures requiring diagnosis, not permission for retries, skips, production deadline increases or weakened assertions. Normal actual child times0.149–0.372s and generous3s safety timeout support this retained run only.

No real HTTP opener/read1, production20/120 elapsed test, inherited supervisor integration, partial-network cleanup, arbitrary C stall, native target, provider/auth/model or current hosted success is inferred. The blocked/pending states are deliberately established inside the child before guard acquisition; they model guard-entry state, not an independently exercised supervisor launch. Existing mocked19-case evidence and production source remain separate and unchanged. Root may proceed with the focused test checkpoint and hosted verification; no issue closure or new execution is authorized here.


---

# Additive rereview — real-signal generation 003

Verdict: **CLEAR_SCOPED** for the minimal sampling correction and separately retained successful003 run. Original001 review is retained verbatim above: its first5,454 bytes remain SHA-256 `2156083d2b15368634edd5fae7f8a36789ce65899d055171a392812589368565`. This addendum supersedes only the current-test sampling/budget observations, not the initial generation's historical evidence.

Exact003 freeze: `db0ad9ab53a02d24fd53602e6229436fae79f351e6890e1986f24dce4d8ba796`. Current test: `026ee3e24d131a7134e5ddad0dad53e2fec9e1f9dc4502733cf969efa094e1c9`. Production remains byte-identical `ce51521da9ad3f308638558834320d62e6a6a1b1649f7d2476d2c76a8c53db9c`. Results: `88e747531c44a978af9e7bf9cb6f1a89332a2cdc5bcdfa89a12336f760b6caa3`; log: `73ea66d8c3e732353c0b0f47caf738ff3d17b70a31cb1f7513c384e290b1f137`.

Read/hash/AST inspection only, no rerun or actual signal/process/native/network/Git/remote operations. All003 source/evidence pins matched. Prior001 freeze `2b5eb5bbc0d52d03a638caa35deb59728e908f365dd39b8bcbeb68543d4743dd` and failed002 freeze `1a680b6450b08aeedb1245fe726c2237721c8dbfbbaf5f8218cee78bc9948455`, including every listed evidence file and frozen source copy, remain exact.

Compared001→003 source: only test-only budgets0.1/0.3→0.2/1.2 and the before-getitimer monotonic sample change. The6:1 total/attempt ratio now matches production; this does not change production20/120. The check now uses `sampled_before=time.monotonic()` before reading the remaining timer and compares to `clock.total_end-sampled_before+0.03`. A later deschedule between the timer read and a second clock read can no longer spuriously tighten that upper bound. Retaining30ms allows the production callback's remaining-time computation/relative-timer arming latency; it is a sampling assertion tolerance, not a new runtime cleanup grace. A reset to a fresh1.2s total at the0.2s attempt boundary would exceed that upper bound and still fail.

Historical002 remains **failed**, four tests with three passes/one failure, no skips/errors. Its source had removed the30ms tolerance; retained stderr shows the upper-bound assertion failed in BlockingExit before marker/sleep/total-exit coverage, with return1 and empty stdout. No quantitative overshoot was captured. This does not prove a production timer defect or establish successful fatal-unwind coverage for002; nothing from that failed child is pooled into003 success.

Fresh authorized003 records four passes, zero failures/errors/skips, aggregate1.804543611s. Independently reconstructed all four exact child scripts from current source literals and matched recorded script hashes, expected return codes, exact markers, empty stderr, minimal environment/repository paths and3s child bounds. Attempt/unwind child elapsed1.386043399s, marker present, exit124; other three actual restoration/refusal controls return0. Before/after source pins match. No additional execution was requested or performed by this reviewer.

Finite2s fallback,3s child/20s cooperative/postchecked aggregate controller, platform refusal/unsupported classification, minimal environment and child audit policy are unchanged. Larger separation and corrected sample reduce a concrete timing race; they do not prove flake-free scheduling under arbitrary stalls. Timer delivery after total expiry, very long relative-arm latency or stalled startup can still fail conservatively. All original process-collection/output-allocation/FD-census caveats remain. No production20/120 elapsed, actual HTTP, C/kernel-stall, provider or hosted qualification is inferred. Root may checkpoint this focused correction and review; no retry, issue closure or expanded runtime authority follows.
