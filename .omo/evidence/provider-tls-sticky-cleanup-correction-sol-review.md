# Independent sticky-UNVERIFIED negative fixture review

Verdict: ITERATE — one failure-path teardown gap.

Reviewed test SHA256 `5798f7b2c2c03ec3a4470c9ba9b654352865fa190a8f2fb7c1dba0b347373b30`; source-freeze.json SHA256 `2cebaa7bee3e2f8c770bbfbf034f60f86145079c399b6fe90c960c183ce9e195`; verification.json SHA256 `e0346e0260cdeb6dfcd17cd1ab27076e511ff50059ffa0245d3c66c0fa2a31b2`.

Artifact/source inspection only: no JVM/socket/native rerun, source/Git/remote/CI/auth/model changes or agents. All evidence-listed hashes and all32 productionUnchanged hashes independently match. Independently removed only the target method range from held before/current source and confirmed the remaining bytes identical; held refused-port correction and every other test remain unchanged.

## T1 — P2: finally waits for lifecycle termination without guaranteeing shutdown

The revised recovery block obtains lifecycle and awaits termination, but never calls shutdown itself. It assumes the main try reached broker.close(), which performs lifecycle.shutdownNow(). If entered.await, the first closeWithin assertion or an earlier snapshot assertion fails, execution jumps to finally before broker.close(). Test recovery releases/joins the worker and closes the backend, then waits on a still-active ScheduledThreadPoolExecutor. AwaitTermination does not shut it down; it consumes the remaining deadline, fails and leaves the scheduled lifecycle alive. Its periodic task is scheduled at broker initialization, so this is a real owned resource rather than a dormant executor.

Explicitly shut down the test-owned lifecycle before awaiting it, in teardown that runs independently of earlier test assertions. Repeating shutdownNow on the normal already-shutdown path is safe and does not upgrade the broker's sticky UNVERIFIED proof. Preserve the existing single recovery deadline, actual worker/backend join, fixture finally and primary-failure/suppressed-cleanup evidence. Ensure an earlier recovery assertion does not skip initiating lifecycle shutdown. Add or retain a narrowly injected early-body failure control proving the lifecycle is terminated and the primary failure remains primary, without weakening production behavior.

## Confirmed scoped correction/evidence

Normal-path recovery retains the actual submitted Future, releases and joins it, verifies the concrete backend/executor and owned future counts, awaits lifecycle and closes fixture/listener/sockets under one existing policy recovery deadline. The original bounded miss and repeated broker-close failure/UNVERIFIED assertions remain; no timeout or production predicate changed. The production broker still immediately rejects retry after UNVERIFIED, and source hashes match held freeze.

Retained old-control.log selects exactly1test and fails in sticky broker retry from the old closeRawVerified teardown. Current-control.log selects exactly1test and passes with0skips/aborts; both retained compile logs are successful and output origins identify held old/current test directories and unchanged main classes. These observations are artifact inspection, not an independent execution claim.

The other four hosted TLS cleanup failures remain unresolved; their inspected traces do not establish a decisive concrete backend/lifecycle subpredicate or shared cause. This correction cannot qualify broad TLS integration/provider/native/live/hosted gates or justify weakening those controls.

---

# Lifecycle-line correction rereview

Verdict: ITERATE — shutdown initiation still depends on earlier recovery steps succeeding.

Exact current source SHA256 `17cd7eff88044aad286855039e971688ce3d4969ada427aa0a3feb43ea158314`; new freeze SHA256 `92b0730700e115601c219d6603a3b8fbd19410f9a7febdfa4c44361bda94949e`; verification SHA256 `f7f3c95cd328ad13f845859fc3ed2fa47f6b798dfb1206d18853760cced5f214`. Initial review above remains preserved. Read/hash/source inspection only; no JVM/socket/native rerun, source/Git/remote/CI/auth changes or agents.

The added lifecycle.shutdownNow fixes the demonstrated early-body assertion case when subsequent recovery steps succeed. Retained early-failure artifacts show prior source1owned thread versus corrected0owned threads/0new sockets, with the original assertion primary and the disclosed sticky-precondition mismatch suppressed. Exact unmodified corrected negative control records1pass with0skip/abort/failure. All new listed evidence hashes, current source pin and all initial production pins independently match. Removing the single added shutdownNow line reproduces the prior held source exactly, hence refused-port and outside-method bytes remain preserved.

Remaining original T1 requirement: shutdownNow is placed after worker.get, assertTrue(transport.closeWithin(...)) and assertBackendCleanup. If worker.get times out/is interrupted, or backend cleanup returns false/assertion fails, control goes directly to fixture.closeVerified and the catch; lifecycle.shutdownNow is never reached. No earlier broker.close is guaranteed after an early body failure. Thus a recovery failure still leaves the scheduled lifecycle running, precisely the earlier review's requirement that initiating lifecycle shutdown must not depend on prior recovery assertions. The new probe does not exercise a recovery-step failure.

Move lifecycle retrieval/shutdown initiation ahead of blocking/asserting recovery steps, or put it in an unconditional nested finally that runs even when worker/backend recovery fails. Maintain the same deadline and preserve primary/suppressed errors. Verify a narrowly injected failure before the current shutdown line (e.g. recovery assertion or failed worker wait) cannot skip lifecycle shutdown; external resource census must not treat suppressed cleanup errors as proof of success. Do not alter production sticky-UNVERIFIED semantics or any other TLS failure assertions.

Other four hosted TLS failures remain unresolved, and no broad provider/native/live/CI qualification follows from either retained single-test control.

---

# Unconditional lifecycle placement terminal rereview

Verdict: CLEAR for this single negative-fixture cleanup correction. Both earlier ITERATE sections and all prior evidence remain preserved.

Exact current source SHA256 `254eb0fa63f085a772e09d3bfb6d57790721d82a20e7cdf63a7f7f6fe7605e68`; freeze SHA256 `1b642d501bcabba25c97d9cd94f15e579696a7d4b6dd56a927513885e9693206`; verification SHA256 `208c4715854b8be4d54e00fc1dea1d0e529d4844c104242db3498a96c816b6d5`; handoff SHA256 `90ee8419a696d30ae30932463b8a50750b16a66abb0fbc2eccd23112de8bf561`.

The lifecycle lookup/shutdown is now the first recovery operation after release.countDown, inside the fixture's unconditional finally guard and before worker.get, backend closeWithin or any cleanup assertion. Thus earlier recovery failures can no longer bypass initiating lifecycle shutdown. Later lifecycle await still uses the same shared existing recovery deadline. Normal-path actual worker future join, concrete backend/executor/future-count checks, lifecycle termination, fixture/listener/socket cleanup, owned-thread census and deadline assertion remain present. Primary test failure and suppressed recovery failure handling are preserved.

Independently verified all new evidence/source pins and the unchanged production source pins. Removing the moved lifecycle block from old/current yields identical bytes; removing the target method from current and the initial b5773dec-held baseline also yields identical bytes. Held refused-port correction and other four TLS control assertions are therefore preserved. Production still treats UNVERIFIED as sticky and rejects retry; no production predicate or timeout changed.

Retained exact current negative control discovers1test and records1pass,0failure/skip/abort. New controlled body+recovery failure evidence records CONTROLLED_RECOVERY_FAILURE as suppressed under the retained primary in both versions; old placement leaves1owned lifecycle thread, new placement has0owned threads/0new sockets. This specifically exercises failure before the earlier shutdown line, rather than merely a body failure followed by successful recovery. External census is bounded evidence of the probe's resource cleanup, not an extension of the fixture grace or a claim its deliberately injected assertion passed.

This was read/hash/source/artifact inspection only; no JVM/socket/native rerun, source/Git/remote/CI/auth/model changes or agents. No remaining findings within this correction. Other four hosted TLS cleanup failures remain unknown and unchanged. This approval establishes neither broad TLS/provider/native/live/hosted qualification nor resolution of those failures.
