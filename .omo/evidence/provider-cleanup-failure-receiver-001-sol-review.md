# Cleanup failure receiver001 — independent fixture source review

## CLEAR_SCOPED

Read-only inspection of the current narrow test diff and web-packaged verifier wiring. No tests/JVM/native/process/network or Git mutations; only this report written. Production Broker and other authors' files were not edited. Actions execution remains pending; no runtime qualification is inferred.

Exact observed source pins:

- src/test/kotlin/decompengine/acp/AcpProviderBrokerReviewRegressionTest.kt: `3bed4bbbb27535ea178b9a32dfe7341e4d2a59b8d04e106c39c7333f7adc050f`.
- .github/workflows/ci.yml: `2f2c5b3162bdb2593a1dce6d9cd32aa3de1cc4b16c869f23465ef0d5b82d9b8f`.
- build.gradle.kts: `ddd281eef04fcf3e33312c739316d610d312e7f47a954c62292497bb5d2ba5a9`.

The regression test at173 opts in to expected failure callbacks only for `first cleanup operation survives later failures and successful retry`. Receiver294 defaults expectFailure=false; failed301–304 still checks that expectation before incrementing. Every other Receiver() remains strict, and timedOut still fails. The change does not swallow exceptions generally or relax production cleanup semantics.

The first finishTransport invocation now reaches an explicit failure count1 assertion187; after clearing the raw socket and invoking finishTransport again, failure count2 is asserted191. Existing sticky first-operation CANCEL_RAW_CLOSE assertions, cleanupFailed true, resourcesClosed false, completed0 and body-byte erasure all remain. This models the intentionally persistent failure notification instead of the old fixture throwing inside failed() and preventing the test from checking its intended postconditions. An unexpected complete or missing/extra failure callback still fails the test. No production path or status is altered.

The observed .github/workflows/ci.yml web-packaged command142–145 invokes both verifyAcpProviderGuardianDistribution and verifyAcpProviderDnsDistribution alongside the existing archive/distribution checks, inside the existing owned-JDK wrapper. Both named tasks exist at build.gradle.kts2169/2195 and depend on installDist; guardian checks its installed authenticated binary/digest, DNS checks installed worker bytes and application commitment. This is coherent narrow CI wiring, not proof that these tasks have run or that all distribution/native boundaries are qualified. The review did not expand into the implementation of those existing verifier tasks or the concurrently changing Broker.

All three observed hashes were rechecked unchanged before writing this report. Scope is this test-fixture correction and the two verifier invocations only; root retains Git/release custody. No source correction requested.
