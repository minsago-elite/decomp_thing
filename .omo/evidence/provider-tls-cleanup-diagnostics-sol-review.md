# TLS cleanup diagnostic source review

## Terminal verdict

**CLEAR_SCOPED** for the exact test-only diagnostic delta. No source blocker found. Root may submit this source to the normal authorized Actions compilation/qualification path. This is not a Kotlin compilation, TLS test pass, explanation of the hosted failure, or production fix. Actual495 first failing cleanup subpredicate remains unknown.

Read-only source and retained-artifact inspection only; no source edits, tests, compiler/JVM/TLS/socket/network/native/proc/Git/remote/CI/authentication/model operation. Other owners' work was preserved.

## Exact pins

Worktree `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`:

| Artifact | SHA256 |
| --- | --- |
| build/provider-tls-cleanup-diagnostics/source-freeze.json | f0af6a66ae89cd59ad9a353188545ca516c3a254d2f7d7fcc3ee3747d7505723 |
| current and proposed AcpProviderCredentialFreeTlsFixtureTest.kt | a2a38f8cca2d8c4592f1f331286a6ad816f34ca2864c61b6fad2d047d4369b9b |
| retained before source | 254eb0fa63f085a772e09d3bfb6d57790721d82a20e7cdf63a7f7f6fe7605e68 |
| source-delta.diff | fb90351699885f94aad220fc1d8ea9b5700d842e30f3f51198f34b3675daf490 |
| static-source-checks.json | 4c73b25609af899fa3e8ae5fe8f14ed1f028c3e3827071b8f7f629b60435cbf1 |
| current production AcpProviderBroker.kt | 9bcb01a14be5cde023565d864ac1246cce10632dc05bc735f52a39d688b3334a |

All six freeze file entries rehashed and match. Current test source matches the proposed snapshot; production Broker matches the retained before pin. Prior source freeze1b642d501bcabba25c97d9cd94f15e579696a7d4b6dd56a927513885e9693206 remains historical. Independently extracted final fixed-negative method region, through the next private helper boundary, is byte-identical before/after (SHA8518e4d44b567bce5dd82416e5d7109fc75e93e4e9d715e9e34257e106cfaa98). The diff is confined to the four identified methods, two cleanup-helper regions and their new private observation helpers.

## Exception and timing control flow

The unknown-header, missing-authorization, bounded-response and cancellation methods now catch/rethrow the exact body failure and pass it into their existing finally cleanup. Cancellation's first close exception therefore survives its existing retry rather than being replaced by a later sticky-UNVERIFIED exception.

observeFixtureCleanup retains the first broker-close/backend-assertion error as cleanup primary, always attempts the same fixture close in finally, and suppresses a later fixture error onto the first. When a body primary exists, cleanup failure is suppressed onto it; otherwise cleanup failure is thrown. Identity checks avoid self-suppression. Existing backend, shared-grace and VERIFIED assertions remain on their original successful-cleanup path. Cleanup failure cannot produce a passing body.

Each helper still computes one original absolute deadline before broker close and passes that same deadline to fixture cleanup. There is no new close, cancellation, wait, retry or grace. Post-failure diagnostics can consume time inside the already-failed attempt; they do not reset the deadline. The cancellation elapsed assertion and earlier fixed-negative method remain unchanged. Production irreversible UNVERIFIED is untouched.

## Diagnostic safety and boundedness

Each observation is a stackless CleanupDiagnostic with suppression/stack generation disabled and at most2048 rendered characters. Values are fixed enum/phase/scenario labels, bounded owner count/rows (maximum4), booleans, integer execution state and elapsed/budget/interruption facts. No exception message, arbitrary class name, wire, header, authorization, request/body, receiver/parser content, path or thread stack is rendered. The code does not traverse sensitive authority/wire/receiver fields. References are sampled only for nullness.

ThreadPoolExecutor shutdown/termination and fixed executor Future state are sampled without socket/connection getters, queue/worker locks, I/O or waits. Owner traversal requires admission closed and transport executor terminated and takes the existing owners-list monitor. For these test-owned paths the synchronous start has returned, and production source confirms owners mutation occurs during start/cleanup, not an active transport-worker callback. No active backend producer or new socket-lock operation is introduced by this observation. This is a local test-path assessment, not a general concurrency API guarantee.

Reflection/format failures yield UNAVAILABLE. If backend state cannot safely be sampled after termination it yields UNAVAILABLE_BACKEND_NOT_TERMINATED. Present raw/TLS/connection references explicitly retain closedness=UNOBSERVED. Owner counts beyond4 are marked truncated. Thus a reference is not mislabeled open, a missing sample is not absence, and post-failure state is not represented as the historic return of backend.closeWithin or lifecycle.awaitTermination. Diagnostic failure does not replace the original error under ordinary throwable behavior.

## Limits of clearance

The source adds failure observations only. The retained actual495 evidence demonstrates four cleanup failures but lacks the concrete first-close predicate/reason. A later terminated executor or cleared reference cannot retroactively establish timely cleanup. A future diagnostic can narrow backend/lifecycle/deadline hypotheses while leaving the historical cause unknown. No timeout extension, policy relaxation, sticky disposition reset or production behavior change is supported by this review.

Compilation and runtime verification remain NOT_RUN for this exact source. Actions may qualify it after root's release; this scoped clearance does not qualify native DNS, provider/model behavior, private trial execution or the separate native18-test setup.
