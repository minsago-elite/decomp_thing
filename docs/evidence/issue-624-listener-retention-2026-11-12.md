# Issue #624 listener-retention sampling implementation checkpoint

**Implementation source:** `d4dc2df9e18adf1012f6da4ad9028b9a37b2dac2`, stacked directly on PR #1939 head `aae08783cce1f93537eb68778d4fc5e040991bce`.

This checkpoint adds a bounded main-world `EventTarget` registration probe to the packaged long-session soak. The soak records 24 post-GC samples at five-slot intervals after the Activity stream has drained and the app returns to the dashboard. Each sample includes active listener and target counts, bounded event-type counts, registration/removal accounting, renderer heap, and CDP backing-storage bytes. The evaluator fails closed on missing or inconsistent samples, listener accumulation after the warm-up sample, backing-storage peak growth over 16 MiB, or final residual growth over 1 MiB.

## Local implementation checks

On Node.js `v24.20.0`, the following completed successfully from the source tree at the implementation commit:

```sh
node --check scripts/check-packaged-web-browser.mjs
node --check scripts/packaged-browser-soak.mjs
node --test --test-reporter=tap scripts/soak626/*.test.mjs
```

Result: **29 tests passed, 0 failed, 0 skipped**. The helper suite covers registration accounting, duplicate listeners, explicit and automatic cleanup, garbage-collected targets, bounded sample parsing, and evaluator rejection cases.

## Qualification boundary

This checkpoint does **not** contain a packaged-browser execution of the instrumented 20-minute soak. The hosted packaged-browser CI run must execute on the exact PR head and retain its report before these new listener and backing-storage measurements count as runtime evidence. The probe sees page-main-world `addEventListener`/`removeEventListener` registrations and renderer backing storage; it does not count `on*` property handlers, browser-internal listeners, or worker listeners. The new limits are proposed #624 qualification bounds; this checkpoint does not close #624 or its dependency #219.

## Exact-head review corrections

Follow-up source checkpoint: `d4f76b546c69a33caae3df6e7cd53c0f7dc412aa`, directly based on the implementation source above. It corrects delayed `AbortSignal` accounting after target collection, makes observer-cap overflow fail closed without throwing from an app's registration call, validates bounded event types and monotonic accounting in the evaluator, and retains the existing 35-second stream-drain allowance. It also reports the 24 added dashboard navigations and drain durations; this instrumented workload is not directly comparable to the earlier rapid-switch soak.

At this exact source tree, Node.js `v24.20.0` passed syntax checks for `scripts/check-packaged-web-browser.mjs`, `scripts/packaged-browser-soak.mjs`, `scripts/soak626/listener-retention.mjs`, and `scripts/soak626/evaluate.mjs`, plus the full `scripts/soak626/*.test.mjs` suite: **35 passed, 0 failed, 0 skipped**. These are helper and evaluator checks, not a packaged-browser runtime measurement. The full 20-minute browser run on this exact PR head remains required.

## Dashboard-read settle follow-up

Implementation source: `cca26cfe053c56e3592f8ca9bea34512153b2a27`, directly based on the then-current PR #1948 head `aeb5026d21fd3702d1ca6626495c2fb53e2936d7`.

Each retention sample now starts an observation before navigating back to the dashboard. It tracks only same-origin `GET /nested/api/v1/jobs` requests, correlates each response and terminal loading event by CDP request ID, and requires the fixture job to be rendered, every observed listing request to complete with HTTP 200, and a 250 ms quiet window before sampling. The observation has a 20-second deadline and a 16-request cap; missing, failed, non-200 or excessive reads fail the soak. The report retains only bounded request counts, status codes and duration, not request IDs or URLs. The evaluator rejects incomplete or unsuccessful listing evidence.

On Node.js `v26.12.1`, exact source commit `cca26cfe053c56e3592f8ca9bea34512153b2a27` passed `node --check` for the soak and tracker modules, `git show --check`, and `node --test --test-reporter=tap scripts/soak626/*.test.mjs`: **40 passed, 0 failed, 0 skipped**. This verifies the tracker and evaluator controls, not browser event delivery.

The latest retained packaged-browser failure on the prior PR head timed out before authentication completed after a `404 NOT_FOUND`; it did not reach the soak or retention samples. Available logs do not identify the failing request path or establish whether the listener probe caused the failure. This follow-up does not claim #624 runtime qualification: a passing exact-head packaged 20-minute soak with retained listener and backing-storage samples is still required.
