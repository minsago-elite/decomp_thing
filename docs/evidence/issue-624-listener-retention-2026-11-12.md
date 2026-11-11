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
