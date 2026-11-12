# #734 active repair cancellation usage-drain evidence — 2026-11-12

Source commit: `26ce828787ed75db3cd0a958ee409c6beba080a8`, on #1943 head
`2c9d72d69181a04f590c7aa29951dace1227afed`.

The focused regression drives the public active-repair path through the
scripted ACP harness. It sends two tool-call updates against a one-call host
limit, then waits for the host's `session/cancel` notification before returning
the final prompt response with token usage. The host keeps the response
collector active during the bounded cancellation grace, retains the reported
usage, and preserves `LIMIT_EXHAUSTED` as the stop reason. The paired case
withholds the final response and verifies that tool exhaustion remains
classified as `LIMIT_EXHAUSTED` when usage is unavailable. Ordinary completed
turns with missing or invalid usage remain protocol failures under separate
controls.

Focused command:

```text
./gradlew --offline test --console=plain \
  -x verifyFrontendToolchain -x frontendInstall -x frontendBuild \
  -x generateFrontendAssetManifest -x verifyFrontendAssets \
  --tests 'decompengine.repair.TraceGuidedRepairTest.active ACP repair preserves tool-call exhaustion when final usage arrives during cancellation' \
  --tests 'decompengine.repair.TraceGuidedRepairTest.active ACP repair preserves tool exhaustion when cancellation yields no final usage'
```

Retained JUnit result: `TraceGuidedRepairTest`, **2 tests, 0 failures, 0
errors, 0 skips**. The two frontend asset tasks were excluded because the
exact-source snapshot does not contain generated `frontend/dist` assets. Kotlin
compilation and the focused test task completed successfully.

This is local scripted-peer evidence for the cancellation/usage classification
boundary. It does not qualify live-provider behavior, successful production
validation under #236, process-death or power-loss behavior, or hosted exact-head
CI. The #1943 required-contract lane also has an independent existing host
mount-event cleanup failure; this focused run does not diagnose or waive it.
