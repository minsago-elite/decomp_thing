# Web workflow scheduler summary

The authenticated bootstrap response may include `runtime.scheduler`. It is an
additive v1 field; older responses without it remain supported and the Runtime
view labels the measurements unavailable. This snapshot does not enable workflow
actions or grant admission authority.

For the application-owned web workflow executor, the snapshot reports a server
`sampledAt` timestamp, fixed source `web-workflow-executor`, `approximate: true`,
`running`/`stopping` lifecycle, active worker count, configured worker limit, queued
task count and configured queue capacity. Counts are canonical decimal strings,
with the owned executor's maximum two workers and 32 queued tasks enforced in the
contract. Semantic checks reject active/queued values above their respective
configured limits. These are independently read aggregate observations, not an
atomic scheduling decision. Queue capacity comes from configuration rather than
adding two racing queue samples.

When an executor is borrowed, the service reports `state: unavailable` and
`EXTERNAL_EXECUTOR`, without fabricated zero counts. Reads require an initialized,
open service, perform no storage acquisition or recovery, and do not start worker
threads or workflow tasks. The projection includes no job identities, thread
names, paths, process diagnostics or host-wide resource values. HTTP authorization
uses the existing private bootstrap boundary.

Runtime displays the snapshot already retained at the most recent session check.
Navigation does not make another metrics request or start polling. Units, source,
sample time and approximate scope are explicit. Queue position and start time are
not reported; aggregate depth does not imply strict FIFO order. Free capacity does
not override the separate workflow-capability result. Logout clears the Runtime
snapshot with the rest of private session evidence.

Verification:

- 163 web/journal JVM tests pass, including an inert saturated one-worker/one-slot
  queue, configured default limits, shutdown lifecycle, absent-root preservation,
  borrowed-executor unavailability and exact shared wire-fixture projection.
- 40 valid and 31 invalid contract fixtures pass the shared verifier; frontend
  decoding covers the same fixtures, including saturation, unknown metrics,
  invalid bounds, a false exactness claim and inconsistent capacity.
- 257 frontend tests, lint and typechecked `distZip` pass. Runtime tests cover
  sample rendering, no extra request, unknown values and logout cleanup.
- The packaged history browser verifies idle 0/2 workers and 0/32 queued tasks,
  server sample time, approximate/unknown-position labels and no navigation-time
  request. Existing session, activity, report and byte-preservation checks pass.
  Evidence: [web-scheduler-summary-20260905.json](evidence/web-scheduler-summary-20260905.json),
  UI build `d305e22070c22253a4ca9e0279ebe5b7e585d157b7975f56a6d9cbb60aa3b11f`.
  No workflow ran in the browser journey. Chrome used test-only `--no-sandbox`;
  shutdown and owned-work cleanup were confirmed.

This advances #181 and consumes the private Runtime surface from #166. Per-attempt
queue position, broader worker-resource accounting, provider measurement-time
provenance, configured monetary estimates and full D4 qualification remain open.
