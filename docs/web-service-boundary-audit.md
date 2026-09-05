# D2 service-boundary audit

This audit concerns issue #158 at application commit `98778b6`. It establishes two
acceptance criteria, not completion of D2 or the full service migration.

| #158 criterion | Finding | Evidence and remaining scope |
| --- | --- | --- |
| Legacy and new controllers share service operations | Partial | Upload, job/history and fixed journal reads use `WebJobService`. `WebViews.renderAgentProgress` still opens a journal path; exploration and repair HTML rendering also retain report reads. Full adapter parity has not been established. |
| Public DTOs omit private storage/diagnostic data | Partial | Explicit legacy job projection and fixed JSON errors omit persisted paths/diagnostics; legacy/v1 progress projections omit prose, plan entries and paths. Retained-label classification and remaining HTML/report surfaces still need audit. |
| Injected stores/adapters support tests without native tools or live agents | Satisfied | `WebJobService` accepts `JobStore`, legacy adapters, durable adapters, an executor, a workflow-store factory and a diagnostic mapper. The tests use inert callbacks, local fixtures and injected persistence faults. |
| One lifecycle/authorization boundary for mutations | Partial | Upload/start operations acquire the service's writable ownership/lifecycle boundary, but `UploadServer.access` exists only in SPA mode. Legacy mode does not apply the same session/origin boundary. |
| Independently bounded request/background execution | Satisfied for production-owned executors | `UploadServer` owns a 16-thread HTTP pool with a 64-entry queue. `WebJobService` separately owns a pool capped at two workers and 32 queued tasks. Both reject excess submissions. Tests cover saturation, admission release, cancellation of queued work and shutdown. |
| Existing job/reconstruction and CLI/core regression coverage | Partial | Web, durable service, journal and job/attempt-store suites cover retained behavior. This audit does not run the broader reconstruction and CLI/core regression scope. |

## Injection evidence

`WebJobServiceTest` proves uploads/reads remain inert, injected legacy callbacks receive the
same stored job, concurrent starts admit one operation, rejection releases admission and
borrowed queued tasks cannot run after revocation. `DurableWebWorkflowTest` injects adapters
that only write fixed report fixtures or wait on latches, plus `attemptStoreFactory` failures
at publication boundaries. It checks exact run/input identity, retries, limits, recovery and
uncertain publication without running native analysis or a provider.

`WorkflowAttemptStoreTest` adds local persistence/reopen, ownership, transition, compare-and-set
and crash-boundary checks. The test fixtures exercise the service's real storage layer rather
than replacing all storage semantics with a successful stub. This establishes testability;
it does not qualify any production durable adapter, which remains separately capability-gated.

## Resource evidence and limits

The HTTP executor and workflow executor are distinct instances and do not share queues.
Request deadline scheduling uses one separate thread, removes cancelled timer entries and
cancels each active request's timer in `finally`; the timeout begins when the request handler
starts. Service pool arguments are restricted to 1–2 workers and 1–32 queued tasks. Borrowed
executors are explicitly reported as unknown telemetry; their resource policy belongs to the
injecting caller and is not claimed to meet the production-owned pool bounds.

`WebJobServiceTest` saturates a 1-worker/1-queue pool and verifies a third admission is refused,
then that admitted work completes after release. `UploadServerTest` exercises the default
worker/queue bounds while serving HTTP status requests. `WebShutdownTest` runs an inert child
JVM and verifies cooperative and uncooperative shutdown/restart behavior. These tests plus the
explicit pool construction establish separation and finite production capacities. They do
not establish HTTP saturation latency, fairness, a global memory ceiling or production soak
performance; those broader qualification requirements remain open.

## Retained verification

The machine-readable [verification record](evidence/web-service-boundary-audit-20260905.json)
records the exact source commit, command, per-suite counts and log hash. The run includes all
web/journal tests plus `JobStoreTest` and `WorkflowAttemptStoreTest`. This documentation-only
audit does not rerun frontend/browser suites or claim native/live-agent functionality.

## Subsequent exploration renderer migration

The legacy job controller now reads `exploration.json` through `WebJobService.readArtifact`
using the selected report prefix and a 1 MiB limit, matching the v1 exploration source ceiling.
Strict JSON decoding rejects duplicate keys and malformed input before supplying a JSON object
to `renderJob`. The exploration renderer no longer performs file I/O; absent explicit input
renders an unavailable report even if a file exists beside the job. Malformed report shapes
also render unavailable without making the entire job page fail.

A regression compares differing supplied/stored reports and proves the renderer uses only
supplied data. HTTP checks preserve the existing confidence/candidate display for valid data
and cover missing, malformed, oversized, duplicate-key and wrong-shape input with unchanged
report bytes. This completes the exploration-specific direct read identified above; repair
history, reconstruction and artifact inventory reads, full privacy classification, legacy
authorization and broader CLI/core qualification remain separate unresolved migration work.
