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

## Subsequent repair/reconstruction JSON migration

Repair history and reconstruction progress now follow the same explicit-input pattern as
exploration. The controller's fixed report-name selection reads each through the shared
artifact service with a 1 MiB source ceiling and strict JSON decoding. Renderers no longer
open these files; callers must supply the JSON object. Existing `renderRepairHistory` job
and report-context parameters remain source-compatible, but omitted payload now means
unavailable rather than an implicit disk read. Valid supported report presentation remains.

HTTP regressions cover supplied versus stored values, missing/malformed/oversized/non-object
and duplicate-key reports, and unchanged bytes. Missing or undecodable reports show an explicit
unavailable/not-generated message. These read failures do not fail the job page or create
report files. This is bounded input handling, not complete semantic validation or certification
of report prose as public. Artifact inventory enumeration/metadata still performs renderer I/O;
legacy authorization, privacy classification and broader CLI/core qualification remain open.

## Subsequent artifact listing migration

Artifact enumeration now runs through `WebJobService.listArtifactSummaries` after job/attempt
report-context validation. It returns relative artifact paths, display names and 64-bit sizes;
`WebViews` performs neither file enumeration nor metadata reads. The traversal retains its
10,000-entry/32-level limits and exclusions for the selected report root's `source-tree` and
`runs` directories. Sizes come from enumeration attributes rather than a later renderer stat.
The root must be a directory; missing roots yield an empty inventory, and listing failures
render unavailable without failing the job page. No partial inventory is presented on failure.

Tests compare explicit supplied metadata against different stored files, preserve sizes above
2 GiB, verify root exclusions and check the HTTP unavailable state at the traversal bound.
This is a legacy metadata inventory, not a transactional snapshot or download authorization.
The existing filesystem walk does not establish retained-descriptor containment across every
concurrent directory mutation. Downloads still require their independent artifact checks.
All legacy renderer filesystem I/O identified by this audit is now outside `WebViews`; full
legacy/v1 service parity, inventory containment qualification, privacy, legacy authorization
and broader CLI/core regression work remain open before #158 can be closed.

## Same-store HTTP adapter parity

A real HTTP regression now switches one temporary store through legacy → SPA → legacy server
lifetimes. It uploads an inert ELF through legacy multipart POST, reads it through authenticated
v1 after restart, uploads a second ELF through authenticated v1, and reads both through legacy
after another restart. Explicit comparisons cover job identity, filename, uploaded status,
creation/update timestamps, byte count and common ELF metadata. The all-bits-set entry point
retains the documented legacy signed numeric `-1` and v1 lossless `0xffffffffffffffff` forms.

The test verifies exact `job.json` and `input.elf` bytes after each mode transition and read,
and injected workflow callbacks remain uncalled. This proves interoperability for the current
upload/single-job read operations on identical persisted fixtures. It does not establish all
workflow/action, source/archive, error, authorization or event adapter parity, and does not
assert every auxiliary store file is unchanged by startup ownership/recovery. Keep the full
#158 shared-service criterion open until those remaining operation classes are audited.

## CLI/core regression qualification

The subsequent [combined regression record](evidence/web-cli-core-regression-20260905.json)
qualifies #158's existing job/reconstruction and CLI/core regression-coverage criterion at
source commit `8ae61d5`. It combines the web/journal and job/attempt-store suites with:

- `PatchCliTest` and `ReconstructionCliTest`: explicit strategy selection, strict harness names,
  provenance and evidence-only behavior without implicit provider use.
- `RepairCliPresentationTest`: real CLI unavailable-input exit behavior, acceptance-dependent
  presentation and bounded private-text-free console history.
- `RepairCliProgressTest`: persisted phase delivery, cursor gaps, bounded output and blocked-console
  isolation without blocking journal producers.
- `ProgramModelTest` and `ReconstructionProfileTest`: deterministic provenance/planning, parser
  contracts, ownership, profile identity/immutability and resource ceilings.
- `ReconstructionPipelineTest`: ELF metadata, injected analysis/model capture, stable generated
  layout, unresolved evidence and buildable output using the real project builder.

All selected tests passed without failures or skips. The reconstruction pipeline compiles
synthetic generated projects; it injects its analyzer and does not analyze a real target or
contact a provider. This is regression coverage of the existing API contracts and supported
fixture behavior, not qualification of every CLI command, live provider, real-target pipeline,
archive/source scenario, browser or release gate. Criteria 1, 2 and 4 remain open for complete
adapter parity, public-data classification and the shared legacy authorization boundary.

## Packaged legacy browser qualification

The [retained legacy browser report](evidence/web-legacy-browser-20260905.json) exercises the
packaged application's actual legacy HTML and polling script on Linux/Chrome. It checks initial
rendering, exact large usage, artifact metadata, diagnostic/prose/path withholding, automatic
polling, missing-journal row preservation, valid-empty row clearing, restored-journal recovery
and reload without page exceptions. All observed browser requests are GET/HEAD; no workflow is
admitted or executed. The fixed input, artifact and simulated-active job bytes are unchanged
at journey completion, and the journal matches its original fixture after restoration.

The driver deliberately changes its own fixture: it sets status to analyzing after startup
recovery, then removes, empties and restores the journal. These are test-owned state edits,
not evidence of application write operations or transactional storage consistency. The new
`--mode legacy` reuses owned read-only extraction, Node-free application PATH, browser/process
cleanup and archive/JAR identity capture. Chrome uses test-only `--no-sandbox`. This qualifies
legacy presentation/polling, not legacy session authorization or live workflow execution.

The archive was built from application commit `e4df2e9`; SHA-256 is
`8f90e08b2d16ce11788d7aba94a85b47ca2c433e38773963ef420557a839ec51`.
The report confirms unchanged installation bytes and completed shutdown/cleanup. Other browser
engines, accessibility qualification and the remaining D2 privacy/parity/authorization criteria
remain open.

The existing [public SPA journey](evidence/web-legacy-driver-public-20260905.json) also passed
against the same archive after the launcher change, including packaged home/Runtime and
explicit chunk-error recovery. The upgrade-driver unit tests and script syntax checks passed.
