# Revision-bound program structure

Issues: #534, #535, #536 (tracker #183), #537, #538 (tracker #184), #539, #540
(tracker #185) and #541, #542 (tracker #186). These views show the program model,
module plan and confidence report recorded in one persisted candidate revision.
They are read-only projections of recorded facts: nothing is inferred from source
text, compiled or executed, and nothing establishes accepted reconstruction.

## Records and binding

A revision is selected exactly as the [recorded source inputs](web-api.md) are: the
durable job/run must hold a candidate with that `revisionId`, and the source tree
manifest plus `reports/build_contract.json` must reproduce its `sourceSha256`. The
structure reader then uses two evidence files that the manifest commits by SHA-256:

| Record | Profile declaration | Path in the generated-C profile |
| --- | --- | --- |
| Program model | `program-model-evidence` | `reports/program_model.json` |
| Module plan | `module-plan-evidence` | `reports/module_plan.json` |

A record whose bytes differ from the manifest digest is refused with
`409 SOURCE_REVISION_CHANGED`. Every response repeats the binding, the source
commitment, the revision `metadataVersion`, the manifest digest, each record's path,
digest, byte size and schema version, and a `structureVersion` digest of all of them.
Pages are signed for one session, filter set and page size and embed the
`structureVersion`; a changed record expires them (`410 CURSOR_EXPIRED`). Entity and
module links in the browser carry `structureVersion`; a read pinned to a different
version is refused with `409 STRUCTURE_CHANGED`, so a view never merges records from
two report generations. Generated implementation and header links also carry the
originating `sourceSha256` and `metadataVersion`; a manifest-only change is refused
by the source viewer rather than silently adopting a newer source snapshot.

The reader admits a model of at most 64 MiB and 250,000 functions (250,000 globals
and types each), a plan of at most 16 MiB, identifiers of at most 4096 characters,
100,000 references per array and 500,000 references across all model call/global
arrays. Before retaining entity columns and references, it charges a conservative
allocation estimate (UTF-16 strings, reference slots, array growth, maps, lazy orders
and collision groups), capped at 96 MiB per projection including its admitted plan.
The cache retains at most two input/manifest/descriptor digest combinations and at
most 128 MiB of those charges, evicting least-recently-used projections. These are
admission/retention limits, not measured peak JVM heap or complete #536 qualification;
parser buffers, input bytes and active requests also need memory. A projection is
reused only for identical commitments; commitments are recaptured on every read.
Entity detail reads the committed model again, checks its digest and parses only the
selected entity object from its recorded offset.

## Model states

Only `available` documents carry entity rows, totals or summaries. The JSON schema
forbids rows and numeric totals in every other state, so an unsupported or partial
record never appears as an empty successful recovery:

| State | Meaning | Example reasons |
| --- | --- | --- |
| `available` | Recorded model parsed within limits | — |
| `not-recorded` | The manifest or profile records no model | `MODEL_NOT_RECORDED`, `PROFILE_DECLARES_NO_MODEL` |
| `unsupported` | Schema version other than 1–4 | `MODEL_SCHEMA_UNSUPPORTED` |
| `invalid` | Malformed, closed-field mismatch, assessed label or foreign input | `MODEL_MALFORMED`, `MODEL_INPUT_MISMATCH` |
| `limit-exceeded` | Record exceeds a reader bound | `MODEL_BYTES_EXCEEDED`, `MODEL_ENTITIES_EXCEEDED` |

The plan has its own state with the same vocabulary. When the plan is not
`available`, ownership is `not-recorded` for every entity and no modules are listed.
Only the assembled, manifest-committed model is read; exporter shards and progress
files are never admitted, so an incomplete export has no `available` state.

The web reader checks the schema version, closed field sets for that version,
unique identities per kind, address grammar, the extraction vocabulary and that
schema 2+ entities remain `unassessed`. Schema 3/4 byte evidence is bounded before
nested JSON allocation and validated with the producer's closed-shape, generation,
nullability and aggregate window/requested-byte rules. It does not re-verify model
canonical bytes; that remains the producer and archival-audit authority.

Canonical plan bytes alone are insufficient for admission. Module IDs must match
the web module grammar (at most 128 characters), generated paths must be bounded
relative paths without traversal or control characters, and owned entity IDs obey
the model identifier bound. Cycles must reference distinct recorded modules. Invalid
or over-limit plans leave a valid model available with ownership `not-recorded` and
no module projections. Ambiguous entity ownership and bounded references with no
model record remain intentional visible diagnostics, not malformed-plan errors.

## Identity, labels and evidence classes

Rows keep the recorded `entityId`, the exact unsigned 64-bit address as lower-case
hexadecimal, the recorded name, the extraction label and plan ownership. A
`selector` equals the recorded identity when it fits the URL identity grammar;
otherwise it is null and the entity is listed without a link.

`extractionStatus` is the producer label (`recovered`, `partial`, `failed`,
`synthetic`). `recoveryAssessment` is `unassessed` for schema 2+ and `not-recorded`
for schema 1; no extraction label is a scored assessment. `evidenceState` is a
display class derived only from recorded fields, in this precedence:

1. `excluded`: the recorded plan assigns the entity to no module.
2. `unresolved`: extraction `failed`, ownership is ambiguous (several modules list
   it), or the manifest's `unresolvedImplementationIds` contains it.
3. `inferred`: extraction `partial` or `synthetic`.
4. `recovered`: extraction `recovered` with none of the above; still unassessed.

Rows also expose `implementationUnresolved`, `reportedUnresolved` (membership in the
manifest's unresolved recovery population) and `nameCollision`.

## Routes

All routes are private reads with the source-input session policy, JSON only, and
admit `HEAD`. `R=/api/v1/jobs/{jobId}/runs/{runId}/revisions/{revisionId}`.

- `GET R/functions` → `functionInventory`. Query: `limit` (1–200, default 50),
  `cursor`, `sort` (`address`, `name`, `id`), `order` (`asc`, `desc`), `search`
  (case-insensitive name/identity substring or `0x` address prefix), `status`,
  `evidence`, `ownership`, `module` and `structureVersion`. Each order has an identity
  tie-break, so pages are stable; `totalFunctions` and `matchedFunctions` report the
  complete recorded and filtered scope.
- `GET R/modules` → `moduleInventory`: recorded totals by kind, evidence class,
  extraction label and ownership; declared-accepted modules; dependency cycles; plan
  references with no model record; name collisions; call and global references with
  no record; and a page of modules with their manifest implementation declaration
  and function evidence counts.
- `GET R/modules/{moduleId}` → `moduleDetail`. Query `kind` (`functions`, `globals`,
  `types`), `limit`, `cursor`, `structureVersion`. Returns the module's implementation
  and header paths with revision source `fileId`s when they are recorded build
  inputs, bounded cycle partners and boundary evidence, and one page of owned
  entities. Plan entries absent from the model are listed with `recorded: false`.
- `GET R/functions/{id}`, `R/globals/{id}`, `R/types/{id}` → `entityDetail`. Query:
  `structureVersion` only. Returns bounded previews (2048 characters, with total
  length and truncation) of prototype, decompiler output, type, initializer or
  declaration text; up to 20 referenced strings; up to 50 calls, callers, referenced
  globals and referencing functions, each `recorded` (linkable) or `no-record`; up to
  20 name collisions; byte-evidence presence for schema 3+ globals; and the owning
  module's generated implementation, header and the shared header as inspect and
  download paths through the source viewer.

## Fact families

`capabilities` states which fact families the selected records support:
function inventory, recorded prototypes (text, not ABI-checked), module ownership,
generated headers and global byte evidence follow the records. Scored recovery
assessment, structured type references, aggregate type layouts, ABI interface facts
and the C++ object model are always `not-recorded` until the owning A-series issues
(#27, #46, #110, #127, #129, #131) publish those facts in a revision record. The
browser lists these families explicitly rather than omitting them.

## Graph neighborhoods

Issues #537 and #538 (tracker #184). `GET R/graph` → `structureNeighborhood` reads a
bounded neighborhood around one recorded focus. Query: `view` (`calls` with a
function `focus`, or `modules` with a module `focus`), `direction` (`outgoing`,
`incoming`, `both`), `depth` (1–3, default 1), `nodeLimit` (1–200, default 60),
`edgeLimit` (1–400, default 150), `unresolved` (`show`, `omit`; calls only) and
`structureVersion`. The response restates the request, so a view never shows limits it
did not ask for.

Relationships keep the report semantics:

| Family | Source | State |
| --- | --- | --- |
| `recorded-call` | `functions[].calls` of the program model; one edge per caller and target with its recorded occurrence count | recorded |
| `unrecorded-call-target` | A call target with no model record: an `unrecorded-function` node and a `no-record` edge, never relabeled external | recorded |
| `inferred-endpoint` | Node `evidenceState` `inferred` (partial or synthetic extraction) | recorded |
| `call-kind`, `external-call` | Direct, indirect, virtual and imported targets: the model records call targets only (#128) | `not-recorded` |
| `module-call`, `module-global-reference` | Derived from recorded calls or global references through plan ownership, the planner's own dependency rule | recorded with the plan |
| `recorded-dependency-cycle` | `dependencyCycles` of the plan; module edges inside one recorded cycle carry `recordedCycle` | recorded with the plan |
| `unattributed-reference` | Per module: references whose target has no single owning module or no record; counted, never assigned | recorded with the plan |

The reader explores breadth first from the focus. Within one million adjacency visits
it counts the reachable nodes and the edges among them exactly, plus edges that continue
past the depth limit and edges to targets the `unresolved=omit` filter leaves out.
It returns the first `nodeLimit` nodes in discovery order (the focus first) and the
first `edgeLimit` edges among them, nearest relationships first. `completeness.state`
is `complete` only when nothing reachable is left out; otherwise it is `truncated` with
`NODE_LIMIT`, `EDGE_LIMIT`, `VISIT_LIMIT` or `BYTE_LIMIT` (long recorded identities halved the
nodes until the response fits 1 MB), and `omittedNodes`/`omittedEdges` are exact.
Past the visit bound every total is `null` (unknown), never a guess. Each node states
its recorded outgoing and incoming totals and how many of them are shown. Model or plan
states other than `available` return `graphState` with no neighborhood.

The browser route `…/revisions/{revisionId}/graph?view=…&focus=…` is linked from
function detail ("Explore its recorded call neighborhood") and module detail. Graph
code lives under `frontend/src/graph/` and loads only when the view opens; the bundle
report refuses any graph or source module in the initial chunk. The layered layout runs
in a module worker with a 2 s deadline and is cancellable; every cancel, timeout,
failure or new neighborhood terminates the worker. Tables of all shown nodes and
relationships (paged at 100 rows) are rendered regardless of the drawing, and each row
has an Inspect button. Inspecting a node or relationship moves focus to the selection
panel, which links to entity and module detail (pinned to the structure version), the
implementation source and header in the revision source viewer, a re-centered
neighborhood, and the digest-pinned program model or module plan record
(`GET R/records/{program-model,module-plan}?structureVersion=`). Line styles and outlines
are repeated as text marks (focus, inferred, unresolved, excluded, no record, hidden
counts), so no state depends on color or line style alone.

## Scorecard

Issue #541 (tracker #186). `GET R/scorecard` → `structureScorecard` reads the
manifest-committed `reports/confidence.json` (schema 2, `confidence-evidence`) of the
same revision, digest-checked like the model, and binds it to the model: its
`recoveryAssessment.modelSha256` and model schema must equal the committed model, or the
record is `invalid` (`CONFIDENCE_MODEL_MISMATCH`). States follow the structure
vocabulary; only `available` carries a scorecard. Query: `sort` (`module`, `score`),
`order`, `limit`, `cursor`, `structureVersion`.

Every measure states its unit, state, reason, the recorded value text verbatim, an
exact numerator and denominator, and its source record and field:

| Measure | Numerator / denominator | States |
| --- | --- | --- |
| Structural recovery score (`projectScore`) | Sum of extraction-label weights / model entities | `measured`; `unmeasured` for an empty population (the recorded `0.0000` is a placeholder); `failed` when the recorded value does not reproduce |
| Module score (`modules[].score`) | The same over the plan's owned entities | as above; `unknown` when no score is recorded; `failed` when the plan names an unrecorded entity |
| Calibrated confidence | — / empirical sample count | `unmeasured` (`UNCALIBRATED`) |
| Assessed recovery | Assessed entities / all entities | `unmeasured` (`UNASSESSED`) |
| Implementation acceptance | Manifest-declared accepted modules / planned modules (current, including accepted repairs) | `measured` |
| Generation completion | Completed / planned modules of the recorded generation; repairs do not rewrite this historical outcome, so it is not compared with current acceptance | `measured`; `partial` when fewer completed; `unknown` when not recorded |
| Unresolved recovery, unresolved implementation | Recorded identities / entities | `measured`; `failed` if the manifest disagrees |
| Excluded entities | Entities the plan assigns to no module / entities | `measured` |

The score formula is `extraction-label-mean-v1`: weights recovered 1, partial 0.6,
synthetic 0.25, failed 0, averaged and rendered with four decimal places. It is defined
once (`StructuralRecoveryScore`) and used by both the producer and this reader, so
`recomputed` reproduces the recorded value exactly from the recorded labels; the
displayed value is always the recorded text. The interpretation is
`structural-recovery`, version 1, `uncalibrated`. No validator threshold applies
(`thresholds.state: not-recorded`); the page shows the attempt's acceptance from the
attempt record and never derives acceptance from a score.

`reconciliation` explains module breakdowns against the project population: the sums of
module numerators and denominators, plus entities in no module, less extra memberships
of entities owned by several modules, equal the project numerator and denominator.
Plan references with no record and score rows for unplanned modules are counted.
Scores are means (`non-additive-mean`): module scores do not add to the project score.
The browser shows the measures, label components, reconciliation, a page of module
scores as a supplementary bar chart followed by the same values in a table, and a
download of the exact confidence record (`GET R/records/confidence?structureVersion=`).

Record downloads hold the job's delivery lease and the shared download admission (four
reads in all, two per session) for the whole response. A first pinned pass reproduces the
manifest-committed digest before any header is sent; the second pass streams through a
held-back final chunk that is released only after that pass reproduces the digest too, so
memory stays at one read chunk and a record that changes mid-response is closed short of
its declared length. A failure after the headers (here and for artifact content) is
rethrown to the listener, which drops the connection; closing the exchange alone could
leave it open with the declared length unmet.

Recorded identities share one public projection under the listener's redaction policy. An
addressable entity or module ID that the policy publishes unchanged in an identity field
is its own selector, in inventories, details, neighborhoods (including the echoed
`focus`), scorecard rows and comparisons. Any other ID becomes a stable alias with no
selector: `function:`, `global:` or `type:` plus a SHA-256 for entities, and
`_withheld.` plus a SHA-256 for modules, which keeps the module-ID grammar. An alias is
itself published unchanged: when a configured value would overlap it, the digest is
re-derived with a salt, and when no safe alias exists the read fails with
`409 STRUCTURE_IDENTITY_WITHHELD`. A request that selects an ID the policy would rewrite,
as a path selector, a neighborhood focus or a function-inventory `module` filter, finds no
record (`404`), checked before any other response is built; an accepted `module` filter is
echoed with the same identity semantics as its selector.

## Comparing attempts

Issue #542 (tracker #186). `GET R/scorecard-comparison?baselineRunId=&baselineRevisionId=`
→ `scorecardComparison` reads the baseline attempt's scorecard, then the current one,
each through its own capture. Identity checks: input binary, reconstruction profile,
confidence schema, score interpretation, formula, model schema, entity population and
module plan. Every check blocks deltas when it differs or is not recorded: a changed
population or module membership makes module and project measures incomparable, and a
side without a module plan has no module scope to compare. Checks compare typed values
and show unambiguous text: the interpretation admits only the vocabulary this reader
understands (`structural-recovery`, version 1, `uncalibrated`; any other recorded
interpretation makes the scorecard `unsupported`, `CONFIDENCE_INTERPRETATION_UNSUPPORTED`),
and the population names the SHA-256 of each kind's sorted, length-prefixed identities as
well as its counts. A comparison whose displayed identities the listener's redaction
policy would rewrite is refused (`409 COMPARISON_IDENTITY_WITHHELD`), because a rewritten
value could contradict its check state. A compatible comparison gives exact decimal differences of recorded values
(and of numerators and denominators) only where both sides are `measured`; otherwise the
delta is `not-comparable` with the side's state. An incompatible baseline withholds every
delta, and an unavailable scorecard on either side compares nothing. Module rows cover
the union of both plans with `presence`, paged by a cursor bound to both structure
versions. Each side carries its own reconciliation. The browser offers the job's other
attempts that have a result revision as baselines.

The browser decoder (`frontend/src/structure/contract.ts`) and the shared verifier
(`contracts/web/v1/verify.py`) hold a reply to the rules the producer follows. Each
side's scope names that side's own model record digest and schema. The model-schema and
confidence-schema checks state those records' schemas. A side has a scope and
confidence identities exactly when its confidence report is available. Every delta is
recomputed from its operands: the exact difference at the wider operand scale, with zero
written as `0`, or `withheld`/`INCOMPATIBLE_BASELINE` for a paired row of an
incompatible baseline, `MODULE_NOT_IN_BOTH_PLANS` for an unpaired module, and otherwise
`CURRENT_`/`BASELINE_` followed by the first unmeasured side's state. An unavailable
reply has no measures, a module total of zero and no continuation. The module page must
be bound to the current structure version.

## Scale

The packaged qualification separates cold first-page samples from the full interaction
journey. `scripts/packaged-browser-structure-cold.mjs --run loopback|constrained --`
starts 20 sequential instances of `check-packaged-web-browser.mjs --mode
structure-cold`. Each instance seeds the 100,000-function revision before launching
the packaged JVM, creates a fresh Chrome process and profile, exchanges a new local
session handoff, then measures the existing click-to-first-100-rendered-rows boundary.
Bootstrap, JVM startup, fixture seeding and navigation to the attempt page are outside
that interval. The 20 child reports retain every timing and failure; no failed sample
is replaced. A child report over 512 KiB keeps its largest facts in digest-bound parts.
The runner rebuilds those parts, checks every part and reference digest against
`report.json`, and only then reads the sample; an inconsistent report fails the sample. The aggregate gates nearest-rank p95 and requires 20 complete samples,
zero raw inventory loading failures, matching source/archive/JAR identities, unique
run directories and observed JVM/Chrome process identities.
Before a cold sample or a profiled structure run launches the package, the driver verifies that every
qualification script it imports or invokes, plus the packaged CI workflow that
defines its invocation, has the same Git blob identity as the declared source commit.
Each report retains the per-file Git blob ID and SHA-256;
the cold aggregate requires the verified source digest to match across all 20 runs.
If the checkout is detached from the declared commit, or any qualification source
is modified, source verification fails and the sample cannot pass. Packaged CI
records the checked-out `driverCommit` separately from the pull-request head and
base SHAs; each cold sample must match those declared PR revisions so a merge
candidate is not reported as if it were the standalone PR head.

The browser profile starts with empty cache and storage. Private requests use the
normal HttpOnly session cookie after the bootstrap fragment is scrubbed. The JVM and
browser are fresh for each sample, so server-side structure caches cannot warm later
samples. The protocol does not clear the operating-system page cache; results are cold
application-process/browser-profile measurements, not cold-storage measurements.
The lifecycle control also launches real Linux process groups: it waits for an
ordinary descendant to exit, escalates to a group kill when a surviving child
ignores cleanup, and refuses to treat forced cleanup as a passing sample. On a
sample timeout, it sends `SIGTERM`, waits for the bounded grace period, then uses
`SIGKILL` if the launcher or any descendant remains; that sample is recorded as
timed out and failed even when cleanup is confirmed. A sample, or a profiled journey,
also fails when the driver itself had to send `SIGKILL` to Chrome or the JVM while
stopping them; its report keeps `forcedShutdown`, the forced processes and the cleanup
outcome.
A process group counts as stopped only when the signal-zero probe finds no members or
`/proc` shows only zombie or dead members on two polls in a row. A host PID 1 that does
not reap orphans therefore cannot hold the remaining samples back, and an unreadable or
malformed `/proc` record keeps cleanup unconfirmed.
Loopback first-page p95 is limited to 500 ms. The constrained profile applies 4× CPU
slowdown, 100 ms round-trip latency, 10 Mbit/s download and 2 Mbit/s upload and limits
first-page p95 to 1 s. Both profiles also gate the browser heap and JVM RSS budgets.

- `WebProgramStructureTest` builds a 100,000-function synthetic revision (4,167
  modules) through the real capture path and requires pages of at most 200 rows and
  under 1 MiB, a p95 across 20 fresh-cache first-page reads below 500 ms, a median
  warm page read below 500 ms and a retained projection below its 96 MiB test
  bound. The 20 reads use fresh cache instances in one already-running test JVM;
  they are not 20 fresh-process cold loads. It prints each sample plus the median,
  p95 and max.
- `node scripts/check-packaged-web-browser.mjs --mode structure` without a profile runs the ordinary
  journey: 20 keyboard pages, reload, search, pinned cross-links, the module source link
  and reflow, with the #1879 module-body observations recorded on failure. It applies
  none of the budgets below and does not verify source or browser identity. CI runs it
  before the Vite proxy step, and runs the cold samples and both profiled journeys after
  that step, so a budget failure cannot skip the ordinary journey or the proxy. Each of
  those four gates runs once the archives are built, even when an earlier step or gate
  failed, so every profile records evidence; a final step fails the job if any gate did
  not pass.
  Failures of the profiled journeys and cold samples carry the same bounded #1879
  observations in the report's `structureFailurePhase`.
- `node scripts/check-packaged-web-browser.mjs --mode structure --structure-profile <loopback-or-constrained>` seeds a persisted
  100,000-function revision (`scripts/packaged-browser-structure.mjs`) into the
  packaged application and drives pinned Chrome: it opens the inventory from the
  attempt page, traverses 50 pages by keyboard (focus returns to the results heading),
  reloads a cursor page, searches across all records, follows pinned caller and
  module links to the module source link, checks 390/320 px reflow, refuses any
  inventory read without the 100-row limit, and asserts a sampled JS heap peak of at
  most 128 MiB and at most 500 mounted table rows. It samples `JSHeapUsedSize` every
  50 ms throughout the measured journey and fails if a sample fails or the largest
  observed gap exceeds 500 ms; the reported peak is sampled, not a continuous heap
  trace. CI runs it in the `web-packaged` job for both profiles.
  Its seed writes manifests directly, so `WebProgramStructureTest` keeps
  `scripts/packaged-browser-structure-profile.json` equal to the current profile.
  During that journey the driver samples the packaged JVM's Linux `VmRSS` every
  25 ms, using the median of five idle samples before structure navigation as its
  warm baseline. It fails on missing samples or incremental RSS above 256 MiB.
  This is sampled process RSS for this synthetic journey; it does not establish a
  maximum over every request pattern or long-running session.

A first read builds the projection. The reader joins planned modules to manifest
files by path, records model columns without decoding text bodies, and parses the
profile-declared model and plan on two virtual-thread workers while the manifest is
parsed; each record is used only after the manifest commits it and its digest matches,
so the result equals a sequential read. Captures stay serialized, so at most two
worker bodies run. Cancellation requests interruption and the parsers check it cooperatively;
read/library operations may still take time to exit. Capture admission remains held until
both bodies actually exit, including after rejection or an unused speculative record, so
subsequent metadata/structure reads receive `SOURCE_CATALOG_BUSY` while they drain.
`WebStructureCaptureCancellationTest` holds both bodies across cancellation and checks
this bound and eventual admission recovery. `WebProgramStructureTest` reports the median
of three first reads with empty projection caches against the 500 ms budget and fails only above three times that
budget, so noisy shared CI hosts catch a regression without flaking; on a host with load average about 15 they
took 166–310 ms (previously 0.84–1.14 s), with warm page reads p50 1–2 ms, entity
detail about 20 ms and a retained projection of about 45 MB.

The packaged journey also opens a call neighborhood from function detail (tables
158 ms, worker drawing 234 ms after the click), inspects a node by keyboard, reads a
200-node module neighborhood whose node table pages at 100 rows, and opens the seeded
scorecard (329 ms) with its confidence-report download. `WebProgramGraphTest` reads
depth-3 neighborhoods of a 100,000-function call graph in 12–14 ms p50 after a first
graph build of 68–112 ms.

A local packaged run in pinned Chrome on a host with load average about 20 measured:
100 rows per page, peak browser heap 15 MB, keypress-to-rendered next page p50 81 ms and
p95 83 ms, full-population search 162 ms and 23 bounded inventory reads. The first
inventory page after the click took 535 ms (584 ms in another run). One instrumented run
under heavier load spent about 300 ms in the browser loading the lazy structure route
before the page was requested and about 540 ms on the first projection build in the
freshly started JVM. The 500 ms first-data-page budget is therefore not yet met in the
packaged measurement, and the checks do not hide it.

Five historical local 20-sample runs measured cold projection p50/p95/max of 323/438/569 ms,
392/487/595 ms, 398/588/751 ms, 270/362/521 ms, and 333/493/502 ms; retained
projection had an estimated post-GC heap delta of about 47 MB under the then-current
test. This heap delta is distinct from the separately charged cache-entry size, which
is about 87 MB for the current 100,000-function fixture. Four runs met the 500 ms p95
budget and one did not, so local timing is variable and does not establish stable qualification. These are synthetic
projection measurements, not hosted production qualification. The packaged browser
measurements above remain separate evidence for response paging, heap, keyboard
interaction and reflow.

The packaged driver retains failed same-origin request duration and header timing so a
canceled first response remains visible in the latency diagnosis. A `loadingFailed`
terminal is accepted as consumed only for Chromium's exact `net::ERR_ABORTED` canceled
signature and only when the complete streamed body matches the fixture oracle and
Content-Length, the response is an uncached HTTP 200, Resource Timing reports matching
encoded/decoded sizes and HTTP 200, and the expected ready DOM follows the failure.
The driver may classify a narrowly proven cancellation for diagnosis using request-ID
and URL hashes after all 52 consumption actions are proven. This classification is
diagnostic only: the qualification gate still requires zero raw `loadingFailed`
inventory requests. A consumed-body proof does not establish why Chromium reported
failure or turn that request into a successful terminal. Structure-mode server
phase timings can be enabled for the packaged diagnostic with
`-Ddecompengine.web.structureTiming=true`; they are stderr diagnostics and do not alter
the response or any budget.
