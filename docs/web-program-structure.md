# Revision-bound program structure

Issues: #534, #535, #536 (tracker #183) and #539, #540 (tracker #185). These views
show the program model and module plan recorded in one persisted candidate revision.
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

## Scale

The packaged qualification separates cold first-page samples from the full interaction
journey. `scripts/packaged-browser-structure-cold.mjs --run loopback|constrained --`
starts 20 sequential instances of `check-packaged-web-browser.mjs --mode
structure-cold`. Each instance seeds the 100,000-function revision before launching
the packaged JVM, creates a fresh Chrome process and profile, exchanges a new local
session handoff, then measures the existing click-to-first-100-rendered-rows boundary.
Bootstrap, JVM startup, fixture seeding and navigation to the attempt page are outside
that interval. The 20 child reports retain every timing and failure; no failed sample
is replaced. The aggregate gates nearest-rank p95 and requires 20 complete samples,
zero raw inventory loading failures, matching source/archive/JAR identities, unique
run directories and observed JVM/Chrome process identities.
Before either structure mode launches the package, the driver verifies that every
qualification script it imports or invokes has the same Git blob identity as the
declared source commit. Each report retains the per-file Git blob ID and SHA-256;
the cold aggregate requires the verified source digest to match across all 20 runs.
If the checkout is detached from the declared commit, or any qualification source
is modified, source verification fails and the sample cannot pass.

The browser profile starts with empty cache and storage. Private requests use the
normal HttpOnly session cookie after the bootstrap fragment is scrubbed. The JVM and
browser are fresh for each sample, so server-side structure caches cannot warm later
samples. The protocol does not clear the operating-system page cache; results are cold
application-process/browser-profile measurements, not cold-storage measurements.
The lifecycle control also launches real Linux process groups: it waits for an
ordinary descendant to exit, escalates to a group kill when a surviving child
ignores cleanup, and refuses to treat forced cleanup as a passing sample.
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
  trace. CI runs it in the `web-packaged` job.
  Its seed writes manifests directly, so `WebProgramStructureTest` keeps
  `scripts/packaged-browser-structure-profile.json` equal to the current profile.
  During that journey the driver samples the packaged JVM's Linux `VmRSS` every
  25 ms, using the median of five idle samples before structure navigation as its
  warm baseline. It fails on missing samples or incremental RSS above 256 MiB.
  This is sampled process RSS for this synthetic journey; it does not establish a
  maximum over every request pattern or long-running session.

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
