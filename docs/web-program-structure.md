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

Two checks qualify the 100,000-function budget (#536):

- `WebProgramStructureTest` builds a 100,000-function synthetic revision (4,167
  modules) through the real capture path and requires pages of at most 200 rows and
  under 1 MiB, a median warm page read under 500 ms and a retained projection inside
  the 256 MiB incremental JVM budget. It prints the measured values.
- `node scripts/check-packaged-web-browser.mjs --mode structure` seeds a persisted
  100,000-function revision (`scripts/packaged-browser-structure.mjs`) into the
  packaged application and drives pinned Chrome: it opens the inventory from the
  attempt page, pages 20 times by keyboard (focus returns to the results heading),
  reloads a cursor page, searches across all records, follows pinned caller and
  module links to the module source link, checks 390/320 px reflow, refuses any
  inventory read without the 100-row limit, and asserts a peak JS heap of at most
  128 MiB and at most 500 mounted table rows. CI runs it in the `web-packaged` job.
  Its seed writes manifests directly, so `WebProgramStructureTest` keeps
  `scripts/packaged-browser-structure-profile.json` equal to the current profile.

A local run on a heavily loaded host (load average about 40) measured: 100 rows per
page, peak browser heap 12 MB, keypress-to-rendered next page p50 81 ms and p95 84 ms,
full-population search 161 ms, and 23 bounded inventory reads; on the server, warm
page reads p50 2 ms, entity detail 22 ms and a retained projection of about 47 MB.
The first read of a revision builds its projection and took 0.84–1.07 s there, above
the 500 ms first-data-page budget; later reads reuse it. That first-read latency is
the remaining gap for this budget and is not hidden by the checks.
