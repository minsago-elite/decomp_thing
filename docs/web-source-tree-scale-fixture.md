# Packaged source-tree scale fixture

`scripts/packaged-source-tree-fixture.mjs` creates one credential-free job-store
entry with a completed `RECONSTRUCT` attempt and an unaccepted candidate revision.
It writes an inert 64-byte ELF header and 25,000 small UTF-8 source-tree files by
default. The `Makefile` is a fixture input only; the seeder and its tests never run
it, invoke a compiler, or contact a model provider.

The fixture uses the registered `generated-c-make-v1` profile, the schema-3 source
tree manifest and build contract, and the real workflow-state wire format. The
test calls `WebJobService.readSourceCatalog` and
`WebJobService.readRevisionSources`, then pages both results through the source
page adapters. It also verifies representative physical source bodies against
their manifest digests. A 25,001-file control confirms both readers refuse the
over-limit metadata with bounded unavailable results.

Run the generator with pinned Node 24.20.0 and an empty absolute directory:

```sh
node scripts/packaged-source-tree-fixture.mjs \
  --root /absolute/job-store \
  --files 25000
```

The file count includes `Makefile`. `--files 25001` creates the deliberate
over-limit control. Existing files are never replaced; use a new empty root for
each fixture. The stored `binary_path` binds to the supplied absolute root, so
the job-store record is root-specific while source paths, source contents,
manifest records and source revision identity are deterministic.

The packaged `source-tree` browser mode uses the same fixture and real
application readers. It visits all 500 pages of the 24,999-file `modules`
directory, checks exact ordering and keyboard focus, opens a file and its first
bounded preview chunk, runs common/rare/missing searches, and cancels a search
through the SPA's own navigation after the server has returned successful bounded
response headers. This proves the in-app route transition aborts the outstanding
browser response read; it does not prove server work stopped after disconnect. It
measures the first-page duration for
all three search terms, plus local feedback for 50 keyboard page interactions.
CI records request-head and response bytes, route durations, mounted rows,
browser heap, and application process-tree RSS.

CI runs both profiles. Loopback uses the 500 ms first-page ceiling; constrained
emulates fourfold browser CPU slowdown, 10 Mbit/s download, 2 Mbit/s upload and
100 ms round-trip latency, and uses the documented 1 s first-page ceiling. Both
profiles gate the 100 ms local-feedback p95, 500 ms first preview chunk, 2 s
maximum search first page, 128 MiB maximum observed browser heap, 256 MiB
incremental application RSS, 50 directory rows, 8 KiB request heads, and 1 MB
response ceilings. The post-browsing and post-navigation heap samples remain
separate measurements; neither can mask an over-budget peak sampled during the
journey. The
integration test also seeds 25,001 files and confirms the real catalog and
revision readers refuse that over-limit input.

### Fresh-process first-page samples

Before the full journey, qualification attempts 20 sequential cold first-page
trials per source-tree profile. An unconfirmed teardown stops the sequence and
fails the profile. Every started trial uses a new packaged JVM, Chromium
process, and empty uniquely identified browser profile. The fixture is written before the
JVM starts; authentication and application startup are recorded separately and
excluded from the page timing. The measured interval starts with direct
navigation to the deterministic `modules` route and ends after the exact first
50 filenames render and the bounded directory response has completion
evidence. All 20 attempts are retained; failures are not replaced or dropped.

After those trials, the existing full pagination, interaction, search, detail,
heap, and RSS journey runs in its own application and browser process. Its
repeated page and resource measurements describe that journey, not the
fresh-process cold p95. Fixture seeding and runtime identity reads can warm the
filesystem page cache; the OS cache is uncontrolled and no cold-disk performance
is claimed.

The final `report.json` keeps the cold median/p95, gate, attempt/failure counts,
and evidence references. Complete source-tree request records and all cold
sample records are retained in the sibling `source-tree-scale-evidence.json`
artifact, bounded to 8 MiB and bound by its byte count and SHA-256. The outer
supervised report verifies its schema, profile, source/workflow and
package/browser identity, fixture identity, sample count, route counts, and
digest before copying it beside the final report. Evidence is copied after the supervisor confirms that no
owned processes remain, including for a failed performance gate; a failed gate
remains failed. If the sidecar exceeds its bound or cannot be written, the run
fails explicitly and marks complete evidence retention as unconfirmed.

The synthetic tree does not qualify real generated projects, cross-browser
behavior, long sessions, or production workloads. A client abort proves stale
browser work is discarded, not that server processing stopped. The
larger-than-supported tree is refused rather than partially displayed; if the
job provides `source-tree.zip`, use its verified archive route as the
alternative. These fixture and CI results are evidence for #1056, not production
qualification or completion of parent #625.
