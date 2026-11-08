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
bounded preview chunk, runs common/rare/missing searches, and cancels an in-flight
search by navigating away. The CI mode records request-head and response bytes,
route durations, mounted rows, browser heap, and application process-tree RSS.
Its required gate applies the loopback source budgets from
[`web-delivery.md`](web-delivery.md#measurement-profiles-and-budgets), including
the 500 ms repeated first-page p95, 500 ms first chunk, 2 s first search page,
128 MiB browser heap, 256 MiB incremental application RSS, 50 directory rows,
8 KiB request heads, and 1 MB response ceilings. The integration test also
seeds 25,001 files and confirms the real catalog and revision readers refuse
that over-limit input.

The repeated page samples are taken from one warmed packaged JVM; they are not
fresh-process cold-load measurements. The synthetic tree does not qualify real
generated projects, cross-browser behavior, long sessions, or production
workloads. A client abort proves stale browser work is discarded, not that
server processing stopped. The larger-than-supported tree is refused rather
than partially displayed; if the job provides `source-tree.zip`, use its
verified archive route as the alternative. These fixture and CI results are
evidence for #1056, not production qualification or completion of parent #625.
