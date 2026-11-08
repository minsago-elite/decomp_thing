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

This fixture checkpoint establishes reproducible source-tree data and the real
metadata-reader ceiling. It does not establish packaged-browser request,
latency, heap or RSS budgets. Those measurements remain part of #1056 and need
to be wired into the packaged browser journey separately.
