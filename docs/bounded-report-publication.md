# Bounded analysis and reconstruction reports

`GhidraJvmAnalyzer` streams `reports/ghidra_analysis.json` through a bounded JSON
writer. `RecompilableProjectGenerator` uses the same writer for
`reports/analysis.json` and `reports/unresolved.json`. These paths no longer build
complete report strings or escaped copies of symbol lists in memory.

## Limits and evidence

| Resource | Host ceiling |
| --- | ---: |
| Analyzer summary bytes, including whitespace and final newline | 1 MiB |
| Each supplemental report | 32 MiB |
| String or field name, in UTF-16 code units | 65,536 |
| Object fields and array entries, counted together per report | 1,000,000 |
| Container nesting depth | 16 |
| Report elapsed time | 60,000 ms |
| Total supplemental symbol records | 100,000 |
| Each supplemental symbol name, in UTF-16 code units | 16,384 |
| Generated-file entries, including the two supplemental report names | 100,000 |

Each supplemental report's byte ceiling is the lower of its host ceiling and the
selected profile's `archiveMaximumFileBytes`, since it becomes archive payload.
These reports do not borrow unrelated build, planner or reconstruction-context
budgets. The existing profile schema has no supplemental-report deadline field;
the independent host deadline covers preparation and both supplemental
publications together. The analyzer summary has its own report deadline and also
checks the wrapper's original elapsed allowance, starting before export.

The appended `reportPublication` object records effective JSON ceilings.
Supplemental reports additionally record the selected archive file budget and
their applicable record/name/file ceilings. These are configured limits, not
measurements of report bytes, process memory or transaction durability.

The writer uses an 8 KiB output buffer, emits UTF-8 and JSON escapes incrementally,
and checks byte capacity before each write. It bounds scalar length before
encoding, counts collection items before emitting them and checks nesting before
opening a container. String and writer operations reach cooperative cancellation
and elapsed checks at bounded intervals. A blocked native filesystem operation
cannot be preempted by these checks.

Direct callers can construct `GhidraAnalysis` without the bounded ELF reader.
Supplemental preparation therefore independently bounds symbol count and name
length while copying references to immutable symbol records. Counts and emitted
lists use that snapshot. It retains duplicates and relative order within each
kind. The snapshot does not copy names or concatenate all three inventories.
The manifest already owns a sorted, unique, immutable file list; the writer merges
the two supplemental names into its traversal without another sorted collection.

## Publication and compatibility

Each report is staged in a private sibling temporary file, flushed and closed,
then published with `ATOMIC_MOVE` and `REPLACE_EXISTING`. Cancellation and elapsed
time are checked immediately before the move. There is no non-atomic fallback.
A rendering, budget or cancellation failure before that move leaves the previous
report intact; cleanup makes no callbacks and preserves the original failure.
An unsupported atomic move fails the publication.

This is ordinary application output in the supplied parent directory, not an
oracle path-authority boundary. Staged and final files have POSIX owner read/write
permissions (`0600`), including when replacing an older report with broader
permissions. The repository's Linux execution environment supports those file
attributes. There is no fsync durability claim or transaction spanning all three
reports. Source generation can already have written project files, and the first
supplemental report can have been published when the second fails.

Existing field order, value types, unsigned decimal values, symbol duplicates and
ordering, generated-file sorting/deduplication, and final newline are preserved.
Dynamic strings, including metadata and paths, receive complete JSON escaping.
The writer rejects unpaired UTF-16 surrogates; valid Unicode and the ELF reader's
replacement characters are retained. Indentation is now consistently two spaces,
so report bytes/hashes change. `reportPublication` is appended after the existing
fields. Field names in these fixed schemas are unique; the streaming writer does
not maintain a separate set to enforce uniqueness for arbitrary callers.

## Verification

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.reporting.BoundedJsonReportTest' \
  --tests 'decompengine.project.ReconstructionReportsTest' \
  --tests 'decompengine.analysis.GhidraJvmMetadataInspectionTest' \
  --tests 'decompengine.project.ProfiledReconstructionPipelineTest' \
  --tests 'decompengine.project.ReconstructionPipelineTest.Ghidra analysis delegates to the program model adapter and captures report' \
  --tests 'decompengine.project.ReconstructionPipelineTest.initial C project layout is stable' \
  --tests 'decompengine.project.ReconstructionPipelineTest.reconstruction pipeline generates buildable project' \
  --tests 'decompengine.project.ReconstructionPipelineTest.unresolved symbol report is emitted' \
  --tests 'decompengine.project.GhidraExportBudgetBindingTest' \
  --tests 'decompengine.analysis.GhidraJvmExportBudgetTest'
```

All 30 selected tests pass with zero failures, errors or skips. They use small
authored metadata, names and local Make/Ninja
fixtures. They check all three schemas, UTF-8/escaping, exact byte accounting,
independent small limits, cancellation/deadline behavior, old-file preservation,
temporary-file cleanup and output permissions. All 38 original public JVM member
declaration/descriptor pairs across the analyzer, analysis, generator and pipeline
are retained, with no additions, compared with the parent layer.

This work does not qualify production-scale memory use, the whole parent JVM,
other report renderers, the complete archive budget or production execution.
Those remaining phase and consumer bounds stay open in
[#84](https://github.com/minsago-elite/decomp_thing/issues/84).
