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
and elapsed checks at bounded intervals. Production output transfers bounded
chunks to a fixed helper JVM; the caller does not perform native staging writes.

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
An unsupported atomic move fails the publication. A rename already issued to the
filesystem cannot be revoked by a deadline check, interruption or helper stop.
The final move remains outside the enforced native staging guarantee. A timeout
observed after that commit starts does not prove the previous target remained
unchanged; complete in-flight publication remains open in
[#1066](https://github.com/minsago-elite/decomp_thing/issues/1066).

This is ordinary application output in the supplied parent directory, not an
oracle path-authority boundary. The supplied directory must remain stable while
publishing; path-based file-key comparisons do not authenticate an opened inode
against concurrent hostile parent/path replacement. Staged and final files have POSIX owner read/write
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

## Enforced native staging

The fixed report helper receives only its unique candidate path and byte allowance;
it has no final report name or rename operation. Native directory creation,
candidate creation/open/write/flush/close belong to that helper. A one-chunk queue
and capped sender tasks keep native stdin backpressure off the analysis caller;
queue waits reach the same caller checkpoint and independent report deadline.
The helper has a 16 MiB heap and a 64 MiB Linux RSS ceiling. Its response must
contain bounded creation identity, exact byte count/digest, complete footer/EOF,
successful exit and closed transfer/capture streams before publication is admitted.
Provider paths such as ZipFS are refused before helper admission: transferring
their text to the helper's default filesystem would otherwise name a different
host path. The existing 32 MiB independent report host ceiling is unchanged;
smaller configured report/profile allowances are passed through exactly.

Two retained invocation owners cap sender, capture and control resources. Late
handles remain owned; unknown launches and unconfirmed native creation cannot
release capacity merely because a caller returned. Creation is announced before
native mutation, and the candidate identity is announced after creation. Missing
creation identity retains the candidate/owner rather than deleting a colliding
file or assuming process absence settled an unfinished filesystem transaction.
Candidate deletion runs on the retained capped control task. A blocked close or
deletion keeps its references and slot after the single five-second caller cleanup
allowance; later proven quiescence can release it. No cancelled Future serves as
absence proof. Injected output-stream fixtures retain the existing cooperative
test seam and do not qualify arbitrary native filesystem operations.

These guarantees preserve the previous report on refusal before the final rename
starts. They do not qualify script/resource writes, fixed-path diagnostic
publication, final rename cancellation, fsync durability or multi-report atomicity.

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

The original publication checkpoint executed all 30 selected tests with zero
failures, errors or skips. They use small
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
