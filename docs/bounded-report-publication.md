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
chunks to a fixed native helper; the caller does not perform native staging writes.

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

Packaged-browser report compatibility: since #1894/#1895, the packaged-browser
report verifier applies an availability-notice semantic gate to every
integrity-verified passed session report. Passed session reports retained before
that gate, such as the #1882 evidence, show INVALID under the current verifier.
Their results under the verifier at the commit that produced them remain valid,
but they do not qualify the new notice criteria. Re-verify archived evidence with
that commit's `scripts/verify-packaged-browser-reports.mjs`.
Since #1896 the verifier also applies a connection-notice gate to every passed
session report that passes the availability-notice gate: it requires a
`connectionNotice` section and its four fixed `connection-*.png` files. Session
reports retained before #1896 keep their availability-notice result but show
INVALID for the connection criterion; the same re-verification rule applies.

## Enforced native staging

The fixed report helper receives only its unique candidate path and byte allowance;
it has no final report name or rename operation. Native directory creation,
candidate creation/open/write/flush/close belong to that helper. A one-chunk queue
and capped sender tasks keep native stdin backpressure off the analysis caller;
queue waits reach the same caller checkpoint and independent report deadline.
Before executing its payload, the static helper sets and reads back a hard and
soft `RLIMIT_AS` of 64 MiB. The limit covers all mapped user address space,
including shared mappings, rather than sampling RSS after allocations. It does
not bound kernel allocations, page cache or the parent JVM. Cgroup charged memory
is a different quantity: a shared page may be charged to another cgroup. The
fixed bootstrap contains no process-creation calls and performs only a same-PID
descriptor self-exec. Before protocol or path I/O, the payload installs kernel
denial of process creation, further exec, limit changes and rename operations.
Core size is zero and the
helper is non-dumpable. There is no unrestricted JVM fallback. Its response must
contain bounded creation identity, exact byte count/digest, complete footer/EOF,
successful exit and closed transfer/capture streams before publication is admitted.
Provider paths such as ZipFS are refused before helper admission: transferring
their text to the helper's default filesystem would otherwise name a different
host path. The existing 32 MiB independent report host ceiling is unchanged;
smaller configured report/profile allowances are passed through exactly.

The model reader uses the same authenticated static endpoint, with its existing
512 MiB streamed byte ceiling and the lower of the selected parent memory budget
and 256 MiB as its address-space limit. A budget below its existing 64 MiB minimum
is refused. These child limits do not reduce the model byte allowance: the reader
streams fixed-size chunks, while the parent owns the returned model bytes.

Source, fixed build policy, actual bounded compiler/build record and executable
digests belong to the defining application JAR. Installed sidecars must match
those resources byte for byte; coherent replacement of mutable sidecars cannot
authorize another helper. Only the qualified Linux x86-64 static ELF and OpenJDK
21 descriptor layout are accepted. Unsupported enforcement is refused before
payload I/O. Compatibility JVM fixture entrypoints retain diagnostic RSS checks
and are not the bounded production path.

An opened, authenticated executable descriptor remains owned through the actual
OpenJDK 21 `ProcessBuilder.start` acknowledgement. The command executes
`/proc/<parent-pid>/fd/<descriptor>`, so atomic pathname replacement cannot select
another image. The JDK's child exec-error pipe is close-on-exec and its parent
waits for EOF before returning the process; generic injected `Process` objects
cannot supply that acknowledgement. See the
[qualified JDK child exec protocol](https://github.com/adoptium/jdk21u/blob/1c417fbfc2f7/src/java.base/unix/native/libjava/childproc.c#L390)
and [parent acknowledgement](https://github.com/adoptium/jdk21u/blob/1c417fbfc2f7/src/java.base/unix/native/libjava/ProcessImpl_md.c#L762).
Two shared executable pins cap pending launches. An unknown launch, failed close
or blocked close retains its descriptor and refuses fresh admission; a returned
close callback is insufficient unless the actual channel is closed.

This deployment verification assumes the installed application JAR and helper
inode are trusted application artifacts, and verified helper inodes are never
modified in place. Deployment updates must publish a new inode. An opened descriptor pins an inode, not
immutable contents: hostile same-inode writes during verification and launch are
outside that deployment assumption. This is not authority to execute caller-owned
or oracle-provided mutable binaries. It does not change the existing requirement
for stable output directories or authenticate report paths against hostile parent
replacement.

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

# Ghidra invocation report schema v2

`ghidra_analysis.json` now writes `schemaVersion: 2`. The `analysisOutcome` field reports that
model validation, metadata identity checking, and report publication succeeded. The `invocation`
object records the per-call command supplied to the process-starter boundary and the returned
process exit value. This is diagnostic boundary evidence; it is not kernel argv attestation,
proof of a particular runtime class, analysis correctness, or authenticated path identity.

Bundled and controlled test Java commands disclose only the executable, main class, and exact
worker argument slice. Custom commands withhold executable and arguments. Adapters that provide
no invocation receipt report `status: unavailable`. Consumers should read `invocation.exitCode`
only when `invocation.status` is `captured`.

The in-memory `GhidraAnalysis.mainClass` and `args` getters remain compatibility projections of
qualified evidence and are empty when it is unavailable or custom. `returnCode` remains the
deprecated logical successful-wrapper code and is not a process exit receipt. Schema v2 removes
the former top-level `mainClass`, `args`, and `returnCode` fields; absence of `schemaVersion`
denotes a legacy v1 report.

The snapshot limits are 256 command elements, 65,536 UTF-16 units per element or
working directory, and 131,072 units in aggregate including the directory. Validation
checks cancellation at gaps of at most 1,024 UTF-16 units, including supplementary
characters that straddle a chunk boundary. Admission errors use fixed diagnostic
labels. Qualified payloads still pass through the private atomic 1-MiB publisher.

The opt-in `GhidraDotDirectoryInvocationQualificationTest` launches a separate probe
with installed application JARs before test helpers on its classpath. The probe
requires a build witness from `src/test/python/ghidra_invocation_provenance.py`:
`pin` follows cleanup and precedes cache-disabled compilation and installation.
With `-PqualifyGhidraInvocation=true`, one Gradle task graph builds the installation
and test classes, then seals them before running the tests. `seal` checks compiled
class bytes against the installed application, bridge JAR, and separately staged
bridge scripts; `verify`
checks HEAD, dirty/source inventory and installed hashes before and after analysis.
A missing witness, old compiler output, changed source, exporter mismatch, or stale
installation refuses qualification. Keeping preparation and sealing in the same
task graph prevents a second helper build from changing the sealed generation.
The opt-in requires real-Ghidra mode, disabled build caching and disabled incremental
Kotlin compilation. A normal test-JVM run or bundle property is insufficient proof.

Each hosted run uses a new directory with the `.decomp_engine/jobs/.../reports/analysis`
suffix. It observes the complete bounded direct-child inventory throughout analysis,
rejects a second matching process identity even in a later poll, and resolves the
project argument from the observed worker vector while that child lives. Acceptance
requires schema 2, the expected offset/classifications/outcome, authored `main`, a
new project database, and no dot-name rejection. Compiler/probe sessions and observer
threads must acknowledge bounded cleanup on every exit.

`build/orchestration/ghidra-invocation-qualification/` retains private bounded
`retained-invocation.json`, `observed-worker.json`, `compiler.json`, and `provenance.json`.
The provenance document binds report/observation/compiler digests and the source/build
manifest to one fresh run. The observation contains the approved receipt projection
and project identity, never the full JVM vector, options, classpath, or raw compiler
output. These artifacts are diagnostic evidence, not oracle authorization. Synthetic
controls and isolated compilation do not qualify installed Ghidra, default web
reconstruction/exploration, or actual hosted artifact upload membership.
The bundled CI job downloads its own uploaded artifact by ID and checks these four
files against the retained bytes and provenance digests. That check establishes
artifact consistency for the run, not authentication of the artifact.
