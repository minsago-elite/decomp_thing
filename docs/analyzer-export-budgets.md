# Analyzer export budget binding

`ProgramModelAnalyzer.analyze(Path, Path)` remains the existing two-argument
interface. An analyzer that supports selected export budgets also implements
`ExportBudgetedProgramModelAnalyzer`. Its `withExportBudgets` method binds limits
before analysis starts. `GhidraJvmAnalyzer.withExportBudgets` requires this
capability and rejects an unsupported injected analyzer before creating output.
Existing callers of the two-argument analysis method remain compatible.

The bundled Ghidra adapter returns a copy with the smaller of each requested and
configured wall-clock or resident-memory limit. It retains its command factory,
tool identity, recovery mode, model-byte limit, diagnostic limits and termination
grace. Binding does not locate Ghidra, construct a worker command or write files.
The existing isolated worker execution applies the resulting limits.

Host admission remains a separate caller responsibility. The profile overload of
`ReconstructionPipeline.generate` performs that admission before binding budgets;
its [pipeline contract](profiled-reconstruction-pipeline.md) describes the full
handoff. The wrapper now uses [bounded ELF inspection](bounded-elf-metadata.md),
checks input identity against the exported model and shares its elapsed deadline
across export and metadata. Selected resident-memory budgets also lower the
metadata allocation model; a budget below its 8 MiB fixed reservation is rejected
before binding. The summary and supplemental reports have separate
[streaming publication bounds](bounded-report-publication.md). These limits do
not bound the entire parent JVM; complete phase bounds remain part of
[#84](https://github.com/minsago-elite/decomp_thing/issues/84).

## Focused verification

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.project.GhidraExportBudgetBindingTest' \
  --tests 'decompengine.analysis.GhidraJvmExportBudgetTest' \
  --tests 'decompengine.project.GhidraExportLifecycleTest' \
  --tests 'decompengine.project.ReconstructionPipelineTest.Ghidra analysis delegates to the program model adapter and captures report' \
  --tests 'decompengine.project.ReconstructionPipelineTest.reconstruction pipeline generates buildable project'
```

The nine selected tests use ordinary authored inputs, a local fixture build and
owned `sleep`/`printf` processes. They check both directions of deadline clamping,
recorded resident-memory limits, retained diagnostic caps, worker cancellation,
wrapper delegation and legacy call compatibility. They do not exercise memory
exhaustion or establish production analysis or release qualification.
