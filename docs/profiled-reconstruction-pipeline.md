# Profile-aware reconstruction pipeline

`ReconstructionPipeline.generate(binaryPath, workDir, profile)` admits requested
budgets against `ReconstructionHostSafetyLimits.DEFAULT`, resolves the registered
adapter and binds worker export budgets before analysis creates output. A caller
can supply an explicit `hostSafetyLimits` policy and an optional `reconstructor`.
An unsupported profile or analyzer fails before analysis starts. The same profile,
host policy and reconstructor reach source generation; the selected adapter then
passes both policies to the shared build boundary. The boundary rejects a build
configuration wider than the selected profile, independently rechecks the host
ceiling, and records the profile digest, declared budgets, host build ceilings,
and effective configuration in `reports/build_contract.json`.

For example, the bundled analyzer can select Ninja through the existing wrapper:

```kotlin
val report = ReconstructionPipeline(GhidraJvmAnalyzer()).generate(
    binaryPath,
    workDir,
    GeneratedCNinjaReconstructionProfile.descriptor,
)
```

The default reconstructor emits unresolved evidence placeholders. This call's
successful build alone does not establish recovered behavior. An explicitly
supplied reconstructor follows the selected adapter's normal validation path.

`RecompilableProjectGenerator.generate(analysis, projectDir, profile, ...)` exposes
the same profile and host-policy handoff for an existing analysis. Source
generation performs admission before the wrapper creates supplemental report
directories. The supplemental paths `reports/analysis.json` and
`reports/unresolved.json` are reserved: selected declarations cannot occupy those
files, their ancestors or descendants, including through templates. Both entry
points check this before output. Existing report paths and fields are preserved;
[bounded streaming publication](bounded-report-publication.md) now normalizes
whitespace and appends effective report limits.

The existing pipeline constructor, `generate(Path, Path)` method and generator
method with its default reconstructor remain compatible, including the generator's
JVM default-argument bridge. The two-path pipeline retains its legacy injected
analyzer contract: that analyzer supplies its own export limits. Its build now
uses the default profile's registered adapter. This intentionally changes its
compiler selection from the old builder default `gcc` to the registered profile's
`cc`, so the command and compiler used may change where those resolve differently.
The new profile overload requires explicit budget support from an injected analyzer.

## Verification and remaining bounds

```sh
./gradlew --no-daemon test \
  --tests 'decompengine.project.ProfiledReconstructionPipelineTest' \
  --tests 'decompengine.project.ReconstructionPipelineTest.Ghidra analysis delegates to the program model adapter and captures report' \
  --tests 'decompengine.project.ReconstructionPipelineTest.initial C project layout is stable' \
  --tests 'decompengine.project.ReconstructionPipelineTest.reconstruction pipeline generates buildable project' \
  --tests 'decompengine.project.ReconstructionPipelineTest.unresolved symbol report is emitted' \
  --tests 'decompengine.project.GhidraExportBudgetBindingTest' \
  --tests 'decompengine.analysis.GhidraJvmExportBudgetTest'
```

The focused lifecycle and pipeline tests use authored ELF headers/models and local Make/Ninja
fixture builds. Pipeline tests verify an explicit host ceiling reaches generation,
one-function module planning, selected manifest identity and recorded build
budgets. They also verify host, registration, capability and report-layout rejection
before output. Worker budget tests separately exercise owned `sleep`/`printf` processes.
The pipeline fixture supplies a recording analyzer; it does not run Ghidra or
qualify production execution.

The analyzer now uses a [bounded positional ELF inventory](bounded-elf-metadata.md)
and shares its elapsed deadline across export and metadata. It verifies the input
digest against the model before reporting. Its summary and the downstream
unresolved-symbol/generated-file reports now stream with independent byte and
publication bounds. Complete phase bounds and the other consumer, role-permission
and production qualification criteria remain
[#84](https://github.com/minsago-elite/decomp_thing/issues/84) work.
