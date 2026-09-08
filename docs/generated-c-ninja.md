# Generated C with Ninja

`GeneratedCNinjaReconstructionProfile.descriptor` selects the registered
`generated-c-ninja-v1` profile through `ArchivalReconstructionService`. The existing
service API accepts it as the `profile` argument. The CLI accepts
`--profile generated-c-ninja-v1`; omitting `--profile` retains generated-C/Make.

This profile emits `build.ninja` and invokes Ninja directly. It shares C interface
rendering, candidate checks and per-module compiler validation with the Make
profile. Its separate build definition compiles each owned source, tracks header
dependency files, and links `build/reconstructed`. A source-inventory check rejects
missing or unowned C files. No Makefile is generated and Make is not invoked.
Ninja syntax and dependency handling follow the [Ninja manual](https://ninja-build.org/manual.html).

The selected compiler and flags are recorded with the profile. Warnings remain
errors, file/macro/debug paths are mapped to the project root, and the common C
build runner retains bounded output/time, source stability, per-module diagnostics
and artifact identity checks. Build contracts and `BUILDING.md` record the actual
Ninja command and dependencies. Ninja logs live under the excluded `build/` tree.
The public `MakeProjectBuilder` remains a compatibility entry point for Make.

Local requirements are Ninja (tested with 1.13.2), the configured C compiler,
a POSIX shell, and `find`, `sort` and `tr`. For an agent-free exploratory build:

```sh
llm_bin_patch reconstruct ./program --output ./reconstruction --profile generated-c-ninja-v1 --evidence-only
```

Evidence-only mode emits explicitly unresolved placeholders. Profile selection
also works with the existing configured reconstruction harness. Unknown profile
IDs and missing profile values are usage errors detected before progress output
or harness setup. Only the two built-in profile IDs are accepted; this option does
not load arbitrary profile files. Binary analysis still uses bundled Ghidra.

Installed-launcher tests cover argument validation and absence of output side
effects. The end-to-end profile proof below starts from an authored model; it does
not claim a live binary-analysis CLI qualification.

`GeneratedCNinjaIntegrationTest` supplies an authored two-module C model, accepts
both modules through the compiler gate, builds with Ninja and checks the fixture's
exit code. It packages and strictly extracts the source archive, rebuilds without
a Makefile, and requires equal executable hashes, build contracts and audits.
A separate case rejects an added unowned source before accepting an artifact.
Run this focused proof with:

```sh
./gradlew --offline --no-daemon test --tests 'decompengine.project.GeneratedCNinjaIntegrationTest'
```

This is a local non-Make profile demonstration. It does not qualify production
compiler/runtime containment, authenticated ACP execution, a GCC reconstruction,
or calibrated recovery accuracy. Other #84 criteria, including independent role
permission proof and the repository-wide neutrality gate, remain open.

Ninja archive validation recomputes the expected command and dependency list from
the selected profile and recorded parallelism. Parallelism and time/output budgets
must be numeric and within supported/profile bounds; duplicate JSON keys are
rejected. A build record from another tool or configuration cannot qualify solely
by retaining successful status flags. These are consistency checks on retained
local evidence, not compiler/runtime authentication or independent verification
of every operation performed by an edited build definition.
