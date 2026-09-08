# Generated C with Ninja

`GeneratedCNinjaReconstructionProfile.descriptor` selects the registered
`generated-c-ninja-v1` profile through `ArchivalReconstructionService`. The existing
service API accepts it as the `profile` argument. CLI defaults remain unchanged.

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
a POSIX shell, and `find`, `sort` and `tr`. The profile can be used through the JVM
service API; this change does not add a CLI profile selector.

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
