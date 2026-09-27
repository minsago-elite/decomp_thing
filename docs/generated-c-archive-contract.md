# Generated-C archive policy contract

This document records one narrow #84 slice: the build and archive policy is
selected by the admitted reconstruction adapter. It does not claim that the
generated-C implementation has been fully extracted from every reusable-core
consumer.

## Contract

`ReconstructionAdapter.archiveBuild` supplies an `ArchiveBuildPolicy` for the
selected profile. The policy owns the required evidence paths, build-control
paths, source revision, build validation, and profile-specific build-input
classification. The shared archive transport only applies the policy.

Before archive paths are prepared, `checkedTransportLayout` requires every
strict build-control path to be required evidence. It also requires the
archive manifest, archive README, source-tree manifest, the selected program
model evidence, and every layout declaration with the `archive-payload` role to
remain outside omitted output roots.

The current registered generated-C profiles have this policy:

- the omitted output root is `build`, which keeps `build/reconstructed` out of
  the source archive;
- `reports/build_contract.json` is a retained strict build-control record;
- the selected profile's build definition (`Makefile` or `build.ninja`) is a
  required input;
- required reports include the archival audit, build log, source-tree
  manifest, model/plan evidence, unresolved evidence, confidence evidence, and
  toolchain evidence.

The build policy validates source-bound schema-2 build evidence, stable source
inputs, warnings-as-errors, reproducible path mapping, absence of API
credentials and analysis-cache requirements, sorted source-input identities,
and the recorded artifact identity. A successful local build therefore
provides a checked archive/build record; it does not authenticate the toolchain
or the reconstruction agent.

## Evidence in this repository

`ArchiveTransportLayoutTest` covers the adapter contract for every registered
generated-C profile and rejects an output omission that would hide declared
inputs or strict controls. `GeneratedCNinjaIntegrationTest` supplies the
existing authored two-module proof: it builds with Ninja, packages and
extracts the archive, confirms the build artifact is omitted, rebuilds the
extracted source, and compares the executable hash, build contract, and audit.
The focused command is:

```sh
./gradlew --offline --no-daemon test \
  --tests 'decompengine.project.ArchiveTransportLayoutTest' \
  --tests 'decompengine.project.GeneratedCNinjaIntegrationTest'
```

The fixture starts from an authored program model and local build tools. It
does not establish a complete GCC reconstruction, calibrated recovery
accuracy, or production release authority. Any unresolved entities remain
unresolved in the audit and reconstruction summary; archive success does not
turn them into accepted implementations.

## Gates still unavailable

This slice leaves the following production gates open:

- contained, authenticated compiler/runtime qualification and the production
  generated-C repair provider (#236/#49);
- independent ACP role and permission evidence through the public Make/Ninja
  workflows (#829/#63/#64/#65);
- the repository-wide neutrality migration and its remaining findings (#827);
- supported-scale resource qualification and complete in-flight phase-budget
  enforcement (#825/#826/#1066);
- a complete authenticated GCC reconstruction, archive, clean rebuild, and
  fidelity release evidence (#47/#48/#54).

Binary analysis is outside this fixture. Production analysis remains required
to use the bundled Ghidra Java/API boundary; this document does not authorize
`GHIDRA_HOME`, an external `analyzeHeadless`, or any substitute analyzer. The
fixture also supplies no authenticated oracle truth or agent authority, so its
local build/archive observations cannot cross those boundaries.
