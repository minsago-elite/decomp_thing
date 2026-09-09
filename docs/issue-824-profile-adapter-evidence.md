# Issue #824: profile-role evidence record

```yaml
record: issue-824-profile-role-contract-v1
status: draft-contract-evidence
issue: 824
profile_identity: ReconstructionProfile.sha256
```

The current repository establishes these facts:

- `ProjectFileRole.VIEWABLE` and `ProjectFileRole.ARCHIVE_PAYLOAD` are declared on
  profile-owned `ProjectFileDeclaration` values, alongside an explicit
  `ProjectContentKind` (`src/main/kotlin/decompengine/project/ReconstructionProfile.kt`).
- The generated-C Make and Ninja descriptors carry those declarations; Ninja changes
  only the declared build-definition path (`GeneratedCMakeReconstructionProfile.kt`,
  `GeneratedCNinjaReconstructionProfile.kt`).
- `WebSourceEvidence` admits a host allowlist of profiles, verifies the manifest's
  profile and input identities, and exposes only manifest entries with the
  `VIEWABLE` role and UTF-8 content (`src/main/kotlin/decompengine/web/WebSourceEvidence.kt`).
- Archive transport selection already resolves through the registered reconstruction
  adapter and checks profile-declared archive payload roles
  (`src/main/kotlin/decompengine/project/ReconstructionAdapter.kt`,
  `src/main/kotlin/decompengine/web/WebArchiveEvidence.kt`).

This is contract evidence from source inspection and existing authored fixtures. It
does not claim that #824 is complete. Generic archive/audit/view conventions still
remain in shared code, including hardcoded source-manifest, audit, archive-readme,
hash-manifest, and confidence-report paths. Those conventions require a later
adapter migration that preserves profile identity, provenance, and unresolved
states.

Production qualification was unavailable for this slice: `scripts/ci.sh`, the
Docker archival gate, ACP contract qualification, production-scale bundled-Ghidra
execution, and authenticated oracle qualification were not run. No external
`GHIDRA_HOME` or `analyzeHeadless` installation was used or introduced.
