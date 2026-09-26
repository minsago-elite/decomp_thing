# LLVM clean-build reconstruction archive evidence v1

This document records the smallest evidence contract that can be admitted from
the repository's current LLVM reconstruction facts. It is a retained evidence
boundary for #115; it does not close #115 or any of its child issues.

## Current admitted facts

The fixed-container inner worker contract in
[`llvm-behavior-hosted-clean-build-v2.md`](llvm-behavior-hosted-clean-build-v2.md)
establishes a bounded, unsigned producer receipt for these facts:

- one independently verified reconstruction archive is extracted into two
  separate clean roots;
- authenticated `src/**/*.c` inputs are compiled directly with the retained
  Clang and LLD identities;
- the two resulting executable files are compared byte-for-byte; and
- the receipt retains archive, source-lineage, toolchain, command, dependency,
  object, output, and executable commitments.

The same contract explicitly excludes Make, Ninja, CMake, project callbacks,
caller-provided commands, and a generic executable runner. Its two-build result
therefore supports the producer facts `twoCleanBuildsCompleted=true` and
`executableReproduced=true` only within that bounded direct-build scope.

The ACP lineage index binds accepted session/change provenance to the archive,
but it does not provide hosted-build or executable authority. ACP remains a
read-only candidate producer and has no oracle, validation, scoring,
certification, or release authority. The coordinator contract likewise states
that this worker does not close #115.

## Evidence contract for #115

An eventual #115 completion record must retain these values from independently
authenticated inputs and outputs. A producer receipt or caller assertion must
not substitute for an unavailable value.

| Evidence | Current state | Admission rule |
| --- | --- | --- |
| Archive and full-tree source/dependency provenance | Partial | The current worker binds one verified archive and lineage index. Complete accepted full-tree source, generated-input, tool, runtime, and repair provenance remains the #849 boundary. |
| Full-tree configure, compile, and link | Unavailable | The current worker is a fixed direct Clang/LLD path and deliberately ignores candidate build policy. Do not project it as the #850 configure/build result. |
| Archive bytes and manifest hashes reproduced from independent roots | Unavailable | The current worker reproduces executable bytes only. #851 requires independent archive and manifest reproduction evidence. |
| Hosted workflow, image, runtime, and cleanup authentication | Unavailable | The receipt is unsigned and explicitly leaves hosted workflow, runtime closure, containment, terminal absence, and admitted-artifact claims false. #852 remains open. |
| Bundled Ghidra isolation | Preserved | Analysis continues through the bundled Ghidra Java APIs; production must not require `GHIDRA_HOME` or an external `analyzeHeadless` installation. |
| Authenticated oracle boundary | Preserved | ACP/build receipts remain read-only evidence. They do not grant oracle, reference-authoring, scoring, certification, or release authority. |

The unresolved rows are production gates, not negative claims about whether a
future implementation can satisfy them. Until every required row has current
authenticated evidence, the aggregate status must remain unresolved and #115
must remain open.

## Required cross-binding before promotion

The future completion record must cross-bind, using the repository's canonical
bytes and exact revisions, at least:

1. the admitted archive and complete source/dependency manifest;
2. the source/build/oracle/ACP provenance and bounded repair history;
3. the exact configure and build commands, environment, compiler/linker/runtime
   identities, diagnostics, cleanup observations, and executable identity;
4. the archive bytes and manifest hashes from independent clean roots; and
5. the authenticated hosted workflow and independent archive-verification
   results.

Missing or unsigned values remain unresolved. In particular, the existing
`reports/build_contract.json` is not hosted clean-build evidence, and a local
or caller-claimed digest cannot promote any unresolved row.
