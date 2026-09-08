# Module reconstruction acceptance

The configured ACP harness receives the deterministic module target, recovered
evidence for its owned entities, the supplied observed behavior, required module
interfaces, and explicit build and acceptance instructions. The implementation
target must match the profile's editable `module-implementation` declaration.
Interfaces are readable and the one implementation is writable. The workflow
retains the invocation receipt before interpreting the agent's result.

A successful agent turn is a candidate revision. Acceptance requires exact
agreement between its source bytes and reported change, complete ACP release
evidence, attributable definitions for every owned entity, no generic placeholder
definitions or undefined decompiler types, and the generated-C compiler gate.
The compiler uses the profile's driver and flags, including mandatory `-Werror`,
and compiles the module to `/dev/null`. Its execution uses the profile's time and
output limits and the same environment sanitation as the full-project builder.

New module checkpoints use schema 6. They retain the selected input-binary identity,
model schema version and profile SHA-256 alongside the module fingerprint.
Cache reuse, rollback acceptance and archival audit require these identities to
match the current model and profile. Their compilation record binds the command,
source SHA-256, outcome, return code, and diagnostic digest and byte count. The
archive verifier checks a successful record against the source and declared
profile. The archive reader accepts historical schema-4 and schema-5 records, but current
audit treats their acceptance as unresolved. Generation regenerates those
checkpoints to retain input identities and pass the current compiler gate.
Full-project linking and behavior validation remain required by their respective
archive and release workflows.

This compiler gate is a local host subprocess. Its record does not independently
authenticate the compiler executable, runtime, or consumed header bytes, and it
does not prove contained production compilation. A local passed record therefore
does not by itself establish production release eligibility; #64 tracks the
qualified contained compiler and complete input/output artifact closure.

If a retry fails validation or is cancelled, the workflow restores the preceding
accepted source and ACP receipt and keeps its checkpoint. A rejected attempt is
recorded under `reports/modules/<module>.attempt.json`; a returned ACP receipt is
retained beside it as `<module>.attempt.execution.json`. A rejection aborts the
generation request, preserving the accepted revision rather than publishing an
invalid replacement. A successful retry or reuse removes these temporary attempt
artifacts. Without a preceding accepted revision, a failed candidate remains
explicitly unresolved and may be retried.

Resume checks bind the module's evidence fingerprint, profile, reconstructor
identity, accepted source hash, and execution receipt hash. These checks cover
completed modules and workflow-observed interruption. Whole-process crash
recovery during revision publication still requires durable transaction coverage
under issue #64. Module-specific selection of observation and shared-type evidence
and production independent-agent runs are also tracked by #64 and #67.

Regression coverage is in `SourceTreeTest`, `AgentExecutionEvidenceTest`, and
`ReconstructionAcpEvidenceArchiveVerifierTest`; the profile and strict project
builder retain their separate focused suites.

Cancellation at the module compiler gate stops reconstruction. It does not become
an ordinary compile rejection or a cached unresolved checkpoint. When a prior
accepted revision exists, the workflow restores its source and execution evidence,
retains an interrupted-attempt report, and preserves the caller's interrupt flag.
The prior accepted checkpoint and manifest remain reusable. Compiler wait
interruption and interrupted file I/O propagate through the cancellation path;
this local behavior does not establish authenticated production compiler identity.

The authored running-compiler regression first compiles an accepted revision with
`cc`, then pauses the next compiler-wrapper invocation after explicit readiness.
It confirms changed candidate bytes are present before interrupting generation,
then requires wrapper termination, restored accepted source/checkpoint/manifest
bytes, preserved cancellation and reuse without another reconstruction call.
This is a local interruption fixture, not production compiler qualification.

Module input fingerprint version 2 uses structured JSON containing the selected
module model (including input-binary SHA-256 and model schema version), exact
shared/module/private interfaces, sorted dependency interfaces, observed-behavior
text, profile digest and compiler policy. The model's deterministic serialization
retains every selected function/global/type field. Null and empty observations
remain distinct. Changing binary identity or model contract invalidates cached
reconstruction even when extracted source fields are otherwise unchanged.

Existing fingerprints use the historical encoding and therefore miss the new
cache key once; regeneration produces the new key. Unchanged current inputs still
reuse accepted checkpoints. This input binding does not make observed-behavior
prose a validated measurement or establish production executable identity.

Each module's confidence `revisionEvidence` exposes `inputBinarySha256`,
`modelSchemaVersion` and `inputFingerprintProvider` beside `inputFingerprint`.
These identify the selected model input and fingerprint encoding without requiring
a reader to infer them from a hash. They are model-bound local attribution fields,
not a new claim of authenticated binary execution or behavioral coverage.

Archival audit exposes `moduleCompilationEvidence`, keyed by module ID, for
accepted revisions that pass its compiler-record checks. Each record retains the
source path and digest, checkpoint path and digest, binary/model/profile identities
and compiler record. For sources marked accepted, invalid or historical
checkpoint records appear in `moduleCompilationEvidenceProblems` instead.
Unaccepted sources have no accepted compiler record. Diagnostic commitments and counts
are format-checked and bounded; retained hashes do not independently authenticate
the compiler or prove that diagnostic bytes were replayed.

Toolchain reporting uses the generated-C adapter's selected compiler driver and
Make version observations. Each probe drains bounded output and waits within the
smaller of the profile build budget and a two-second/16-KiB host ceiling, followed
by the existing build-process cleanup. Failed, oversized, timed-out or invalid
UTF-8 observations are reported as `unavailable`; caller cancellation propagates.
`compilerCommand` and `compilerVersion` replace the historical hardcoded `gcc`
field. These local version strings do not authenticate executable identity.

`GeneratedCProjectRendering` owns shared, public and private C interfaces and the
GNU Make build definition. It indexes model functions/globals and computes
cross-module call visibility once per plan, then renders each module's declared
entities in plan order. `GeneratedCDeclarations` holds the existing C declaration
normalization policy. This extraction preserves current generated-C semantics;
full alternate-profile routing remains separate migration work under #84. Declaration normalization does not
establish recovered ABI accuracy.

The generated-C renderer also selects and renders the synthetic entrypoint and
returns its entity attribution to orchestration. `GeneratedCCandidateValidation`
owns the C function/global definition and placeholder checks and their lexical
helpers. Orchestration retains invocation release, prompt budgets, prior issues,
checkpoint acceptance and rollback. These checks remain the existing local
acceptance policy; they do not certify behavioral equivalence or ABI correctness.

`ModuleCompilationPolicy` is the local compilation contract. Application-owned
`ReconstructionCompilationPolicies` selects it by registered profile ID; profile
data cannot register implementation code. Prompt commands, generation, checkpoint
reuse, fingerprint policy identity, archival audit and archive command checks use
that selection. Generation rejects an unregistered profile before writing the
project or dispatching reconstruction. The generated-C policy identity and
compiler evidence encoding are unchanged. This contract supplies local compilation
only; qualified runner/input/output receipts and complete alternate-profile
routing remain required for production acceptance under #84.

`ReconstructionAdapters` selects local generation behavior and compilation together
by profile ID. The workflow obtains interface/entrypoint/build-definition rendering,
default and failed-attempt fallback reconstruction, candidate assessment and
toolchain reporting from that adapter. `ProjectRendering` exchanges source text
and entity attribution; file publication and checkpoint transactions remain in
orchestration. Explicit caller reconstructors are retained. The public
`EvidenceModuleReconstructor` and `RecoveredCModuleReconstructor` compatibility
names now reside with the generated-C implementation. Full-project build/archive
routing and language-specific prompt/request assumptions remain to be migrated;
generated-C/Make and generated-C/Ninja adapters are registered.

Archival reconstruction resolves its adapter before analysis or output creation
and delegates the full-project build to that adapter. The generated-C adapter
owns Make/compiler command configuration and forwards profile time/output budgets
to the existing builder. Its toolchain report observes the selected build
executable as `buildCommand`/`buildVersion`, replacing the historical `make` field.
Archive verification and the legacy single-project pipeline still contain
additional generated-C/Make conventions; this service dispatch is not complete
alternate-profile support or authenticated production build qualification.

Archive transport selects `ArchiveBuildPolicy` from the registered adapter. The
generated-C policy owns required evidence paths, rebuild instructions, successful
build-contract validation, source revision capture and archived build-input
selection. Creation still verifies the built artifact; extraction verifies the
retained source-bound contract without requiring the omitted binary artifact.
Shared ZIP/path/hash checks and authenticated ACP lineage verification remain in
the archive layer. Model/report path assumptions and other archive consumers still
require migration before alternate-profile support is complete.

Archive model reads and strict control-JSON checks use the profile's declared
`program-model-evidence` path. Required generation reports likewise resolve their
layout declarations rather than assuming the default filenames. The service
regression relocates model, confidence, toolchain and unresolved reports, requires
that the old paths are absent, then performs strict extraction, clean rebuilding
and audit comparison. This proves those report paths are selectable within the
generated-C/Make profile; source/build layout and alternate-language support remain
separate requirements.

The generated-C builder selects the declared build-definition path, adds Make's
`-f` argument when it differs from `Makefile`, and requires the build configuration
to agree with the profile. Build source capture and archive payload comparison
use the same profile-selected input policy, including that build definition.
Default-layout commands and source-hash encoding remain unchanged. The service
fixture also relocates the build definition to `config/rebuild.mk`, verifies its
retained source-input digest and completes strict extraction and rebuilding.
That relocation fixture remains a Make build. The separate generated-C/Ninja
profile provides a non-Make build path; see [its qualification](generated-c-ninja.md).

Build diagnostic ownership reads the selected `module-plan-evidence` declaration.
Relocating that report preserves planned module IDs in the build contract rather
than silently assigning fallback source-path owners. The service fixture relocates
the plan to `reports/planning/modules.json`, compares planned IDs with build owners,
and requires identical build contracts after archive extraction and rebuilding.
This covers build ownership; the separate generated-C repair index still has
its own default report-path assumptions.

The archival reconstruction service derives its final implementation status from
the audit produced during packaging. A successful build with any audited unresolved
entity ends with the `UNRESOLVED` progress phase; its progress file uses `unresolved`.
`reconstruction.json` records `implementationStatus` and `unresolvedEntityCount`
alongside the independent build exit code. When the audited unresolved inventory is
empty, the local implementation workflow uses `complete` / `COMPLETED`. This status
does not assert calibrated recovery accuracy, behavior equivalence, production
containment or release eligibility. Archives remain available for unresolved trees.

The packager returns the audit with its bundle result so the service uses the same
assessment without repeating the audit or reparsing its report. The service also
uses the module count observed during generation rather than planning a second time
for its final summary. Focused Make/Ninja service tests cover a buildable placeholder
tree remaining unresolved and an accepted authored implementation reaching local
completion, including the persisted summary and progress fields.

`ArchivalReconstructionService` and the bundled model-analyzer factory default to
`ReconstructionHostSafetyLimits.DEFAULT`, an independent immutable host policy.
The service no longer copies the requested profile's budgets into its own admission
ceiling. The default limits cover export time/memory, planner work and cardinality,
module/context size, build time/output and archive inventory/bytes; their initial
values admit both built-in profiles without changing either descriptor digest.
Requests exceeding a default ceiling are rejected before analysis or reconstruction.

A JVM host that explicitly authorizes different limits can pass the same
`ReconstructionHostSafetyLimits` to `GhidraHeadlessProgramModelAnalyzer.bundled`
and `ArchivalReconstructionService`. This leaves requested budgets and profile
identity unchanged rather than silently clamping them. The admission test checks
an increased context request, both default entry points, unchanged identities and
explicit host authorization. Individual phases still need their own measured
resource enforcement; admission alone does not prove complete phase budgeting.

Optional `exploration.json` is checked before analysis starts. The service reads a
stable regular file under a byte bound of the smaller of 16 MiB and four times the
profile's reconstruction context character limit, decodes strict UTF-8, then checks
the decoded string length against that character limit. It rejects excessive or
malformed input rather than truncating it or loading an unbounded report. Missing
exploration input remains optional, and admitted text is forwarded unchanged.
This text is prompt context; it does not authenticate behavioral claims or create
measured behavior evidence. Complete module prompts retain their separate budget
check after interfaces and other context are assembled.

The service tests verify Unicode context forwarding and rejection of character
excess, byte excess and malformed UTF-8 before analyzer invocation, source-tree
creation or progress publication. Prelaunch cancellation is also checked before
creating the reconstruction output directory.
