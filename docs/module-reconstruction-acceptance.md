# Module reconstruction acceptance

The configured ACP harness receives the deterministic module target, recovered
evidence for its owned entities, the supplied observed behavior, required module
interfaces, and explicit build and acceptance instructions. The implementation
target must match the profile's editable `module-implementation` declaration.
Selected interfaces are inline prompt snapshots; the one implementation is
writable and no project files are readable by the provider. The workflow
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

Current bounded-agent requests use contract `v4` and input fingerprint provider
`module-reconstruction-input-v3`. The fingerprint binds the input binary/model
schema, profile, compiler policy and exact selected prompt. Incoming recovered
callers are summarized separately from outgoing callees. Caller summaries retain
identity, address, prototype and edges into the owned module, without importing
caller implementations. Outgoing functions and referenced globals supply only
required interfaces. The Generated-C adapter selects the transitive recovered
typedef/tag/enum declarations referenced by those interfaces and local evidence.
Unrelated entities and unrelated observed cases do not enter the prompt or hash.
Recovered type records are atomic: a record containing several declarations is
retained whole when any declaration is needed. Lexical type selection may retain
a same-named alias when a local variable shadows it; it does not invent missing
types or infer executable behavior from names.

Selected shared, module, private and dependency interface snapshots are included
inline in `recovered-module-evidence`, alongside the owned recovered functions and
globals. The objective and both context inputs, including ACP ID/media-type framing and
separators, are assembled and bounded before agent dispatch using the same text
renderer as the ACP transport. The only workspace permissions are write/create on the owned
implementation; headers and prior source cannot expand the readable context.
Complete project headers remain compiler inputs. The provider must replace the
owned implementation from recovered evidence, while the workflow retains prior
source for rollback and acceptance. Durable session inventory captures hashes of
authorized writable paths without granting the provider permission to read them. The archive verifier independently rejects
v4 receipt policies granting header or prior-source reads.

Historical `v3` requests retain their original prompt rendering and structured
`module-reconstruction-input-v2` plus transitive-interface fingerprint replay.
Custom/evidence-only reconstructors retain that historical input contract. Fresh
bounded reconstruction does not reuse a v3 checkpoint as v4 evidence. Archive
fallback replay selects the renderer by the exact versioned reconstructor identity;
relabeling an old fallback with the current contract fails verification.

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
entities in plan order. `GeneratedCDeclarations` preserves the recovered function
declarator, including its return type, parameters, qualifiers and variadic marker,
and changes only the emitted function identifier under the existing naming policy.
It does not replace the model's return type with a guess from the decompiled body
or manufacture a zero-argument prototype. Global types likewise retain their
declared spelling and pointer/array structure.

Model-supplied typedef chains are resolved within bounded declaration context to
identify void, integer and array shapes while retaining their emitted spelling.
An incomplete array, including one hidden behind a typedef, requires initializer
evidence before a definition can be generated. `_Noreturn` placeholders and
static or inline declarations exposed across module boundaries fail with the
affected entity's identity.

Names such as `undefined8`, `byte` and `pointer` are not converted into guessed C
types. The strict compiler resolves named types against the supplied declarations;
missing types fail the existing module gate and remain in its diagnostics and
unresolved-entity inventory. Explicit typedefs and ordinary identifiers with those
spellings remain valid. Malformed or unsupported declarators fail with the model
entity's identity instead of a fallback declaration. Rendering and compilation do
not establish recovered ABI accuracy; authenticated ABI facts and production
qualification remain separate requirements.

The generated-C renderer also selects and renders the synthetic entrypoint and
returns its entity attribution to orchestration. A synthesized zero-argument call
requires an explicit `(void)` parameter list or a model-resolved void alias;
an unspecified `()` declaration, named parameters or a variadic signature cannot
justify dropping arguments. A synthetic entry accepts void or resolved integer
returns, preserving the integer process status; unsupported return shapes fail
before entry artifacts are written.
An existing `main` keeps its recovered declaration.

The explicit `--evidence-only` path selects the closed
`declaration-purpose=evidence-carrier-v1` profile option and the fixed
`evidence-carrier:v1` reconstructor. This changes the profile digest and cache
identity. Its C sources contain a diagnostic inventory with support symbols
derived from digests; raw names, declarations, and initializer displays remain
in the unchanged program-model evidence. Its diagnostic entry point does not
call a recovered function. The full model, plan, and entity ownership remain in
the archive, and every entity remains unresolved. Even an empty inventory does
not claim a completed implementation.

Carrier builds retain the strict compiler flags and archive rebuild checks.
Their module checkpoints cannot become accepted implementations. Archive
admission checks the fixed strategy, deterministic source bytes, and unresolved
state; changing a generator label is insufficient. Project-bound behavior
evidence and repair promotion reject this purpose. Ordinary generated-C
reconstruction continues to require the recovered declarations described above.
These project checks do not classify arbitrary executables supplied without
their project provenance.

`GeneratedCCandidateValidation`
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

`ArchivalReconstructionService`, direct source generation and the bundled model-analyzer factory default to
`ReconstructionHostSafetyLimits.DEFAULT`, an independent immutable host policy.
The service no longer copies the requested profile's budgets into its own admission
ceiling. The default limits cover export time/memory, planner work and cardinality,
module/context size, build time/output and archive inventory/bytes; their initial
values admit both built-in profiles without changing either descriptor digest.
Requests exceeding a default ceiling are rejected before analysis or reconstruction.

A JVM host that explicitly authorizes different limits can pass the same
`ReconstructionHostSafetyLimits` to `GhidraHeadlessProgramModelAnalyzer.bundled`
and `ArchivalReconstructionService`. Direct generation also accepts an explicit
host policy through an additive `SourceTreeGenerator.generate` overload; the
original positional and trailing-lambda signature delegates with the default
host policy. The service forwards the same policy it admitted at construction.
This leaves requested budgets and profile
identity unchanged rather than silently clamping them. The admission test checks
an increased context request, both default entry points, unchanged identities and
explicit host authorization. Individual phases still need their own measured
resource enforcement; admission alone does not prove complete phase budgeting.

Optional `module-observations.json` is preferred over legacy `exploration.json`.
Its bounded schema binds an input SHA-256 and unique cases containing inputs,
exit status, stdout/stderr bytes and producer-supplied recovered-function entry
trace attribution (function IDs and evidence digest). The service validates a
stable regular UTF-8 file under a 4 MiB corpus limit; prompt selection rejects
wrong binary identities or unknown function IDs, and includes only cases whose
traced functions intersect the owned module. Whole-execution outputs remain
non-authoritative context: trace attribution is neither module-only output
attribution nor coverage, equivalence or authenticated oracle evidence.

A real trace integration can supply `ModuleObservationAttributor` to
`AutomaticExplorer`, publish an existing `ExplorationReport` through
`writeModuleObservations`, or call `ModuleObservedBehavior.write` with retained
traced cases. `AutomaticExplorer` checks the input digest before and after its
observation run. It has no default function-entry tracer; absent actual trace
evidence, it produces no guessed attribution. Legacy opaque exploration therefore
contributes an explicit unavailable/unscoped statement to current bounded-agent
prompts. Historical replay and custom reconstructors retain their original text.
Legacy input still uses the smaller of 16 MiB and four times the profile character
limit, with a decoded-character check. Complete selected prompts have a separate
budget check after all interface and observation context is assembled.

The service tests verify Unicode context forwarding and rejection of character
excess, byte excess and malformed UTF-8 before analyzer invocation, source-tree
creation or progress publication. Prelaunch cancellation is also checked before
creating the reconstruction output directory.

Generated-C module objectives and recovered function/global prompt formatting now
belong to `GeneratedCModulePrompt`, selected through `ReconstructionAdapter`.
Make and Ninja share that C-specific implementation. `BoundedLlmModuleReconstructor`
retains the workflow-owned target/role checks, context-size gate, workspace rules,
receipt capture, exact-change validation and rollback. Moving prompt formatting does
not grant the adapter acceptance or filesystem authority.

`HistoricalModulePromptReplayTest` preserves the old 5,515-character prompt and
SHA-256 for both built-in profiles and replays retained v3 fallback artifacts.
`ModulePromptCompatibilityTest` checks current selected prompt commitments and the
exact budget boundary. `ModuleMinimalContextTest` distinguishes incoming callers,
excludes unrelated entities, and compares the measured text with the actual agent
request. These are deterministic contract fixtures, not live ACP or behavioral
qualification.

The complete module prompt now uses the smaller of the selected profile's
`reconstructionMaximumContextCharacters` and the reconstructor's configured
ceiling. That effective limit is recorded in results, cancellation reports,
oversize diagnostics and the profile-aware reconstructor cache identity. Default
profile identities remain unchanged; custom strategies retain their existing
identity unless they opt into the profile-aware method.

Accepted agent candidates, reused checkpoints, rollback baselines and archival
checks require numeric prompt metadata with a nonnegative character count, a
positive budget, and `characters <= budget <= profile limit`. Unresolved records
may retain the size of an oversized prompt that was rejected before dispatch.
The archive's exact factory and cache identity checks still apply. These checks
establish budget consistency; they do not replace invocation-bound ACP evidence.

Focused tests cover either ceiling being tighter, exact-limit dispatch to a
cancelled test harness, default identity compatibility, and unresolved workflow
reports that retain the selected limit without dispatching an agent. Candidate
assessment also rejects an above-profile budget under each supported agent
identity form before invoking the compiler.
The auditor's metadata test covers missing and null values, numeric strings,
negative values, zero budgets and exceeded limits while preserving unaffected
module evidence. Its authored fixture supplies no ACP release receipt.

Direct `SourceTreeGenerator.generate` calls select a planner from the admitted
profile when no planner is supplied. The planner consumes the profile's entity,
dependency-edge and work limits, maximum functions per module, and declared
module implementation/interface paths. The archival service uses this same
selection path.

An explicitly supplied planner retains stricter limits; generation caps each of
its four limits by the profile. Its module implementation and interface
declarations must match the profile before traversal or source-tree writes.
Compatible Make and Ninja module declarations remain interchangeable even though
their build definitions differ. This binds planning policy to the selected
profile; independent host admission remains a separate check and runs before
direct generation selects or runs a planner, invokes reconstruction callbacks,
or writes source-tree files.
