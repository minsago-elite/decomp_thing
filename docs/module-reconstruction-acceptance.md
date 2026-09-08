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
only the generated-C/Make adapter is registered today.
