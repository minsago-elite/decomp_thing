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

New module checkpoints use schema 5. Their compilation record binds the command,
source SHA-256, outcome, return code, and diagnostic digest and byte count. The
archive verifier checks a successful record against the source and declared
profile. Historically verified schema-4 archives remain readable; generation
regenerates schema-4 checkpoints so new accepted revisions pass the compiler gate.
Full-project linking and behavior validation remain required by their respective
archive and release workflows.

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
