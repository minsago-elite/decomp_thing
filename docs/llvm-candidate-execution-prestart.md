# LLVM candidate execution pre-START admission

`LlvmBehaviorCandidateExecutionAdmissionPublisher` is the first Kotlin-owned A15 boundary between
an opaque reconstruction candidate and behavior execution. It authenticates and commits everything
the existing LLVM 22.1.6 behavior run would need, then stops before `START`. It does not launch a
process, observe a runtime, collect candidate output, compare behavior, score fidelity, or authorize
a release.

This deliberately fail-closed checkpoint exists because neither current execution abstraction is a
sound generic A15 runner. `BinaryExecutionBoundary` is an MVP string-output interface without the
authenticated runtime, complete resource, byte-stream, workspace, or immutable-publication
contract required by issues #117, #124, #126, and #130. The production full-tree isolation runner
has those stronger primitives, but its journal, worker protocol, filesystem layout, cgroup receipt,
and cleanup state machine are specialized to A13 function observation. Treating either one as a
generic executor would overclaim what ran.

## Raw authority surface

The sole production method accepts six absolute normalized `Path` values:

1. the checked behavior corpus;
2. the checked reference report;
3. the checked diagnostic matrix;
4. the checked LLVM artifact manifest;
5. one opaque candidate executable; and
6. the pre-START receipt destination.

There is no runner, process, parsed JSON, claimed digest, policy, callback, observation, mismatch,
score, or verdict parameter. Even the non-public implementation's JVM constructor accepts only the
same six raw paths and performs the complete operation.

All five inputs remain descriptor-pinned while the host authenticates the fixed reference tuple,
derives the plan, authenticates the tuple a second time, and terminally re-hashes the candidate.
Inputs must be distinct regular nonsymlink files in trusted non-group/world-writable directories.
The candidate must have one link, be owner-executable, fit the fixed 128 MiB ceiling, and not be
group/world writable. Lexical and existing-inode aliases with the output or its deterministic
temporary are rejected.

The receipt binds the exact candidate length/hash; corpus, report, diagnostic-matrix file and
self-hashes, and artifact-manifest hashes; all 48 case IDs; an input-only projection; the exact
sandbox declaration; and the complete execution-limit declaration. Each case separately commits
to its command template, inputs, and declared artifact collection paths. The command commitment
includes the fixed `/candidate/clang` mount path, candidate digest, argument vector, clear-inherited
base environment, and case overlay. The input commitment includes directories, stdin, and staged
file records.

## No oracle disclosure or delegated authority

The authenticated corpus necessarily contains reference expectations, but it remains a host input.
The derived input projection selects only command arguments, environments, directories, stdin,
staged input records, and artifact path names needed to define collection. Artifact path names are
committed by hash and are not readable in the receipt. The projection never selects expected exit
status, stdout/stderr bytes or hashes, artifact presence, mode, content, hash, or base64. The
published JSON contains only the projection commitments and the four reference-artifact hashes; it
contains no readable expectation or comparison result. `oracleExpectationsExposed: false` describes
that mechanically checked receipt property. It is not a claim about a sandbox mount, because no
sandbox or candidate process exists in this phase.

ACP remains the primary candidate producer/operator. An ACP turn may create source changes from
which the host later obtains the opaque candidate path, but ACP does not enter this publisher and
does not receive a parser, reference value, observation, comparison, score, or release capability.
This checkpoint does not yet bind an ACP receipt through a hosted clean build to the resulting
executable; adding that lineage is required before release admission.

## Runtime, limits, and outcome semantics

The runtime section commits the reviewed backend, immutable image digest, platform, containment
policy, control-client identity, engine profile, and sandbox digest. Within this receipt these are
authenticated declarations only. Both `liveRuntimeIdentityVerified` and
`liveContainmentVerified` are fixed to `false`; no Docker engine, OCI runtime, cgroup, namespace,
image, or control-client process was observed during candidate admission. The later, separate
[`LlvmBehaviorRuntimePreflightPublisher`](llvm-runtime-preflight.md) can now verify the declared
engine/image identity and containment capabilities without changing this receipt or authorizing
candidate `START`.

The limits section copies and hashes the fixed timeout, stdout, stderr, artifact, memory, file,
open-file, process, CPU, workspace-byte, and workspace-entry ceilings. Binding a ceiling is not
evidence that it was enforced. Accordingly, the execution phase is fixed to `pre-start`, start
authorization and candidate execution are false, and case results, exit code, signal, timeout,
resource exhaustion, captured-byte counts, and candidate-output identity are all `null` rather than
invented successes or failures. Scoring authority and release eligibility are always false.

## Immutable publication and residual trust

The output parent must already be a canonical dedicated mode-0700 directory. The publisher permits
only the one target or its deterministic recovery temporary, uses the shared descriptor-bound
no-replace protocol, synchronizes the file and directory, and publishes an owner-read-only,
single-link mode-0400 file. A byte-identical target or crash temporary can be recovered
idempotently; a different target, hostile temporary, simultaneous residue, or unrelated directory
entry is retained and rejected.

Descriptor and terminal checks detect every substitution visible at their checkpoints. As with the
current Kotlin control-file layers, they do not prove exclusion of a cooperating same-UID writer or
root that transiently changes and perfectly restores pathname, bytes, metadata, and permissions
between observations. This receipt cannot authorize `START`, so that residual is not promoted into
an execution claim.

## Remaining A15 work

A real candidate execution checkpoint still needs a program-neutral version of the authenticated
OCI/cgroup state machine: private staging of the input-only projection, an immutable candidate
snapshot, exact argv and environment launch, enforced time/memory/PID/file/workspace/output limits,
bounded binary stdout/stderr and artifact collection, signal/exit/OOM/timeout semantics, cleanup
proof, and immutable candidate observations. Live control-client/image/engine capability preflight
now exists, but it does not prove per-container containment and cannot substitute for that runner.
After that, Kotlin still must own deterministic repeat replay, comparison/scoring, persistent
mismatch rationale, hosted clean-build and ACP provenance lineage, and the fail-closed release gate.
The pre-START receipt is not wired into CI or a release workflow.
