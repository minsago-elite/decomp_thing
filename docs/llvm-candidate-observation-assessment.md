# LLVM candidate observation assessment

`LlvmBehaviorCandidateAssessmentVerifier` is a bounded Kotlin/JVM comparison utility for the fixed
LLVM 22.1.6 driver behavior reference. Its result is always labeled
`non-authoritative-caller-supplied-observations-v1` and always has `releaseEligible: false`.

This is an A15 precursor, not behavior evidence. The utility does not execute either Clang binary,
create or authenticate a sandbox run, establish that the candidate produced the supplied bytes,
score fidelity, publish an artifact, or authorize a release. ACP may consume a resulting diagnostic
read-only, but neither ACP nor this assessment authors oracle truth.

## Fixed inputs and trust boundary

The one-shot factory accepts exactly seven raw filesystem paths:

1. the checked behavior corpus;
2. the checked reference report;
3. the checked diagnostic matrix;
4. the checked oracle manifest;
5. a candidate executable;
6. caller-supplied candidate observations; and
7. the reviewed case-ownership artifact.

It first invokes the existing fixed Kotlin reference-evidence verifier. It then snapshots the
candidate executable, strict-canonical observation JSON, and exact reviewed ownership bytes.
Candidate executable length and SHA-256 must match the observation binding. Reference corpus ID,
corpus SHA-256, and canonical sandbox SHA-256 must match the authenticated reference. All reference
and caller inputs are read again before terminal acceptance.

There is no factory or constructor that accepts parsed JSON, a digest, a policy, an ownership map, a
runner, a clock, a mismatch identity, a verdict, or a prevalidated token. The implementation invokes
no process and contains no Python dependency.

The filesystem checks pin regular-file identity across each read, reject symlink path components,
and reject group/other-writable candidate executable and immediate-parent modes. They do not exclude
a cooperating owner of the candidate file, its pathname directory, or a writable ancestor (or root)
that transiently mutates or replaces and then restores the accepted pathname and metadata between
observations. This assessment is non-authoritative even when every check succeeds.

## Caller observation contract

`oracle/llvm-behavior-candidate-observations.schema.json` describes schema version 1. The root binds
the exact reference corpus and sandbox plus a separate candidate executable byte length and SHA-256.
It contains exactly the 48 reviewed case IDs in their fixed order. A case is one of:

- `observed`, with an exit code, canonical raw stdout/stderr triples, and bounded raw artifact
  records;
- `not-run`, with a closed failure code; or
- `infrastructure-failed`, with a closed failure code.

A raw blob triple is `(bytes, sha256, base64)`. Base64 length is checked from the declared byte count
before decoding; alphabet, padding, unused trailing bits, decoded length, and SHA-256 are then
recomputed. Present artifact triples also carry a normalized relative POSIX path and readable mode.
Absent artifact data is entirely null. Per-blob, per-case artifact-count, aggregate decoded-byte,
JSON input/canonical, nesting-depth, node-count, string, candidate-executable, and UTF-8 path bounds
are fixed in Kotlin as well as constrained by schema.

The reference binding includes the exact authenticated report, diagnostic-matrix file and self
digests, and artifact-manifest digest in addition to the corpus and sandbox. The observation format
has no fields for pass/fail, mismatch identity, owner, rationale,
normalization, score, or release eligibility. Case-count or order drift is rejected. Missing expected
artifact paths are compared as absence; present extra paths produce `unexpected-artifact` records.
Unknown absent extra paths are rejected because they are not observations.

## Reviewed ownership

`oracle/llvm/22.1.6/behavior-case-ownership.json` is the exact reviewed 48-case ownership map. Its
canonical file SHA-256 is
`f403a57b1712df43d7043b3593f38aa705005136edfd97a78691e273c9a46c5f`. The Kotlin verifier fixes
that digest, validates `oracle/llvm-behavior-case-ownership.schema.json`, requires exact reference
bindings and case order, rejects missing/duplicate owners, and cross-checks all 16 diagnostic owners
against the authenticated diagnostic matrix. There is no fallback owner.

## Derived mismatches and identities

The fixed closed mismatch kinds are:

- `execution`
- `exitCode`
- `stdout`
- `stderr`
- `artifact-presence`
- `artifact-content`
- `artifact-mode`
- `unexpected-artifact`

Both `not-run` and `infrastructure-failed` use the same `execution` identity kind. Their distinct
closed failure codes remain in the record, while a status or reason change does not churn the stable
mismatch identity.

For the 16 diagnostic cases, exit-code, stdout, and stderr differences reuse the exact
`clang-diagnostic-…` identities authenticated by the diagnostic matrix. The matrix's `order`
identity remains reserved. This utility never parses or infers diagnostic order from stderr bytes.

Every other identity hashes UTF-8 domain `decomp-clang-behavior-mismatch-v1`, followed by these UTF-8
components, each prefixed by an unsigned 32-bit big-endian byte length:

1. reference corpus SHA-256;
2. case ID;
3. closed mismatch kind; and
4. artifact path, only for artifact kinds.

The external ID is `clang-behavior-` plus the first 32 lowercase hex digits. Any collision within an
assessment fails closed. The complete ledger is sorted by mismatch ID and exposed through an
unmodifiable copy.

## Assessment output

`oracle/llvm-behavior-comparison-assessment.schema.json` describes deterministic canonical output.
It binds every authenticated reference input digest, the candidate executable, exact observation
SHA-256, ownership ID and SHA-256;
reports exact observed/not-run/infrastructure-failed and matching/mismatching-observed counts; and
contains the complete sorted mismatch ledger. The API defensively copies canonical bytes and exposes
an immutable ledger. Its operator summary begins with `NON-AUTHORITATIVE` and repeats
`releaseEligible=false`.

The output is intentionally not published by this component and is not wired into release CI. A
future authoritative A15 path still needs a Kotlin-owned sandbox runner, authenticated candidate-run
provenance, deterministic repeated replay, persistent mismatch rationale, hosted clean
reconstruction, scoring, and a separate fail-closed release decision.
