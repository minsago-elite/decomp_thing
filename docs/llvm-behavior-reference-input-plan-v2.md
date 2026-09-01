# LLVM behavior reference input plan v2

Issue #139 requires a Python-free, Kotlin/JVM-owned route to fresh LLVM behavior
reference evidence. This checkpoint supplies only the reviewed input side of that
route. It does not claim a reference executable, runtime, observation, expected
output, comparison, score, START decision, or release decision.

## Kotlin/JVM authoring boundary

`LlvmBehaviorReferenceInputPlanV2Generator` is the production author. Its public
surface accepts only an output `Path`. The 48 case definitions and their literal
UTF-8 bytes are reviewed Kotlin values; Kotlin derives every base64 encoding, byte
length, and SHA-256 digest. The generator does not read the historical behavior
corpus, report, diagnostic matrix, ownership document, sandbox declaration, or any
ACP receipt.

The checked canonical artifact is
`oracle/llvm/22.1.6/behavior-reference-input-plan-v2.json`:

- byte length: `46787`
- SHA-256: `01424f3b14419b2da463c2c5aefbd89a81c03b11ac5847b750f79d72eb7e5d0d`
- schema SHA-256: `e96f2bf456f363150a2ea8a9368831b534b413e8c1d1159c5994c3750c36ce23`

`LlvmBehaviorReferenceInputPlanV2Verifier` accepts only that exact absolute,
normalized filename. It validates the pinned closed schema, canonical JSON, all
case/blob/path/dependency semantics, the fixed artifact digest, stable file
identity, and byte equality with a fresh in-memory rendering from the Kotlin
source definitions.

## Input-only contract

The plan retains the 48 reviewed case intents, 54 literal files, deterministic
base environment, case ownership metadata, arguments, stdin, and categories. It
does not contain any of the historical v1 fields or values that would assert
truth: expected exit status, stdout/stderr bytes or hashes, artifact presence,
artifact modes, report/matrix hashes, mismatch IDs, executable identity, image
identity, engine/client identity, or sandbox programs.

Capture is defined as raw process exit status, raw stdout, raw stderr, and the
complete final workspace tree. Normalization is empty and diagnostic paths are
captured with `raw-bytes-no-rewrite`. Three isolated repetitions are required to
produce byte-identical canonical observation payloads. Those observations do not
exist yet and this input plan does not claim otherwise.

The two PCH reuse cases no longer embed the 240,960-byte PCH captured by the v1
runtime. Each instead depends on `precompile-header:answer.pch` produced within
the same repetition. The plan fixes a topological execution order, requires the
producer's unique `-o answer.pch` pair and each consumer's unique
`-include-pch answer.pch` pair, forbids the producer path from being a staged
input, requires a fresh regular file, and byte-binds the shared `answer.h` input
on both sides.

## ACP boundary

ACP is recorded as the `first-class-candidate-producer-operator`. Its future
candidate contribution is authenticated session, change, hosted-build, and
artifact provenance exposed read-only to Kotlin admission. ACP has no oracle,
reference-authoring, policy-authoring, validation, observation-authoring, START,
containment, terminal-absence, scoring, certification, or release authority.

The input-plan generator consumes no ACP evidence because this artifact defines
reference inputs, not a candidate. Candidate lineage remains the separate #140
prerequisite.

## Reproduction and remaining prerequisite

Regenerate the checked artifact solely through Kotlin/JVM:

```sh
./gradlew generateLlvmBehaviorReferenceInputPlanV2
```

Focused verification is:

```sh
./gradlew test \
  --tests decompengine.oracle.behavior.LlvmBehaviorReferenceInputPlanV2Test \
  --tests decompengine.oracle.core.OracleSchemasTest
```

The checked `behavior-corpus.json`, report, matrix, and Python-bearing
`oci-container-v1` sandbox remain readable only as historical incompatible v1
evidence. No production v2 generator or verifier imports them.

A full `reference-definition-v2` remains intentionally unavailable until a
fresh Kotlin-authenticated runtime declaration supplies a new image/runtime
tuple and binds the exact reference executable. The old v1 image, client,
sandbox, PCH, and reference digests are explicitly inadmissible.
