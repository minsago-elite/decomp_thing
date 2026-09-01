# LLVM behavior hosted clean-build receipt v2

`candidate-hosted-clean-build-v2.json` is a Kotlin/JVM-produced, unsigned receipt for the
deterministic candidate build facts required by #140 and #115. It binds one independently verified
reconstruction archive and its `candidate-acp-lineage-index-v2.json` to two clean builds and one
byte-identical ELF candidate. It is producer evidence, not an authenticated GitHub Actions or
Sigstore attestation.

The receipt is strict canonical JSON. Production and verification must apply fixed input,
canonical-output, depth, node, and string limits before schema validation. Every object is closed,
the build array has exactly two positional entries, detailed commands and objects are represented
only by count/hash commitments, and no field can carry an unbounded report or provenance list.

## Archive and ACP lineage binding

The producer starts from raw archive and lineage-index paths. Kotlin independently authenticates
the archive before projecting its stored byte length and SHA-256, archive-manifest identity, and
source-tree-manifest identity. `archive.verified=true` means that verification completed; it is not
a caller assertion.

The producer parses the lineage index as strict canonical schema-v2 JSON and cross-checks it against
the archive-derived value. The receipt retains its exact bytes and SHA-256, the
`candidateSourceLineageSha256`, the accepted reconstruction/repair counts, and all four ACP
aggregates: receipt, session, change, and joined lineage sets. It also repeats the authenticated
reconstruction profile and full source revision. The verifier requires every repeated count,
revision, and aggregate to equal both the index and the archive projection.

This makes ACP a `first-class-candidate-producer-operator`. ACP evidence remains read-only input to
Kotlin. ACP has no oracle, reference-authoring, policy-authoring, validation,
observation-authoring, START, containment, terminal-absence, scoring, certification, or release
authority.

## Locked toolchain and observed runtime

The receipt fixes the exact reviewed LLVM 22.1.6 build environment through the SHA-256 identities
of:

- `oracle/llvm/22.1.6/source-lock.json`;
- `oracle/llvm/22.1.6/toolchain-reproduction.json`;
- `oracle/llvm/22.1.6/build-record.json`; and
- `oracle/llvm/22.1.6/build-toolchain.Dockerfile`.

Those hashes, the recorded-origin image digest, `linux/amd64`, `SOURCE_DATE_EPOCH`, and the compiler
and linker paths, executable lengths, hashes, and version-output hashes are schema constants. A
fresh image is rebuilt from the locked Dockerfile and base image. Its observed image ID is retained
separately: a fresh image ID is runtime evidence and is not rewritten into the historical
recorded-origin identity.

`runtimeClosure` cross-binds that observed image digest to both builds and requires the inspected
platform to be `linux/amd64`. The producer must observe the image identity and platform from the
container runtime; a tag, caller-supplied digest, or build-record string is not an observation.

## Exactly two direct-Clang clean builds

Build ordinal 1 and build ordinal 2 use separate, empty, private extraction and output roots. Each
starts by extracting the independently verified archive again. Neither build executes the stored
`Makefile`, and neither reads `reports/build_contract.json` as build policy or hosted provenance.
Those files are untrusted candidate payload for this step.

Kotlin derives the bounded source set and fixed argv directly from authenticated source bytes. It
invokes the locked Clang executable once per source and invokes the locked Clang driver directly for
the final link. The linker selected by that fixed driver command is the locked LLD. There is no
shell, Make, Ninja, CMake, project callback, or caller-provided command in the candidate build path.

Each build entry is constant-size. It records the source revision and count, a commitment to every
exact compile argv, a commitment to every object path/length/hash, a length and commitment for the
bounded combined process output, and the final executable length/hash. Detailed commands, objects,
stdout, and stderr remain in ephemeral build state and cannot expand the receipt.

The producer compares the two final files byte-for-byte, not only by a claimed digest. It then
validates the common file as little-endian ELF64 with machine `x86-64` and records its exact length
and SHA-256 as `candidateExecutable`. The per-build executable identities and the projected
candidate identity must all match.

## Deliberately unsigned claims

This producer receipt truthfully establishes `twoCleanBuildsCompleted=true` and
`executableReproduced=true`. It also records the verified archive/lineage/toolchain bindings and the
observed runtime closure.

It deliberately fixes all of these claims false:

- `hostedWorkflowAuthenticated` and `sigstoreBundleVerified`;
- `admittedArtifactBound`, PREPARED, live-runtime/containment/terminal-absence verification,
  observations, START authorization, candidate start, and candidate execution;
- oracle and reference-authoring or reference-truth authority; and
- scoring, certification, release authority, and release eligibility.

The word “hosted” describes where the producer is intended to run. An unsigned receipt alone does
not prove which workflow ran it. It grants no candidate admission or behavior-execution authority.

## Next attestation boundary

The default next step is one default-provenance invocation of
[`actions/attest@v4`](https://github.com/actions/attest) after the producer has closed both output
files:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write

steps:
  - uses: actions/attest@v4
    with:
      subject-path: |
        /absolute/output/candidate-hosted-clean-build-v2.json
        /absolute/output/candidate-reconstructed
```

No custom predicate input is supplied, so the action's default SLSA build-provenance mode applies.
The explicit list must resolve to exactly two subjects in one Sigstore bundle, named
`candidate-hosted-clean-build-v2.json` and `candidate-reconstructed`. Wildcards, directories,
additional subjects, two separate single-subject attestations, and a bundle that covers only the
executable all fail closed.

A later Kotlin verifier must work offline from raw receipt, executable, bundle, and independently
pinned trusted-root/policy bytes. It must bound and parse the Sigstore bundle, verify its signature,
certificate and transparency evidence, authenticate the expected repository/workflow/ref/commit
identity, validate the SLSA statement, and require an exact two-element subject set whose names and
digests match the receipt and executable bytes. GitHub documents the trusted-root and bundle inputs
needed for [offline attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline);
the project verifier must perform the equivalent checks under Kotlin ownership before it may set
either attestation claim true.

## Current artifact-ingress limitation

The repository does not yet have an authenticated hosted ingress for a locally generated candidate
archive and lineage index. `workflow_dispatch` accepts scalar inputs, not an uploaded file, and the
existing workflows only upload their own outputs; they do not download and authenticate a candidate
artifact from a designated producer run. A mutable URL, caller-claimed digest, arbitrary prior-run
artifact, or unchecked release asset would merely move the trust gap.

Consequently this contract does not add a workflow or pretend that a local archive reached GitHub
Actions. The follow-up must define a bounded ingress with an authenticated source run/repository,
immutable artifact identity, exact archive/index cross-binding, retention and replay rules, and
fail-closed download semantics. Only then can the hosted job produce these facts and the subsequent
offline Kotlin gate authenticate the two-subject bundle. Candidate admission remains a later,
separate record.
