# LLVM behavior fixed-container inner clean-build worker receipt v2

`candidate-hosted-clean-build-v2.json` is a Kotlin/JVM-produced, unsigned inner-worker receipt for
the deterministic candidate build facts required by #140 and #115. It binds one independently verified
reconstruction archive and its `candidate-acp-lineage-index-v2.json` to two clean builds and one
byte-identical ELF candidate. It is producer evidence, not an authenticated GitHub Actions or
Sigstore attestation.

This checkpoint intentionally exposes no general build CLI or host-side Gradle task. The internal
worker has zero caller-selected paths and reads only fixed future-container paths under `/inputs`,
writes staged output under `/stage-output`, and creates scratch state only under `/work`. Candidate
sources and headers are adopted into sealed anonymous identities before Clang can consume them;
system headers and the normal dynamic-tool runtime remain protected by the inspected read-only
worker root. Only the pending Kotlin-owned outer container coordinator may launch it. In particular,
direct retained-tool execution on an ordinary mutable host is a non-authoritative test seam, not a
production security boundary.
The fixed image, pre-START inspection, crash journal, cleanup ordering, and publication requirements
for that boundary are specified by the
[`hosted container coordinator v1`](llvm-behavior-hosted-container-coordinator-v1.md) contract.

The inner worker writes strict canonical JSON under fixed input, canonical-output, depth, node, and
string limits before schema validation. Every object is closed, the build array has exactly two
positional entries, detailed commands and objects are represented only by count/hash commitments,
and no field can carry an unbounded report or provenance list. JSON Schema checks shape and fixed
constants only. `LlvmBehaviorHostedCleanBuildV2Verifier` separately reopens a mode-0400 receipt and
mode-0500 executable from one closed mode-0700 directory, pins the reviewed schema hash, checks all
explicitly supported repeated-field equalities, inspects the exact ELF, and terminally
reauthenticates both files and their lexical parent. Its public result exposes no archive, lineage,
runtime, or producer-authority projection: those remain opaque receipt claims. That pair verifier
still cannot prove that the builds occurred or authenticate the archive, container, workflow, or
Sigstore provenance.

## Archive and ACP lineage binding

The inner worker starts from its fixed archive and lineage-index paths. Kotlin independently authenticates
the archive before projecting its stored byte length and SHA-256, archive-manifest identity, and
source-tree-manifest identity. `archive.verified=true` means that verification completed; it is not
a caller assertion.

The inner worker parses the lineage index as strict canonical schema-v2 JSON and cross-checks it against
the archive-derived value. The receipt retains its exact bytes and SHA-256, the
`candidateSourceLineageSha256`, the accepted reconstruction/repair counts, and all four ACP
aggregates: receipt, session, change, and joined lineage sets. It also repeats the authenticated
reconstruction profile and full source revision. During production, Kotlin requires every repeated
count, revision, and aggregate to equal both the index and the archive projection.

This makes ACP a `first-class-candidate-producer-operator`. ACP evidence remains read-only input to
Kotlin. ACP has no oracle, reference-authoring, policy-authoring, validation,
observation-authoring, START, containment, terminal-absence, scoring, certification, or release
authority.

## Locked toolchain and inspect artifact

The receipt fixes the exact reviewed LLVM 22.1.6 build environment through the SHA-256 identities
of:

- `oracle/llvm/22.1.6/source-lock.json`;
- `oracle/llvm/22.1.6/toolchain-reproduction.json`;
- `oracle/llvm/22.1.6/build-record.json`; and
- `oracle/llvm/22.1.6/build-toolchain.Dockerfile`.

Those hashes, the recorded-origin image digest, `linux/amd64`, `SOURCE_DATE_EPOCH`, and the compiler
and linker paths, executable lengths, hashes, and version-output hashes are schema constants. The
reproduction artifacts describe a fresh image rebuilt from the locked Dockerfile and base image.
The image ID parsed from their Docker-inspect artifact is retained separately and is not rewritten
into the historical recorded-origin identity.

`runtimeClosure` cross-binds the image digest parsed from that inspect artifact to both builds and
requires the recorded platform to be `linux/amd64`. This unsigned inner worker consumes a bounded
Docker-inspect artifact, so it sets `runtimeImageInspected=false`,
`runtimeClosure.authenticated=false`, and `runtimeClosureAuthenticated=false`. A tag,
caller-claimed digest, or build-record string cannot replace the inspect artifact. The later hosted
workflow attestation (or a Kotlin-owned container coordinator) must prove that both builds actually
ran in that exact inspected image before the runtime boundary is authenticated.

## Exactly two retained-tool clean builds

Build ordinal 1 and build ordinal 2 use separate, empty, private extraction and output roots. Each
starts by extracting the independently verified archive again. Neither build executes the stored
`Makefile`, and neither reads `reports/build_contract.json` as build policy or hosted provenance.
Those files are untrusted candidate payload for this step.

Kotlin derives the bounded source set and fixed argv directly from authenticated source bytes. It
copies authenticated Clang and LLD descriptor bytes into sealed anonymous executable identities and
keeps those identities until each child has been reaped. A private JNA `posix_spawn` boundary selects
the exact retained executable through a parent-owned descriptor capability while fixing logical
`argv[0]` to `clang` or `ld.lld`. Descriptor-pinned working directories are applied before exec, the
environment is rebuilt without `PATH`, `LD_*`, compiler search variables, `HOME`, or `PWD`, and the
child closes every inherited descriptor above stderr. The #140 outer coordinator is a security
prerequisite: its exact five-mount contract leaves the toolchain loader/cache/library locations on
the inspected read-only image root, and the inner worker additionally forbids `/etc/ld.so.preload`.
The kernel and loader may therefore resolve the retained tools' `PT_INTERP` and `DT_NEEDED` names
only from that fixed read-only runtime TCB; this inner receipt deliberately does not claim to
authenticate that dynamic closure. There is no shell, Make, Ninja, CMake, project callback,
caller-provided command, or generic executable runner in the candidate build path.

The descriptor fanout is intentionally finite under the worker's fixed `RLIMIT_NOFILE=1024`:
at most 128 translation units and 256 total candidate `src/`/`include/` inputs are accepted. Every
candidate compiler input is checked against the authenticated revision, copied into a sealed memfd,
and referenced through a sealed Clang VFS overlay with external names disabled. Clang receives the
sealed primary-source inode on stdin and searches quoted includes only under its virtual overlay
parent, so lookup cannot fall through to a physical `/proc` descriptor directory. Kotlin commits
that authenticated primary explicitly because Clang omits stdin from its depfile. Dependency and object outputs are descriptor capabilities;
object bytes are sealed immediately
after the exact Clang child exits. Clang is forced to use integrated cc1 and the integrated assembler,
an explicit reviewed resource directory, and the GCC installation derived from an authenticated
fixed query, so it performs no subordinate tool lookup.

Each build entry is constant-size. `sourceCount` is the number of authenticated `src/**/*.c`
translation units. `compileCommandSetSha256` is the domain-separated, length-prefixed commitment to
the commands in source-path order; each command retains its ordinal and every logical argv token,
while process-local descriptor capabilities are replaced by fixed role placeholders. This keeps the
commitment exact while making retries independent of process IDs, descriptor numbers, and random
scratch-directory names.
Each compile emits a bounded dependency file. Kotlin rejects dependencies outside the authenticated
source revision and reviewed container system-header roots, and commits every canonical dependency
path, byte length, and SHA-256 through `dependencyCount` and `dependencySetSha256`.
`objectSetSha256` uses the same encoding over project-relative object path, byte length, and SHA-256
leaves in source-path order. The sorted environment and link argv have separate commitments.

Linking invokes the exact retained LLD directly. Before compilation, Kotlin runs only the fixed,
bounded Clang `--print-file-name` queries for `Scrt1.o`, `crti.o`, `crtbeginS.o`, `libgcc.a`,
`libgcc_s.so.1`, `libc.so.6`, `libc_nonshared.a`, `ld-linux-x86-64.so.2`, `crtendS.o`, and `crtn.o`.
Every result must be one canonical root-owned file with the expected basename; its authenticated
bytes are copied into a sealed identity. LLD receives those retained CRT/libc/compiler-runtime
identities and the sealed objects in one reviewed order, with no Clang link driver, `-###` parser,
response file, linker script, `-L`, or `-l` search. The loader's canonical runtime pathname and
authenticated identity are both committed; its sealed identity is also supplied under
`--as-needed` after `libc_nonshared.a`, matching the reviewed glibc linker-script dependency.
`linkPlanInputCount` and the ordered
`linkPlanSha256` bind the exact LLD identity/argv0, link command, resolution role, stable logical
path, length, and SHA-256 of every occurrence. No PID or descriptor capability enters the receipt.
LLD writes the candidate ELF to bounded stdout (`-o -`); Kotlin immediately adopts those bytes into
a sealed executable identity.

`combinedOutputSha256` is SHA-256 over each successful compile's bounded stdout/stderr and LLD's
bounded diagnostic stderr in execution order after private-root replacement, with
`combinedOutputBytes` equal to that canonical byte stream's length. Detailed commands, objects,
stdout, and stderr remain in ephemeral build state and cannot expand the receipt.

Each command has a ten-minute cap, each whole clean build has a thirty-minute cap, and compiled
objects have a two-GiB aggregate cap in addition to their individual bounds. Dependency and link
closure bytes are separately aggregate-bounded, and the final executable is capped at 64 MiB.
These are producer resource ceilings, not evidence that a later candidate behavior run was
contained or reached terminal absence.

Each command is a fresh session leader and is pidfd-pinned immediately after spawn. Kotlin drains
separate nonblocking bounded stdout/stderr pipes under the one command deadline. On success, failure,
timeout, or overflow it signals only that unreaped leader's reserved process group and exact pidfd,
then performs exact `waitpid` reaping. It never scans or adopts unrelated JVM descendants. Escaped
sessions remain the responsibility of the separately inspected container cgroup boundary.

The inner worker compares the two final files byte-for-byte, not only by a claimed digest. It then
validates the common file as little-endian ELF64 with machine `x86-64` and records its exact length
and SHA-256 as `candidateExecutable`. The per-build executable identities and the projected
candidate identity must all match.

## Deliberately unsigned claims

This inner-worker receipt truthfully establishes `twoCleanBuildsCompleted=true` and
`executableReproduced=true`. It also records the verified archive/lineage/toolchain bindings and the
image identity parsed from the inspect artifact, without claiming a live image inspection or an
authenticated runtime closure.

It deliberately fixes all of these claims false:

- `hostedWorkflowAuthenticated` and `sigstoreBundleVerified`;
- `admittedArtifactBound`, PREPARED, live-runtime/containment/terminal-absence verification,
  observations, START authorization, candidate start, and candidate execution;
- oracle and reference-authoring or reference-truth authority; and
- scoring, certification, release authority, and release eligibility.

The word “hosted” describes where the worker is intended to run. An unsigned receipt alone does
not prove which workflow ran it. It grants no candidate admission or behavior-execution authority.

## Next attestation boundary

After the missing outer coordinator has validated the staged pair, proved container cleanup, and
published the final pair, the default next step is one default-provenance invocation of
[`actions/attest@v4`](https://github.com/actions/attest) over both final files:

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

A later Kotlin attestation verifier must work offline from raw receipt, executable, bundle, and independently
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
