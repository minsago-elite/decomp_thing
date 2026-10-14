# Issue97 produced-program observation: Python compatibility checkpoint

This additive path fills the original Clang-driver corpus's **execution** gap.
The checked historical48-case corpus, reference evidence and exact sandbox profile
remain unchanged. Their `link-program` output is still artifact-only evidence;
its `answer` function entry is not relabelled as a clean process entry point.

## Closed observation contract

`oracle/llvm/produced_program.py` accepts the exact checked manifest and locked
84,561,368-byte stripped Clang SHA256
`65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006`.
It checks the reviewed `produced-program-start.s` source digest and literal argv.
The Linux/amd64 fixture uses an explicit `_start` and raw write/exit syscalls. It
writes exactly `issue97-produced-program\n`, exits42, and has no interpreter or
dynamic dependencies. No shell or host execution of the fixture is permitted.

There are exactly two bounded target executions:

1. The generic `record_corpus_observations` records Clang's actual compilation
   report and artifact bytes from the same sandbox collection snapshot. It
   checks exit0, empty streams, and exactly one regular `program` artifact with
   mode0755, within16MiB. A bounded ELF parser requires static amd64 ET_EXEC with
   its entry in file-backed executable bytes. It rejects interpreter/dynamic
   headers. Recording remains an explicit reference-authoring operation.
2. The adapter takes **that returned snapshot**, validates its size/hash/mode,
   and creates a private single-link copy. Generic `run_corpus` snapshots and
   authenticates those exact bytes as its executable, uses the same OCI profile,
   and checks marker stdout, empty stderr and exit42. The source copy's bytes
   and0755 mode are checked before/after; the generic profile stages `/oracle`
   readonly/executable using its unchanged0555 staging policy. No released build
   pathname is reopened and no caller-selected executable replaces the artifact.

Both calls retain the original per-target10s wall/CPU,1MiB per stream,16MiB
artifact/file,1GiB memory,128processes/fds,32MiB workspace and1024entry limits.
The finite pair has two target invocations; existing bounded control/cleanup
operations remain the generic runner's responsibility. Missing or unverifiable
cleanup is failure. Unknown artifacts still fail ordinary replay. No caps rise.

The canonical paired JSON carries both actual reports/corpora and the exact
produced artifact. Strict offline verification cross-binds every source, argv,
profile, bound, expected stream and executable identity. Duplicate/unknown fields,
noncanonical JSON, substitution or malformed artifacts refuse. Offline validation
checks relationships in supplied bytes; it is not a signature or independent
attestation that caller-supplied reports represent actual execution.

All authority fields stay explicit: Python compatibility reference observation;
no Kotlin-runtime, reconstructed-candidate, effectiveness or release qualification.
The retained historical corpus and existing Kotlin reference authentication are
not retroactively changed into execution. #139/#140/#857/#112 retain their scope.

## Local controls

Only inert Python controls are authorized locally for this checkpoint. The18
profile tests include11new controls for the closed pair, wrong/missing/mutated/
oversize artifacts, static-ELF metadata, hardlink/symlink/nonregular/mode refusals,
process/profile/argv changes, first-report failure before second start, snapshot
handoff, legacy recording-wrapper parity and strict offline JSON loading. Synthetic
ELF metadata in tests is never executed. All executor/control-client boundaries in
adapter/generic API controls are explicitly mocked. No live observation is claimed.

```sh
mkdir -p build/issue97-produced-program/offline/tmp
TMPDIR="$PWD/build/issue97-produced-program/offline/tmp" \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest \
  tests.oracle.test_llvm_oracle_profiles -v
```

## Hosted qualification: NOT READY until the historical runtime is provisioned

The explicit `LLVM oracle model` dispatch choice `produced-program-observation`
selects a separate job. It does not become a guaranteed failing mandatory PR job,
activate the unrelated native measurement job, silently skip a missing prerequisite
or interpret unsupported-runtime exit78 as success. It fetches locked Clang inputs
through the existing authenticated release acquisition and actually calls the pair.
The job's exact-client prerequisite and full generic executor checks fail closed.

The original profile pins image
`sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248`,
Docker29.7.2 client bytes42,677,472/SHA256
`e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13`,
and the complete recorded engine/kernel/components/helper profile. A stock hosted
client, rebuilt GCC image807f, or LLVM image73285 is not equivalent. Read-only
acquisition inventory found a pinned client download recipe but **no authenticated
locator for historical image510c**. No image/client/engine bytes have been newly
acquired or authenticated by this implementation. The dispatch job intentionally
requires proper provisioned runtime; it is not a positive qualification yet.
Root must supply an authenticated historical runtime before this exact-profile
path can qualify. The original issue also permits a **new, explicitly reviewed
supplemental reference profile generation** using authenticated reproduced inputs
and a supported hosted engine. That must receive separate source/profile pins;
it may not relabel old observations or silently replace the profile used here.
Current qualification remains pending either supported route.

Once provisioned, the observation command is:

```sh
python3 -B -m oracle.llvm.produced_program \
  --artifact-root "$PWD/build/issue97-live/artifacts" \
  --temporary-root "$PWD/build/issue97-live/tmp" \
  --container-runtime /usr/bin/docker \
  --json-output "$PWD/build/issue97-live/evidence/produced-program-observation.json"
```

The runtime path must hold the exact pinned client; there is no PATH fallback.
Temporary/cache/output paths stay repository-contained. The final evidence output
is exclusive-create. An existing observation can be checked without any process:

```sh
python3 -B -m oracle.llvm.produced_program \
  --verify-observation build/issue97-live/evidence/produced-program-observation.json
```

A supported hosted actual pair, retained commit/source/runtime/output bindings and
strict offline checks must pass before #97 can close. Then #95 still needs its
relevant hosted chain green and no unresolved required A12 issue. This source
checkpoint, synthetic tests, missing-prerequisite refusal, or dispatch workflow
presence does not satisfy those remaining qualification gates.
