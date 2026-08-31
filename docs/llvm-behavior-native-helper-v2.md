# LLVM behavior native helper v2 prerequisite

`decomp-llvm-behavior-helper` is a static native prerequisite for a future Kotlin-owned LLVM
behavior executor. It replaces the three inline Python programs used by the locked v1 sandbox with
one bounded multicall executable. This checkpoint builds, checksums, installs, and hostile-tests the
helper, but does not change the v1 corpus, run either Clang executable, authenticate a live container
runtime, authorize `START`, compare behavior, score fidelity, or authorize a release.

The build-local Kotlin result is therefore deliberately labeled
`non-authoritative-build-local-native-helper-v2`, with `digestPinnedByReference=false`,
`startAuthorized=false`, `scoringAuthority=false`, and `releaseEligible=false`. Its adjacent digest
detects a one-sided replacement of the installed bytes or adjacent checksum; a principal trusted to
rewrite both remains trusted at this checkpoint. It is not a reviewed reference lock. A future v2
corpus must pin the exact installed helper bytes and the
authenticated compiler/build provenance that produced them.

## Closed CLI contract

The first argument is always `decomp-llvm-behavior-helper-v2`. Exactly three roles follow:

- `pre-exec ROLE NONCE MEMORY PIDS CPU_QUOTA CPU_PERIOD FILE_SIZE OPEN_FILES PROCESSES CPU_SECONDS
  OOM_ADJUSTMENT -- ABSOLUTE_COMMAND [ARG ...]`
- `stage`
- `collect`

Unknown versions, roles, extra role arguments, empty or oversized command arguments, relative
commands, malformed or duplicate environment bindings, numeric overflow, leading-zero numeric
aliases, and values outside the fixed policy fail with exit 125. The helper writes no success text.
Pre-exec writes exactly one binary control frame,
`NUL + behavior-preexec-v2:ROLE:NONCE + LF`, immediately before `execv`.

Pre-exec accepts only `keeper`, `setup`, `target`, and `collector`. Nonces are exactly 32 lowercase
hexadecimal characters. The target tuple is fixed to the reviewed current limits: 1 GiB memory, 128
PIDs/processes, 16 MiB file size, 128 open files, 10 CPU seconds, 100000/100000 CPU quota/period,
and OOM score adjustment 500. The three control roles use 512 MiB memory, 64 PIDs/processes, 64 KiB
file size, 128 open files, 30 CPU seconds, the same CPU quota/period, and the same OOM adjustment.

Against the controller-authenticated procfs view, pre-exec requires exact `0::/` cgroup membership
and exactly one read-only cgroup-v2 mount record rooted at `/sys/fs/cgroup`. It checks the listed
memory, swap, pids, CPU, hierarchy, optional-default, required-controller, and cpuset values, no
delegated child cgroups, non-writable control files, exactly one cgroup member, the expected
`oom_score_adj`, and exact core/file/open-file/process/CPU rlimits. The command environment is
caller-defined because it becomes the candidate or control-program environment, but it must be a
bounded set of unique portable names. The future Kotlin controller must authenticate the procfs and
mount configuration and derive and bind those exact values; callers do not get to author a
prevalidated receipt or `START` token.

`stage` requires an otherwise empty environment containing exactly `TARGET_UID`, `TARGET_GID`,
`WORKSPACE_BYTES`, and `WORKSPACE_ENTRIES`. `collect` requires the same four names: the target
identity binds the source workspace. The future controller must separately prove that the collector
runs as UID/GID 0 with only the narrowly required read capability; this helper binds its results root
to the effective collector identity but does not assign that identity. The intended wrapper is
`/usr/bin/env -i`, so image or host environment values cannot leak into either trusted filesystem
role.

## Fixed filesystem boundary

Staging reads `/case-inputs` and writes an initially empty `/workspace`. It verifies that workspace is
one `rw,nosuid,nodev` tmpfs mount whose mounted root is `/`, with the exact declared byte and inode
quotas, owner/group, and mode 0700. The setup process effective UID/GID must equal `TARGET_UID` and
`TARGET_GID`, so every copied entry is created by the declared workspace owner rather than relying on
an implicit chown. Collection revalidates `/workspace` as the exact root of the same quota-bounded
`ro,nosuid,nodev` tmpfs, owned by `TARGET_UID`/`TARGET_GID` with mode 0700. It writes only to an
initially empty `/case-results` directory owned by the collector's effective UID/GID with mode 0700.

Both traversals are descriptor-relative, lexically sorted, and confined to the `STATX_MNT_ID` of
their opened source root; a kernel that cannot report that identity fails closed. They use no followed path component,
reject symlinks, devices, sockets, FIFOs, hard-linked regular files, special mode bits, directory
replacement, entry-set mutation, file shrink/growth, allocated-block drift, and metadata mutation. File opens are checked
against the preceding no-follow metadata and again after copying. Bounds cover path depth, entry
count, logical bytes, allocated blocks, individual copy buffers, arguments, and environment bytes.
Staging emits mode 0400 or 0500 according to the input executable bits; collection requires
owner-readable files and preserves their ordinary 0777 mode. Partial trees remain inside the
throw-away runtime workspace or controller-owned collection lease and are never behavior evidence.

The helper assumes the future controller has stopped the target container and will prove whole-cgroup
terminal absence before collection is accepted. Descriptor checks detect concurrent mutations that
cross the observed metadata/entry-set checkpoints; they do not replace that containment proof.

## Build and installation integrity

`buildLlvmBehaviorHelper` compiles the C source as a bounded static Linux ELF for x86-64 or aarch64.
`verifyLlvmBehaviorHelper` rejects an interpreter, `DT_NEEDED`, writable-executable loads, an
executable stack, a wrong architecture, a missing v2 marker, or a non-fail-closed direct invocation.
`generateLlvmBehaviorHelperChecksum` publishes the exact SHA-256 line used by the raw-path Kotlin
artifact verifier. Distribution verification requires both files under `libexec/`, executable mode
on the helper, and an exact digest match after installation.

The compiler path defaults to `/usr/bin/cc` and may be overridden only through the explicit
`llvmBehaviorHelperCompiler` Gradle property. A compiler version can change the helper digest, so
Gradle deliberately rebuilds instead of treating an earlier binary as up to date. This checkpoint
does not claim reproducible compiler output or assign the generated digest permanent reference
authority.

## Required v2 cutover

The checked `oracle/llvm/22.1.6/behavior-corpus.json` remains schema v1 and continues to hash its
inline `/usr/bin/python3` setup, pre-exec, and collector programs. This helper is incompatible with
that sandbox digest by design. The old corpus/report bytes must not be relabeled, patched in place,
or compared across the runtime-policy boundary.

Before any candidate execution can become authoritative, a separately reviewed Kotlin path must:

1. define a schema-v2 sandbox that pins this helper's byte length, SHA-256, fixed in-container mount
   path, three argv forms, environment allowlists, limits, and compiler/build provenance;
2. authenticate a fresh private OCI runtime and image, then capture the reference binary under that
   exact v2 policy without Python-owned generation or validation;
3. publish a fresh Kotlin-generated canonical corpus report and diagnostic/reference bindings, with
   repeated byte-identical reference runs and hostile mutation coverage; and
4. bind later candidate observations to the v2 reference, admission, live runtime, containment,
   cleanup, clean-build, and ACP provenance receipts.

Until those steps land, neither the helper nor its checksum may enter behavior scoring or release
evidence. ACP may supply authenticated candidate-change/build provenance and consume oracle evidence
read-only; ACP does not author reference truth, observations, scores, or release decisions.
