# LLVM live runtime preflight

`LlvmBehaviorRuntimePreflightPublisher` is the first Kotlin-owned live A15 runtime checkpoint. It
authenticates the checked LLVM behavior corpus and reference tuple, executes only four read-only
control-plane queries against an explicitly supplied private Unix Docker endpoint, and publishes
an immutable identity/capability receipt. It never starts or executes a reconstruction candidate,
does not mount or read candidate bytes, and has no behavior-comparison, scoring, or release
authority.

## Raw production authority

The production method accepts eight absolute normalized `Path` values—the corpus, reference
report, diagnostic matrix, artifact manifest, control-client executable, empty Docker config
directory, Unix runtime socket, and output—and an optional limits object whose values can only
lower hard ceilings. It accepts no process runner, parser, JSON tree, response bytes, claimed
digest, callback, observed fact, score, or token. Internal response fixtures are named
`NonAuthoritative...`; they exercise parsing but cannot authenticate paths, execute a command,
publish bytes, or return the production receipt type.

The four reference files are held by the existing stable-control-file layer and authenticated by
`LlvmBehaviorReferenceEvidenceVerifier`. The control client must be a canonical, single-link,
owner-executable regular file that is not group/world writable. Its exact length and SHA-256 must
match `sandbox.controlClient` in the authenticated corpus. An `O_PATH` descriptor pins that inode,
and `posix_spawn` executes the kernel-owned `/proc/<host-pid>/fd/<fd>` path rather than resolving
the mutable client pathname at exec time.

The Docker config directory must be canonical, empty, current-user-owned, and mode 0700. The Unix
socket and its immediate parent are descriptor-pinned; the socket must be current-user-owned with
owner read/write permission, while its canonical parent must be current-user mode 0700. This makes
group/world socket mode bits ineffective without claiming that root or the same UID is excluded.
The output parent is a separate canonical, dedicated, current-user mode-0700 directory.

## Fixed bounded queries

Every command receives an empty inherited environment and exactly these bindings:

- `DOCKER_CONFIG=<authenticated-empty-directory>`;
- `DOCKER_HOST=unix://<authenticated-private-socket>`;
- `HOME=/nonexistent`;
- `LANG=C`; and
- `LC_ALL=C`.

The executable, working directory (`/`), environment, argument count/bytes, stdout and stderr
captures, and wall clock are bounded by the ACP-owned `LinuxBoundedSessionProcess`. The fixed
queries, in order, are:

1. `--version`;
2. `version --format {{json .Server}}`;
3. `info --format` with the six historical security/runtime fields; and
4. `image inspect <authenticated-image-digest>`.

Nonzero exit, signal termination, timeout, output overflow, malformed UTF-8, malformed or duplicate
JSON, missing fields, and terminal path drift all reject publication. The socket and config
directory are rechecked before and after each query. The client and all raw inputs are terminally
rechecked and the complete reference tuple is independently authenticated a second time. The
output, empty config, socket parent, and authenticated-input parents are separated by inode as well
as spelling, and the config is checked again after receipt publication.

Like the historical verifier, a zero-exit query may write a diagnostic to stderr without changing
the parsed stdout authority. Stderr is still strictly capture-bounded; the receipt records only its
byte count and SHA-256, never its text. Nonzero exit or signal termination always rejects.

## Historical comparison semantics

The Kotlin verifier ports only `_verify_oci_runtime`'s read-only checks. It compares every declared
engine identity field, cgroup driver/version, storage driver, sorted security options, selected
container runtime name/path/version/commit/features digest, local volume-plugin availability,
immutable image ID, platform, ordered image environment, and the absence of implicit image
volumes.

The component digest retains the historical Python
`json.dumps(ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"` byte semantics,
Unicode code-point ordering, and only the two reviewed volatile exclusions:
`(Engine, KernelVersion)` and `(rootlesskit, StateDir)`. The runtime-feature digest remains SHA-256
of the exact UTF-8 feature string. The top-level and Engine-component kernel values must still
agree even though the component copy is excluded from the stable component digest.

## Receipt meaning

The mode-0400, single-link receipt is installed by the descriptor-bound no-replace publisher. It
records the authenticated reference/client/endpoint/config commitments, bounded command transcript
digests, and the live engine, image, platform, and security-capability facts that exactly matched
the corpus. Its positive fields are deliberately named `liveRuntimeIdentityVerified`,
`containmentCapabilitiesVerified`, and `imageVerified`.

`liveContainmentVerified` remains false. Querying rootless, seccomp, cgroup-v2, runtime, and storage
capabilities does not prove that any particular container was created with the corpus isolation
profile. `candidate.started`, `candidate.executed`, `executionClaimed`, `scoringAuthority`, and
`releaseEligible` are also fixed false. No case `expected` exit/stdout/stderr/artifact field or
content is selected, passed to the client, or rendered in the receipt.

## Residuals and next boundary

The exact corpus-bound control client is a cooperating trust principal. The bounded ACP session
runner kills its process group while the unreaped leader still reserves that group ID, but it is
not a cgroup: a deliberately escaping descendant could call `setsid`/`setpgid`. The query runner
also does not impose kernel CPU, memory, or PID ceilings. These gaps prevent using this preflight
as a generic candidate executor; the candidate remains unstarted, and a query failure cannot
produce a receipt.

Descriptor and terminal checks also cannot exclude root or a cooperating same-UID actor that
transiently substitutes and perfectly restores the config/socket/input pathname between checks.
The private-directory requirements exclude other ordinary principals, and the residual is recorded
rather than promoted into containment evidence.

The opt-in real-endpoint test requires
`DECOMP_LLVM_RUNTIME_PREFLIGHT_CLIENT`, `DECOMP_LLVM_RUNTIME_PREFLIGHT_CONFIG`, and
`DECOMP_LLVM_RUNTIME_PREFLIGHT_SOCKET`. Without all three it skips; unit tests use only the
non-authoritative raw-response parser and never manufacture a production receipt.
