# LLVM native sandbox helper-policy v2 draft validation

Issue #139's first cutover checkpoint is a Kotlin/JVM validator for a closed native-helper policy
draft. It deliberately stops before the fresh runtime-dependent fields can turn that draft into a
complete sandbox definition, reference capture, or candidate execution. The validator returns
`non-authoritative-native-sandbox-helper-policy-v2-draft-validation` and fixes
`referencePinned=false`, `candidateStarted=false`, `startAuthorized=false`,
`scoringAuthority=false`, and `releaseEligible=false` in both the schema and the result type.

The production entry point accepts exactly five absolute, normalized raw paths: the canonical v2
policy, static helper, adjacent helper checksum, helper C source, and canonical helper build record.
It accepts no JSON parser, runner, callback, precomputed digest, claimed fact, candidate, reference
token, or observation. All five files are bounded and descriptor-backed, receive one pre-open
lexical/inode-alias check, are hashed from their opened bytes, and are re-hashed before return. The
existing native ELF verifier independently checks the helper/checksum pair at the beginning and end,
and this validator reads the ELF machine field itself to require x86-64 for the fixed
`linux/amd64` policy. Initial symbolic components, group/other-writable files or immediate parent
directories, noncanonical JSON, and observed terminal file-key, size, modification-time, permission,
or byte drift fail closed.

This fixed policy validator can succeed only on an x86-64 Linux build host: the shared helper
artifact verifier requires the native helper to match the host, and this policy additionally
requires ELF machine x86-64. The generic v2 helper artifact remains buildable and independently
verifiable on aarch64, but an aarch64 helper cannot satisfy this `linux/amd64` execution policy.

The bundled schema bytes are pinned by a Kotlin digest. After schema validation, Kotlin also compares
every static top-level policy subtree to the schema's exact JSON primitives and structure. JSON
Schema's mathematical number equality therefore cannot admit alternate canonical bytes such as
`65534.0` for the reviewed integer `65534`; changing any reviewed schema byte requires an explicit
code and test checkpoint.

## Closed definition

The bundled schema fixes schema version 2, backend `oci-container-v2`, helper protocol
`decomp-llvm-behavior-helper-v2`, pre-exec frame, and the executable mount at
`/decomp-llvm-behavior-helper`. Dynamic policy fields are limited to exact byte lengths and SHA-256
bindings for the helper, checksum, source, and build record; Kotlin compares each one to the raw
file. The build record has a closed shape and reconciles the exact source and output bytes with the
fixed static compilation argument template. Its compiler path/version is recorded provenance, not
a claim that this checkpoint reopened or authenticated a live compiler.

Four role definitions pin keeper/setup/target/collector users, working directories, capabilities,
mount profiles, resource profiles, full native pre-exec argv templates, and full command argv
templates. Setup and collection use the native helper's `stage` and `collect` modes. The execution
subject is neutral: a future controller supplies either the freshly captured reference executable
or candidate at the same read-only `/subject/executable` role. The policy does not embed candidate
semantics or expected behavior.

The setup and collector command environments literalize `TARGET_UID=65534` and
`TARGET_GID=65534`, matching the fixed target/workspace identity. Those values are not caller or
runtime substitution seams.

ACP is a first-class candidate producer/operator in the closed machine contract, not merely in
prose. The `acpBoundary` fixes ACP's contribution to authenticated candidate session, change,
hosted-build, and admitted-artifact provenance. Kotlin/JVM retains candidate admission and live
execution ownership through a later separately reviewed live owner, and reference-subject admission
is Kotlin/JVM-host-only. ACP provenance is a read-only oracle input: ACP has no oracle,
reference-authoring, policy-authoring, validation, observation-authoring, START, containment,
terminal-absence, scoring, certification, or release authority. “Operator” means the candidate
workflow role; it does not confer sandbox-control authority. This neutral sandbox remains usable for
reference capture because the reference subject and its admission are explicitly separate from ACP
candidate provenance.

The target template uses
`/usr/bin/env -i ${COMMAND_ENVIRONMENT} /subject/executable ${CASE_ARGUMENTS}`.
`${COMMAND_ENVIRONMENT}` is not a caller seam in this validator. It names a future authenticated,
canonical expansion of corpus-global variables plus the per-case overlay, ordered by Unicode code
point of the portable variable name, with no duplicates and fixed 128-binding/64-KiB ceilings. The
other three roles have concrete empty or exact setup/collection allowlists. The helper's bounded
pre-exec environment name allowlist is also fixed separately.

The draft additionally fixes:

- a read-only root, no network, private PID/IPC/cgroup namespaces, dropped capabilities, no-new-
  privileges, builtin seccomp, disabled init/healthcheck/logging, deterministic host files, and a
  private `/tmp`, including per-role tmpfs/device, mode 01777, rw/nosuid/nodev/noexec options,
  byte/inode quotas, and matching per-role shm sizes;
- every role's helper, workspace, input, result, and subject mount, including read-only and
  `volume-nocopy` state;
- cgroup-v2 membership, controllers, read-only controls, CPU/memory/PID profiles, optional defaults,
  cpuset behavior, hierarchy shape, and OOM adjustment;
- exact control/target core, file, descriptor, process, and CPU rlimits with equal soft/hard values;
  and
- tmpfs paths, owner/mode, 32-MiB/1024-entry/depth/copy bounds, descriptor-relative byte-
  lexicographic traversal/rejection rules, regular-file mode preservation during collection, target
  and control timeouts, stdout/stderr bounds, artifact bound, and pre-exec frame bound.

The policy, source, build record, helper, checksum, paths, and decoded JSON strings are rejected if
they contain a case-insensitive `python` runtime string or one of the known v1 runtime sentinels
`decomp-llvm-behavior-helper-v1`, `behavior-preexec-v1`, or `oci-container-v1`. A v1
version/backend/protocol or any mixture carrying one of those sentinels therefore fails before the
v2 schema and Kotlin binding checks can succeed. Historical schema-v1 corpus/report bytes remain
untouched and incompatible; this checkpoint creates no checked v2 corpus or reference bytes.

## Trust boundary and remaining work

Successful validation proves only that the five cooperating build-local files are mutually
consistent with the bundled helper-policy draft. A caller can still supply a new self-consistent,
unreviewed helper/source/build-record/policy set, so `referencePinned` remains false. Each accepted
file owner and immediate-directory owner remains a cooperating principal; so does a principal able
to replace an ancestor path entry and perfectly restore the observed path. The current shared file
guard does not recursively pin ancestor directories or compare owner, group, ctime, or link count,
and its terminal check does not repeat the initial real-path and pairwise-alias observations. These
limits are part of this draft's trust boundary rather than same-UID/root exclusion claims.

The schema records image digest, exact control client, engine declaration, pre-exec environment
values and nonce, distinct reference and candidate subject executables, the candidate's ACP
session/change/build/artifact provenance, command environment, case arguments and stdin bytes,
case-input tree bytes, deterministic host-file bytes, workspace volume identity, results-lease
identity, and mount-source identities as explicitly unbound runtime inputs. The ACP bindings are
candidate-only and must come from authenticated candidate admission; they never apply to or supply
the reference subject. Those values cannot be authenticated from the five raw files accepted here;
the draft must never be described as a complete execution or sandbox definition.

No process is started, no runtime or per-container containment is observed, and no output is
published. A later independently reviewed checkpoint must generate and pin fresh v2 reference
evidence from the neutral subject role, bind the canonical command-environment expansion and exact
case arguments, stdin, and input tree, compose admission/runtime/containment ownership, and prove
terminal absence before any PREPARED/START transition, score, or release decision. The later owner
must bind the machine-required ACP lineage for candidates without granting ACP reference, policy,
validation, observation, scoring, certification, or release authority.
