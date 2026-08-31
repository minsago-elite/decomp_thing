# Program-agnostic executable behavior corpora

The behavior-corpus runner versions observable command-line behavior for an
opaque executable. It is intentionally independent of GCC, compiler driver
rules, ELF, function names, and any particular source-tree layout. Any C
program profile can supply the same closed corpus, immutable runtime image,
inputs, and expected observations. GCC 16.2.0 is the first substantial
benchmark profile, not a product assumption.

## Closed formats

`oracle/behavior-corpus.schema.json` describes corpus version 1 and
`oracle/behavior-corpus-report.schema.json` describes its deterministic
evidence report. The standard-library validator also enforces relationships
that JSON Schema cannot express conveniently. Both formats reject missing or
unknown fields, duplicate object keys, noncanonical paths, malformed hashes or
base64, duplicate IDs, unsorted sets, unbounded collections, and inconsistent
byte/hash/content triples.

Schema v1 admits the opaque target and authenticated control-client executable
identities from 1 through 134,217,728 bytes. This is a migration-tested
correction of the stale 64 MiB schema ceiling: the already-reviewed LLVM 22.1.6
stripped Clang artifact recorded by the checked v1 corpus and report is
84,561,368 bytes. The schema correction changes neither those artifact bytes
nor their digests, and regression tests accept both exact boundaries while
rejecting zero and 128 MiB plus one byte for both executable identities.

Checked corpus files use sorted, two-space-indented JSON and exactly one final
newline. A semantically equivalent file with different whitespace or key order
is rejected, so the report's corpus SHA-256 identifies one exact reviewed
input. Standard streams, stdin, staged input files, and produced artifacts are
all bytes represented with canonical base64, byte length, and SHA-256. No text
decoding is part of comparison.

The offline pair validator additionally cross-binds that exact corpus digest,
executable, sandbox, limits, ordered case IDs, category union, and every
expected exit/stream/artifact observation. A schema-valid report cannot be
substituted for evidence from another corpus or selectively edited unnoticed.

Each case records:

- a stable ID and sorted behavior categories;
- an argument vector executed directly, never through a shell;
- the complete case environment overlay and exact stdin bytes;
- every staged file's normalized relative path, content, hash, length, and
  executable bit (the runner stages it with one exact canonical mode);
- expected exit status, stdout, stderr, and artifact presence/content/mode.

The global environment is an explicit map and `clearInherited` must be true.
Only `DOCKER_HOST`, supplied to the out-of-container control client, may be
provided to the CLI; it is never placed in the case. `{workspace}` and
`{oracle}` are the only argument/environment placeholders. The complete,
ordered image `Config.Env` is separately authenticated and is rejected if it
contains dynamic-loader, locale-loader, allocator, or shell startup-hook
variables. It exists only during the launch of an authenticated absolute
pre-exec wrapper and `env` binary. The wrapper then executes that launcher,
which clears the environment with `env -i` before starting the role command.
The opaque target therefore receives exactly the merged global and case
variables; neither image values nor the launch nonce reach its argv or
environment.

## Hermetic OCI execution

The reusable, program-neutral `oci-container-v1` backend binds each corpus to
an immutable `sha256:<image-id>` and an exact OS/architecture. The runner
verifies that identity before running a case and rejects images that declare
implicit volumes. The image is the case's authenticated userland runtime
closure; the host `/usr`, libraries, environment, home directory, and working
tree are not mounted implicitly.

The profile also binds the exact control-client byte length, SHA-256, and
version output. Its path must be normalized, absolute, nonsymlinked, regular,
and executable. The runner takes one coherent snapshot, stages that snapshot,
and uses only the staged client. Before any case it authenticates an exact
field-exact engine profile: product, server version/commit/API, OS,
architecture and kernel version, cgroup and storage drivers, the complete
security-option set, the explicitly selected OCI runtime's
name/path/version/commit/features hash, local volume-plugin availability, and
a canonical digest of server component identities. That component digest
excludes only the pair `(Engine, KernelVersion)` (recorded separately) and the
pair `(rootlesskit, StateDir)` (a volatile socket-directory location). A field
with either name on any other component remains authenticated. Every component
must have an object-valued `Details` map whose keys and values are validated
before exclusions. Exactly one `Engine` component is required, and its
`Details.KernelVersion` must equal the separately recorded top-level kernel
version. Rootless mode,
the built-in seccomp profile, cgroup namespaces, cgroup v2, and Linux are
mandatory. Every bound field and the control-client identity are copied into
checked evidence.

Each case uses a cryptographically random local-driver volume whose filesystem
is a fresh `tmpfs`. Its creation options exactly bind `workspaceBytes`,
`workspaceEntries` (`nr_inodes`), `nosuid`, `nodev`, its numeric target owner,
and mode 0700. The runner inspects those options before use, and the trusted
setup checks the live mount type, flags, rounded byte capacity, inode capacity,
owner, and mode before copying any input. A trusted keeper
container holds the tmpfs mount alive, and its exact ID, random name, and
running state are rechecked before every handoff. Three separate short-lived
containers then operate on it:

- a trusted setup container receives authenticated host inputs read-only and
  copies their exact tree into the volume as the non-root target user;
- the opaque target runs as PID 1 and that non-root numeric user with the
  volume as its only writable persistent mount, the executable read-only, no
  network or IPC sharing, a read-only image root, every capability dropped,
no-new-privileges, disabled core dumps, and exact cgroup and rlimit bounds;
- after the target container and all its descendants are force-removed, a
  trusted bounded collector mounts the volume read-only and copies its checked
  contents into a fresh private result directory. Only this collector sees
  that host read/write bind, and it receives exactly the one capability needed
  to read target-owned files. The target can neither traverse nor write it.

Before any keeper, setup, target, or collector command can execute, the
profile-authenticated immutable `preExecArgv` runs as that container's PID 1
inside its actual cgroup. It requires a private cgroup-v2 namespace root and
proves the root is read-only, has no delegated child or enabled subtree, and
cannot open its resource controls for writing. It checks `memory.max`, zero
`memory.swap.max`, `pids.max`, the explicit 100000/100000 CPU quota/period,
and the policy-v1 current-cgroup defaults: unlimited `memory.high`, zero
`memory.min`/`memory.low`, disabled group OOM, CPU weight 100, and zero CPU
burst. When exposed, it also checks the canonical CPU idle/nice/uclamp,
swap-high/zswap, I/O max/weight, and cpuset controls. An empty configured cpuset
must have a nonempty effective cpuset inherited from its ancestors. It also
requires the policy's explicit nonnegative OOM score adjustment (500) in
`/proc/self/oom_score_adj`; choosing a value above the rootless daemon's
inherited adjustment makes it enforceable rather than silently inherited. It
also reads the live CORE, FSIZE, NOFILE, NPROC, and CPU rlimits and compares
their soft and hard values exactly. A mismatch exits before the role command.

Container inspection independently applies closed HostConfig resource policy
v1. Besides the requested memory, swap, PID, CPU quota/period, and rlimits, it
requires canonical defaults for cgroup parent, CPU shares/weight/realtime and
cpuset requests, memory reservation/swappiness/kernel-memory and OOM controls,
blkio/device throttles, platform CPU controls, and I/O maxima. Version-dependent
fields may be absent from an older API, but are checked exactly when advertised;
unrelated daemon metadata is not mistaken for a resource request. The corpus's
`resourcePolicyVersion` and `oomScoreAdjustment`, authenticated pre-exec source,
and copied sandbox profile bind this versioned policy into evidence.

After those checks, the wrapper makes one complete small write containing a
fresh role-and-nonce-bound control frame and immediately `exec`s the role. The
runner requires that exact frame at the beginning of the attached byte stream,
removes it before stdout comparison or evidence retention, and rejects a
missing, wrong, duplicate, or target-spoofed frame. The nonce occurs only in
the wrapper's pre-exec arguments and is absent from the command argv and exact
environment after `exec`. This reserves the binary frame prefix for control
use; it is never part of observable target stdout. The long-lived keeper is
started attached, authenticated the same way, and its exact control client is
then detached before the keeper's running state is rechecked.

Every role also gets a size/inode-bounded private `/tmp`, deterministic
read-only hostname/hosts/resolver files, private PID/cgroup/IPC namespaces, a
fixed hostname, daemon logging disabled, and attached output captured under a
hard byte bound. Container creation returns an ID; all inspect, start, attached
execution, and post-exit state checks use and verify that ID. The runner rejects
OOM termination, a runtime-side error, or disagreement between the attached
client status and the container's recorded PID-1 exit. Random names are only
cleanup fallbacks. Cleanup force-removes every returned ID and fallback name
and the volume, retries control-plane failures, then positively inspects each
object and requires proof that it is absent. Before each create is issued, the
runner arms a deadline covering the maximum 30-second control request plus the
complete additional 30-second publication-uncertainty interval. It restores
the prior deadline only after that create has definitively returned. Thus, if a
bounded control client dies or any `BaseException` interrupts an in-flight
create, cleanup keeps polling and removing every random name through the full
possible late-publication interval, then requires post-window absence. A target
start always uses an already verified ID; removing that ID makes a delayed
start incapable of recreating or executing it.

Cleanup uses a resumable index over a fixed list containing all four container
names and the volume. `KeyboardInterrupt` and `SystemExit` are deferred with a
finite retry budget per object and at the orchestration boundary while those
residue attempts continue; afterward the exact first/original exception object
is re-raised with bounded, deterministic secondary diagnostics. On the main
thread, a temporary `SIGINT` handler prevents an actual signal from skipping a
later target once that handler is installed. Worker-thread cleanup does not try
to mutate the process-wide signal handler (Python forbids that outside the main
thread), but applies the same synchronous cancellation state machine.

Exhausting either retry budget says explicitly that absence was not proved.
Python cannot make entry into `finally`, signal-handler installation,
restoration, and exception re-raise one atomic operation, and `SIGKILL` is not
catchable. In particular, `SIGINT` delivered after a primary error but before
the temporary handler is installed still follows the previous handler and can
supersede that error; a signal in the corresponding restoration/re-raise gap
can likewise terminate the runner. Setup/restoration failures are retained as
cleanup diagnostics, and cancellation while deferral is active does not skip a
later cleanup target.

The collector and the host runner independently enforce incremental entry,
logical-byte, and allocated-byte limits before retaining observations. They
reject symlinks, hard links, special files, changed inputs, undeclared files or
directories, missing artifacts, special mode bits, owner-unreadable artifacts,
non-exact permission modes, or mismatched bytes. Aggregate retained evidence,
case/category counts, and the final closed report are validated before any
report bytes are written.

The corpus itself, including `preExecArgv`, `keeperArgv`, `setupArgv`, and
`collectorArgv`, is trusted control-plane input reviewed with the immutable
image. Those commands are not safe extension points for an untrusted corpus
author: the pre-exec wrapper enforces the launch contract, setup can write the
volume, and collector can write the private result bind. The opaque target
alone is treated as hostile.

The OCI daemon, its configured runtime, and host kernel are the sandbox trust boundary. A profile cannot
claim hermetic execution merely by clearing environment variables or mounting
host runtime directories; it must bind a content-addressed image. If the exact
client, exact engine profile, image, platform, isolation profile, tmpfs quota,
or cgroup setup is unavailable, the runner fails closed. The authenticated
engine profile is a declared trusted executor, not an unrecorded input to
program behavior. The wrapper proves exact limits at the private cgroup root
visible to the container. Cgroup-v2 ancestors combine hierarchically and may
only make the child's hard memory/CPU/PID ceilings or effective cpuset stricter;
they cannot weaken those requested child ceilings. Accordingly these are
authenticated no-weaker upper bounds, not a claim that no ancestor can reduce
available resources or relative CPU/I/O service.

## Normalization policy

Raw comparison is the default. Version 1 supports one deliberately narrow
operation: an exact byte replacement of the runtime oracle or workspace path
on one named stream. The declaration names `stdout` or `stderr`, the runtime
path, and the replacement bytes; each case opts in by ID. Application is
ordered, field-specific, and must match at least once. There is no regex,
whitespace, locale, diagnostic, address, timestamp, or line-ending
normalization.

The checked GCC profile needs no normalization at all: its paths, locale,
clock input, helpers, and output bytes are deterministic. Future profiles must
document every nonempty normalization beside their corpus.

## Run and author profiles

The generic runner is suitable for fixtures and for profiles that need no
additional provenance adapter:

```bash
python3 scripts/run-behavior-corpus.py \
  --corpus /path/to/behavior-corpus.json \
  --executable /path/to/program \
  --json-output /tmp/behavior-evidence.json
```

Set `DOCKER=/absolute/path/to/the/profile-locked-client` and, for a rootless
daemon, `DOCKER_HOST=unix:///absolute/path/to/docker.sock`. A client that does
not match the corpus's exact bytes and version is rejected before any case
runs. Production profiles should wrap the generic API to cross-bind their
artifact and runtime to their own source/build manifest.
`oracle.gcc.behavior_corpus` is one such adapter; none of its identity checks
enter the generic runner.

Profile authoring uses `record_corpus_expectations` only to produce a candidate
from already valid case definitions, authenticated inputs, authored exit
statuses, and an immutable image. The generated bytes must be reviewed and
checked in before the verification path will consume them. Verification never
updates expectations. An authored artifact with `present: false` remains a
normative absence assertion during recording and causes recording to fail if
the path appears; automatic discovery adds only paths that were not declared by
the author.

Checked evidence can be validated without executing its opaque target:

```bash
python3 scripts/check-behavior-corpus-evidence.py \
  --corpus /path/to/behavior-corpus.json \
  --evidence /path/to/behavior-evidence.json
```

This offline check authenticates the corpus/evidence relationship; it does not
claim to reproduce execution on the recorded kernel and OCI executor.

For the checked LLVM 22.1.6 profile, the required Kotlin/JVM admission gate also
authenticates the exact corpus and report bytes, the Clang diagnostic matrix,
and the stripped-artifact identity in the release manifest:

```bash
./gradlew verifyLlvmBehaviorReferenceEvidence
```

The Python command above remains a migration compatibility cross-check. It is
not the authority for this checked LLVM reference-evidence admission.

Run the generic adversarial tests with:

```bash
python3 -m unittest tests.oracle.test_behavior_corpus -v
```

They cover binary data, canonical serialization, exact executable/client/image/
engine identity, prelaunch and target-environment separation, field-scoped
normalization, host-secret and external-network denial, PID-1 descendant
cleanup, timed-out and failed control processes, delayed object publication,
mid-case keeper exit, exact container configuration and tmpfs quotas, live
cgroup/rlimit preflight enforcement, split/missing/wrong/spoofed control frames,
entry/logical/allocated-byte bounds, input mutation, special/exact modes,
implicit image volumes, and undeclared files or directories.

The checked-executor probe reserves exit 78 for
`ExactExecutorProfileMismatch`: a well-formed executor that still exposes every
mandatory isolation capability but differs in an authenticated identity or
provenance field. A missing or changed client, unavailable runtime or image,
daemon/control failure, malformed response, missing mandatory security
capability, or verifier failure is an ordinary hard error. Test discovery and
CI apply the same distinction; operational failures never become skips.

The CI live-fixture suite derives and then asserts a field-exact profile for
the pinned rootless executor it is actually running. Checked production
evidence is stricter: it is regenerated only when the host kernel and every
recorded executor field match that profile. Hosted Ubuntu CI reports a visible
profile-mismatch notice and does not claim to have reproduced evidence created
on a different blessed kernel; it still runs the live generic isolation suite
and all offline corpus, schema, adapter, and provenance gates. A pinned
VM/kernel evidence job is deferred executor infrastructure, not a change to
the program-agnostic corpus semantics.
