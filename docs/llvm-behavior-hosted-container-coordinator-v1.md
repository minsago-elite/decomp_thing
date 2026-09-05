# LLVM behavior hosted clean-build container coordinator v1

This contract defines the Kotlin/JVM-owned outer boundary that may eventually launch the fixed
`LlvmBehaviorHostedCleanBuildV2InnerWorker`. ACP remains the first-class candidate producer and
operator. Its archive, session, and change evidence enter this boundary read-only; ACP has no
oracle, reference-authoring, policy, validation, observation, START, containment,
terminal-absence, scoring, certification, or release authority.
ACP is not an input to the worker-image runtime closure and gains no authority from that closure.

The code-only checkpoint is not hosted-build evidence. Until an authenticated ingress and a live
Docker run complete, every image, container, cleanup, workflow, admission, scoring, and release
claim remains false.

No Python process, module, script, or generated Python evidence participates in this boundary. The
only production logic described here is Kotlin/JVM plus the directly executed authenticated
Clang/LLD toolchain; retained Python compatibility paths cannot satisfy any transition.

## Derived worker image

The reviewed worker image is derived network-free from two inputs:

1. the freshly rebuilt and independently verified LLVM toolchain image ID; and
2. a private build context containing only a staged JDK at `jdk/`, the authenticated Kotlin
   deployment closure at `app/lib/`, and its exact generated launcher arguments at
   `app/worker.args`.

The fixed Dockerfile performs no `RUN`, shell, package-manager, network, secret, or remote fetch.
It copies those two context roots and installs this exact JSON entry point:

```text
/decomp-jdk/bin/java
@/decomp-app/worker.args
```

The authenticated `worker.args` contains `-Djna.nosys=true`, `-Djna.tmpdir=/decomp-jna`, an
explicit colon-separated `/decomp-app/lib/<jar>` class path in deployment-sidecar order, and the
fixed worker main class. No wildcard class-path ordering participates in the launch.

The launcher accepts zero arguments and calls the zero-path inner worker. It is not a general
candidate-build CLI. A derived image ID, rather than a tag or caller digest, binds the JDK, Kotlin
worker, JNA, compiler, linker, system libraries, and fixed image configuration used by one run.
Live inspection requires the inherited image configuration to be exactly the reviewed Ubuntu
`PATH`, empty user and working directory, the single Ubuntu 24.04 OCI version label, the direct
entry point, and an empty command. Inherited volumes, healthchecks, hooks, shell configuration,
loader/JVM environment, or extra labels fail closed.

### Linux image legacy escaping metadata

Image `Config.ArgsEscaped` may be absent or a JSON boolean. BuildKit's
[`dispatchCmd`](https://github.com/moby/buildkit/blob/703866e5f2e4af295b485b181b447a7755d5099c/frontend/dockerfile/dockerfile2llb/convert.go#L1500)
sets it true even for the reviewed `CMD []`, without an operating-system condition.
It is not evidence that the Linux entry point invokes a shell. Docker's
[Linux OCI process construction](https://github.com/moby/moby/blob/v28.0.4/daemon/oci_linux.go#L659)
uses the container path and argument array directly. The image projector still
requires `linux/amd64`, the exact two-element Java entry point, an empty command
and all existing environment/hook restrictions. Null, strings, numbers and
structured values for this metadata are rejected. The stopped-container projector
still requires absent/false `ArgsEscaped`, exact `Path`/`Args` and every existing
runtime restriction. Execution projections and recipe bytes are unchanged.

The `c962a04` hosted run built the production-staged image, then rejected this
field before the retained-tool probe. Its exception did not record the actual
value; the BuildKit behavior above identifies an independently reproducible
incorrect assumption, not a recovered value from that run. The live test now
attaches bounded, escaped inspect diagnostics on projection failure. Required
hosted execution remains necessary; local projector tests are not a Docker pass.
The new true-valued Linux fixture failed against the old projector. After the
correction, 50 focused projector/control/journal/live-contract tests yielded
49 passes, one explicit missing-Docker live skip, and no failures or errors.

### Required live worker-image regression

The LLVM oracle workflow sets `DECOMP_REQUIRE_LLVM_HOSTED_WORKER_IMAGE=1` and runs the opt-in
`LlvmBehaviorHostedWorkerImageLiveIntegrationTest` against the freshly rebuilt exact toolchain
image ID. The test calls the production build-context owner with a separately provisioned,
root-owned JDK, emits that owner's deterministic tar without adding test files, verifies the tar's
recorded size and digest, builds it with networking and cache disabled, and applies the strict
worker-image inspect projector. The root-owned JDK copy preserves symbolic links so copying cannot
silently import an external target and breaks all hard links. If the distribution uses the known
Temurin Debian `lib/security/cacerts` link, the workflow accepts only the exact
`/etc/ssl/certs/adoptium/cacerts` target after proving its real path, root ownership, non-writable
path chain, regular-file type, and byte bound; it copies and compares that file before atomically
replacing only the staged link. The production stager then proves every remaining link is relative,
non-dangling, and resolves lexically and physically inside the copied JDK. A missing, changed, or
unexpected target, Docker executable/socket, exact toolchain image ID, trusted JDK, successful
build, or accepted inspect record is a required-lane failure rather than a skip. Ordinary local
test runs skip this live test unless the required environment flag and all four explicit settings
are present; they do not claim that Docker ran.

The test does not pass a bare local image ID to Dockerfile `FROM`, because BuildKit does not accept
that form as a local base reference. It first proves a bounded UUID tag absent, arms cleanup, tags
the already-selected exact toolchain image ID, and uses only that temporary tag as the build
argument with pulling disabled. Bounded Docker inspection must resolve the tag to the configured
exact ID immediately before and after the derived build. The tag is then removed by its exact name;
the test proves both tag absence and continued inspectability of the original exact toolchain image
and its pre-existing tags. The temporary tag is compatibility plumbing inside test source, not
image-selection or production Docker authority.

Only after the derived image has passed strict inspection does the regression mount a generated
JAR containing only the test-source probe, its shared hostile-check helper, and their nested classes.
The production-staged application JARs are first checked not to contain those classes.
The test uses the fixed `/inputs`, `/stage-output`, `/work`,
`/tmp`, and `/decomp-jna` targets and the production containment limits, then overrides the image
entry point solely to call the zero-argument probe. Two fixed read-only candidate fixture trees are
mounted under `/inputs`; the probe exercises the existing non-authoritative retained-descriptor
Clang and direct-LLD assessment and rejects any execution of candidate build scripts. Before the
two-build reproduction, it replaces both tool names, source/header names, and an object name after
descriptor adoption and requires the retained bytes to remain effective. It also requires a
macro-computed include outside the closed VFS to fail before the header's distinctive contents can
reach compiler diagnostics. The exact success marker records `swaps=5 outside-header=blocked`;
missing LLVM tools fail the required worker probe rather than silently passing. Optional local
JUnit runs report missing tools as explicit skips, unless `DECOMP_REQUIRE_LLVM_RETAINED_TOOLS=1`
requests required-tool mode.

### Docker stdin archive detection

The deterministic context starts with a plain USTAR regular-file header named `Dockerfile`.
Subsequent entries retain PAX paths/link targets, including long UTF-8 names. Every entry still
uses the same root ownership, fixed timestamp, normalized mode, descriptor-selected bytes and
replay digest. This changes the serialized tar size/hash, not the frozen Dockerfile, logical
context membership, launcher arguments, runtime policy or oracle authority. Previous tar hashes
are not reinterpreted as the new bytes.

The earlier always-PAX encoding put the first logical file header at byte 1024, after a PAX
header and its padded body. Buildx's [stdin detection](https://github.com/docker/buildx/blob/1b3aad3219b45e0c38532d0374c25858a4b08f35/build/opt.go)
peeks only 1024 bytes; its [archive predicate](https://github.com/docker/buildx/blob/1b3aad3219b45e0c38532d0374c25858a4b08f35/build/utils.go)
asks Go's tar reader for a logical entry. That prefix cannot supply the entry, so the code takes
the Dockerfile-input branch instead of the tar-context branch. Full-archive parsing alone had
missed this interoperability defect. The observed hosted `COMPRESSION_ERROR` is consistent with
feeding the large binary context to the Dockerfile parser, but hosted success is still required
to confirm that this fix resolves that failure.

The regression checks that 512-byte and 1024-byte prefixes expose the exact regular `Dockerfile`
header to an independent tar reader, and that a PAX-only prefix does not. Existing complete
archive checks still compare every path, type, mode, timestamp, payload and link with an
independent reader. The live build also specifies `--file=Dockerfile`, so an unrecognized archive
fails instead of silently treating the whole input as an inline Dockerfile. No builder fallback,
larger output limit, retry, extra network access or skipped required test is introduced.

Local verification of this fix runs 32 tests: 24 passed, eight environment-dependent retained-tool
or live Docker cases skipped, and zero failures. All ten build-context tests ran, including the
new prefix regression. The first reproduction failed on the old writer with `Truncated TAR
archive`; the corrected prefix and complete-archive checks pass. This host has no Docker daemon,
so these results are not a successful production-staged image build or retained-tool qualification.

The test Docker client accepts image absence only from the exact missing-image response for its
requested reference. Daemon, permission, unsupported-platform/API, and unknown failures remain
indeterminate and abort with bounded escaped diagnostics, including during derived-image cleanup.
An unsuccessful inspect command alone never proves absence.

Image lookup uses one bounded response containing `Id`, `Os`, `Architecture`, and `Variant`.
It accepts only the expected image ID with `linux`, `amd64`, and an empty variant; temporary-tag
identity checks bind the same response to the retained base ID. The test client does not request
`image inspect --platform`: the hosted
[Ubuntu image 20260831.293.1 manifest](https://github.com/actions/runner-images/blob/ubuntu24/20260831.293/images/ubuntu/Ubuntu2404-Readme.md)
ships Docker 28.0.4, whose
[image-inspect command does not implement that option](https://github.com/docker/cli/blob/v28.0.4/cli/command/image/inspect.go).
Build and run commands still require `--platform=linux/amd64`, and the derived worker's complete
inspect response still passes the existing strict image ID, platform, rootfs, and configuration
projection before execution. This compatibility change does not replace platform verification
with a daemon default or weaken missing-image classification.

The template deliberately uses the typed Go field `.ID`, not the JSON key `.Id`.
Docker 28.0.4's [template inspector](https://github.com/docker/cli/blob/v28.0.4/cli/command/inspect/inspector.go)
first formats the typed response and falls back to a raw JSON map with missing-key errors only
when typed formatting fails. Its
[pinned response type](https://github.com/moby/moby/blob/v28.0.4/api/types/image/image_inspect.go)
declares `ID` with JSON name `Id`, and declares `Variant` as a string omitted from JSON when empty.
Using `.Id` would force that fallback and then fail on an absent `Variant`. The typed `.ID`, `.Os`,
and `.Architecture` selectors plus `{{if .Variant}}{{.Variant}}{{end}}` retain a genuinely empty
variant without accepting a sentinel such as `<no value>`; nonempty variants still fail parsing.

That extra probe-JAR mount, fixture shape, direct `docker run`, and entry-point override are an
explicit test overlay. They prove that the exact production-staged image contains a working hosted
Clang/LLD and Kotlin/JNA runtime path, but they are not the fixed inner-worker invocation, a
production `START`, authenticated ingress, lifecycle/absence proof, receipt, observation, score,
publication, or release evidence. No test Docker client or probe is present in production source or
the derived image.

## State machine

One durable operation has this forward-only sequence:

```text
RECOVER
  -> INPUT_AUTHENTICATED
  -> IMAGE_AUTHENTICATED
  -> CREATE_ARMED
  -> CONTAINER_VERIFIED
  -> WORKER_COMPLETED
  -> STAGED_PAIR_VERIFIED
  -> CONTAINER_ABSENCE_PROVED
  -> FINAL_PAIR_PUBLISHED
  -> COMPLETE_AWAITING_ATTESTATION
```

Any failure after `CREATE_ARMED` enters `CLEANUP_REQUIRED`. Final publication is forbidden until
the exact container is removed and terminal absence is proved. The deterministically derived name
is only a recovery locator; the returned container ID and inspected kernel identities remain
authoritative for every mutation.

### RECOVER

Kotlin exclusively locks a pre-provisioned mode-0700 operation root and replays its bounded,
append-only journal before accepting new work. The binding derives the sole container name from
the operation identity before any create attempt, so it remains available after a timeout or
process crash without accepting a caller-selected locator. The request also carries exactly one
operation label, `dev.decompengine.llvm-behavior-hosted-operation=<operationId>`, in addition to
the inherited reviewed image label. A prior armed operation is cleaned by that durable name and,
when recorded, its exact container ID. Corrupt, rolled-back,
cross-operation, or unknown journal residue blocks publication.

### INPUT_AUTHENTICATED

The input archive must arrive through a separately authenticated hosted-ingress record. A URL,
workflow-dispatch scalar, caller digest, arbitrary prior-run artifact, release asset, or local
`reports/build_contract.json` is not ingress authority.

Kotlin independently verifies the raw reconstruction archive and
`candidate-acp-lineage-index-v2.json`, then snapshots exactly these six worker inputs into one
private directory:

```text
candidate-reconstruction.zip
candidate-acp-lineage-index-v2.json
source-lock.json
build-record.json
toolchain-reproduction.json
image-inspect.json
```

The image builds occur before candidate staging so the build context cannot receive candidate
source, credentials, proxy variables, a Docker configuration, an SSH agent, or the repository.

### IMAGE_AUTHENTICATED

The toolchain image is rebuilt without cache from the reviewed Dockerfile, base digest, platform,
and build arguments. Kotlin resolves it once to an image ID and never grants a tag authority. The
derived worker image is built without network or secrets from that exact ID and the closed worker
context. Bounded live image inspection must prove the ID, `linux/amd64`, rootfs/config identity,
fixed entry point, empty command, fixed safe environment, and absence of implicit volumes,
healthchecks, loader/JVM hooks, or shell wrappers. The same live inspection bytes become the
worker's fixed `image-inspect.json` input.

### CREATE_ARMED and CONTAINER_VERIFIED

Before `docker create`, the journal durably records and fsyncs the operation ID and its
deterministically derived container name. The live coordinator must separately descriptor-bind the
authenticated image and staging identities before it arms creation, and retain the returned exact
container ID as soon as creation completes. A timeout can therefore never turn a late container
name into an untracked process. The current code-only journal deliberately marks image, container,
and staging identities unbound; its phase names are not evidence that those checks occurred.

The code-only pre-create plan contains no container-ID input or field and derives its operation
name only from the locked journal owner. It can structurally parse a candidate create-stdout ID and
then render only read-only exact-ID inspection. Those bytes do not prove the invocation, endpoint,
exit status, stderr, or daemon mutation. No START, wait, or removal suffix is exposed by this
checkpoint. A future authenticated coordinator must bind all of those process facts and the strict
stopped-container inspection before it can privately render a mutation command.

The implemented Docker session is correspondingly read-only. Through one descriptor-pinned client,
an empty descriptor-pinned client configuration, and one descriptor-checked private Unix socket, it
can execute only worker-image inspection, retained exact-ID container inspection, anchored exact-name
inventory, and exact-operation-label inventory. Each result is a distinct defensive token bound to
the operation and journal identities; image and container results also retain their expected exact
IDs. These tokens are deliberately non-authoritative. The session accepts caller-selected client
digest and socket bindings, does not authenticate daemon semantics, cannot prove absence from empty
inventories, and exposes no CREATE or other mutation. Kotlin must first derive the runtime bindings
from authenticated corpus evidence, strictly verify the image before mutation, and descriptor-bind
the input and staging roots inside a private coordinator before CREATE can be added.

Kotlin creates a stopped container by exact image ID and then authenticates its effective inspect
record before START. The container must have:

- a read-only root filesystem, `network=none`, private PID/IPC/cgroup namespaces, all capabilities
  dropped, no-new-privileges, builtin seccomp, no privileged mode, devices, host namespaces,
  propagation, restart policy, logging, init, healthcheck, or swap beyond the memory limit;
- the direct fixed JVM entry point above, no command or caller arguments, a closed environment,
  and the numeric UID/GID that owns the private staging roots;
- fixed 4-GiB memory with no additional swap, two-CPU quota, 512-process cgroup, 64-MiB shared
  memory, and exact `core=0`, 2-GiB `fsize`, and `nofile=1024` soft/hard rlimit ceilings; and
- exactly five mounts:
  - `/inputs`: read-only bind of the authenticated snapshot;
  - `/stage-output`: writable bind of a fresh mode-0700 private staging directory;
  - `/work`: mode-0700, 16-GiB, 1,000,000-inode tmpfs with execution enabled because the worker
    executes its authenticated private LLD copy there;
  - `/tmp`: bounded `nosuid,nodev,noexec` tmpfs; and
  - `/decomp-jna`: bounded mode-0700 `nosuid,nodev` tmpfs used only for JNA's executable mapping.

The repository, final output, Docker socket/configuration, home, workspace, credentials, systemd
bus, host JDK, and host application are never mounted.

The request uses exactly two modern `--mount` bind specifications and three legacy `--tmpfs`
specifications. Kotlin checks the two bind requests in `HostConfig.Mounts`, the three tmpfs option
sets in `HostConfig.Tmpfs`, and the two resolved bind records in top-level `Mounts`; the tmpfs
records do not appear in that latter Moby projection. Both resolved bind `Mode` strings are empty
for modern mount specifications, so read-only input access is cross-checked through requested
`ReadOnly=true` and resolved `RW=false` rather than a legacy `Mode=ro` string.

Both host bind sources must be absolute, normalized, non-root paths whose segments use only the
portable ASCII set `[A-Za-z0-9._+@%:=-]`. In particular, commas, whitespace, quotes, backslashes,
and control characters fail before command construction because Docker's `--mount` CSV syntax
does not provide a safe generic encoding for those source strings.

The live client must use the descriptor-pinned empty Docker configuration so client-side proxy
settings cannot add environment variables. The daemon must also be preflighted without additional
default ulimits: Docker merges such defaults into `HostConfig`, and the exact three-ulimit inspect
contract intentionally fails closed rather than accepting an injected limit.

### WORKER_COMPLETED and STAGED_PAIR_VERIFIED

START occurs once by authenticated container ID. There is no `docker exec`. Kotlin applies a
whole-container deadline and requires wait/inspect status agreement, exit code zero, no OOM, no
runtime error, and bounded output. It then reauthenticates the image, inputs, effective container
configuration, and staging directory.

`/stage-output` must contain exactly the mode-0400 receipt and mode-0500 executable. The structural
pair verifier authenticates those exact two bytes. A later strong coordinator gate must also
compare the receipt's otherwise opaque archive, lineage, source, toolchain, and executable claims
with the independently verified inputs and live image facts.

### CONTAINER_ABSENCE_PROVED

Kotlin force-removes only the retained container ID after checking that it is still the inspected
object. It also checks the durable name through the complete late-create uncertainty window.
Terminal proof requires the container object, init pidfd, authenticated cgroup, namespace members,
mounts, and two independently bounded inventories—one filtered by the anchored exact name and one
by the exact operation label—to be absent. A single combined Docker filter is insufficient because
its AND semantics could hide same-name/wrong-label or same-label/wrong-name residue. Daemon
ambiguity, an ABA replacement, surviving descendant, failed removal, unavailable inventory, or
interrupted cleanup blocks final publication.

Each inventory emits only full, untruncated container IDs. Kotlin strictly parses the bounded ID
set and inspects every returned object by that ID; it does not trust delimiter-sensitive rendered
names, labels, or state. An unmatched object blocks publication and does not itself authorize
removal.

The staged pair stays descriptor-pinned throughout cleanup and is reauthenticated afterward.

### FINAL_PAIR_PUBLISHED and COMPLETE_AWAITING_ATTESTATION

The final mode-0700 output directory is never container-visible. Kotlin publishes the mode-0500
executable first and the mode-0400 receipt last using descriptor-bound no-replace operations and
directory synchronization. The receipt is the pair commit marker. Partial state, unrelated files,
aliases, mismatched existing bytes, or a replaced directory fail closed.

Completion means only that the authenticated build-container operation published its exact pair
and proved that build container absent. The inner receipt is not rewritten. Its runtime/workflow
claims remain false. The next hosted step may attest exactly the receipt and executable; a later
offline Kotlin verifier must authenticate the Sigstore bundle and repository/workflow/ref/commit
policy before a separate four-way candidate admission can consume the pair.

## Separate open dependencies

This coordinator cannot manufacture authenticated artifact ingress. That workflow boundary must
name and authenticate the source repository, run, artifact, archive/index pair, retention, and
replay policy before `INPUT_AUTHENTICATED` can be reached.

It also does not by itself close #115. The current inner worker re-extracts the candidate archive
twice and directly compiles `src/**/*.c` with Clang/LLD. Issue #115 separately requires the full
configure/compile/link path and archive/manifest reproduction; that work remains independently
open unless its acceptance criteria are explicitly revised.
