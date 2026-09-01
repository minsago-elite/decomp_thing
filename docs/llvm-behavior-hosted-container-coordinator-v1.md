# LLVM behavior hosted clean-build container coordinator v1

This contract defines the Kotlin/JVM-owned outer boundary that may eventually launch the fixed
`LlvmBehaviorHostedCleanBuildV2InnerWorker`. ACP remains the first-class candidate producer and
operator. Its archive, session, and change evidence enter this boundary read-only; ACP has no
oracle, reference-authoring, policy, validation, observation, START, containment,
terminal-absence, scoring, certification, or release authority.

The code-only checkpoint is not hosted-build evidence. Until an authenticated ingress and a live
Docker run complete, every image, container, cleanup, workflow, admission, scoring, and release
claim remains false.

No Python process, module, script, or generated Python evidence participates in this boundary. The
only production logic described here is Kotlin/JVM plus the directly executed authenticated
Clang/LLD toolchain; retained Python compatibility paths cannot satisfy any transition.

## Derived worker image

The reviewed worker image is derived network-free from two inputs:

1. the freshly rebuilt and independently verified LLVM toolchain image ID; and
2. a private build context containing only a staged JDK at `jdk/` and the authenticated Kotlin
   deployment closure at `app/lib/`.

The fixed Dockerfile performs no `RUN`, shell, package-manager, network, secret, or remote fetch.
It copies those two context roots and installs this exact JSON entry point:

```text
/decomp-jdk/bin/java
-Djna.nosys=true
-Djna.tmpdir=/decomp-jna
-cp
/decomp-app/lib/*
decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain
```

The launcher accepts zero arguments and calls the zero-path inner worker. It is not a general
candidate-build CLI. A derived image ID, rather than a tag or caller digest, binds the JDK, Kotlin
worker, JNA, compiler, linker, system libraries, and fixed image configuration used by one run.
Live inspection requires the inherited image configuration to be exactly the reviewed Ubuntu
`PATH`, empty user and working directory, the single Ubuntu 24.04 OCI version label, the direct
entry point, and an empty command. Inherited volumes, healthchecks, hooks, shell configuration,
loader/JVM environment, or extra labels fail closed.

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
