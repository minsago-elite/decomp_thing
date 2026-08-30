# Stable ACP v1 client

`AcpAgentHarness` is the subprocess-backed implementation of the provider-neutral agent execution contract. It uses
the official Kotlin SDK from Maven Central:

```text
com.agentclientprotocol:acp:0.30.1
```

All lifecycle, filesystem, terminal, containment, and evidence contracts in this module are target-program neutral.
They authorize explicit workflow paths and exact commands; no compiler, language, build system, or benchmark identity
is embedded in the ACP architecture.

The dependency is exact rather than a range. The SDK's stable `LATEST_PROTOCOL_VERSION` is `1`; the harness also
sends `protocolVersion = 1` with `supportedProtocolVersions = {1}` and uses only the v1 `Client` types. ACP v2 types
are draft, require an explicit SDK opt-in, and are not imported or negotiated here. The no-op SLF4J binding is pinned
alongside the SDK to keep SDK logging silent in CLI and test hosts; subprocess stderr remains separately captured.
JNA is independently pinned to `5.19.1` for the small Linux descriptor and transaction syscall boundary.

## Production gate-helper artifact

The static sandbox gate helper is a production native artifact, not a test fixture. `buildAcpGateHelper` invokes an
explicit compiler executable (`/usr/bin/cc` by default, overrideable with
`-PacpGateHelperCompiler=/absolute/path/to/cc`) using a fixed argument vector and static link. The build then checks
that the result is a bounded little-endian ELF64 executable for the build host, contains neither `PT_INTERP` nor a
`DT_NEEDED` entry, and exits with the fail-closed protocol status when invoked without its gate inputs.

`installDist`, `distZip`, and `distTar` all include the verified files at:

```text
libexec/decomp-acp-gate-helper
libexec/decomp-acp-gate-helper.sha256
```

The helper is installed mode `0755`; the sidecar authenticates its content bytes. Set the ACP configuration's
`sandboxGateHelperExecutable` to the helper's final absolute installed path and copy the sidecar digest into
`expectedSandboxGateHelperSha256`. During trusted provisioning, compute
`expectedSandboxGateHelperManifestSha256` for that final installed inode with
`calculateAcpRuntimeManifestSha256`; do not recompute either expected value during an agent launch. The manifest binds
final ownership, mode, metadata, size, and (for a user-owned installation) content, so a manifest computed in the
Gradle build directory is intentionally not presented as portable installation metadata.

`./gradlew verifyAcpGateHelperDistribution` checks the local `installDist` layout. The JVM test task consumes this same
Gradle-built helper; live ACP tests no longer compile a separate security-boundary executable ad hoc.

The Docker image copies the verified distribution as root and checks mode, ownership, and the content sidecar before
switching to the service user. Packaging does not weaken the runtime prerequisites: a container still needs supported
user namespaces, bubblewrap, a user systemd manager and cgroup-v2 authority. If those authorities are unavailable, ACP
preflight and launch fail closed; the image does not add `SYS_ADMIN`, privileged mode, or a fallback sandbox.

## Operator provisioning and preflight

[`config/acp-v1.example.json`](../config/acp-v1.example.json) is the bounded minimal ACP configuration template. It is
intentionally not runnable as checked in: every all-zero digest is a fail-closed placeholder, the user-systemd runtime
path is UID-specific, and the example agent path does not exist until it is provisioned. Copy it to a private regular
file owned by the dedicated service UID with mode `0600`; `ACP_CONFIG_FILE` must be its absolute normalized path.

Provision the components in this order:

1. Create a dedicated, uncompromised service account. Enable and start its user systemd manager, ensure its live
   `/run/user/<uid>/bus` is accessible to that same UID, and verify unified cgroup v2. The account is the trust boundary:
   an unrelated process already running as that UID can interfere through same-UID Linux powers.
2. Install a locally runnable, network-free native ACP v1 executable at
   `/opt/decomp-acp-agent/bin/acp-agent` and its read-only dependency closure at
   `/opt/decomp-acp-agent/runtime`. Direct scripts are not valid executable targets; provision a native interpreter as
   the executable and put the script in a separately manifested read-only mount if that is the reviewed design.
3. Run `./gradlew installDist`, then install the verified static
   `build/install/llm_bin_patch/libexec/decomp-acp-gate-helper` at
   `/opt/decomp-acp-host/decomp-acp-gate-helper`. Verify its distribution sidecar before copying it:

   ```bash
   (cd build/install/llm_bin_patch/libexec && \
     sha256sum --check --strict decomp-acp-gate-helper.sha256)
   sudo install -d -o root -g root -m 0755 /opt/decomp-acp-host
   sudo install -o root -g root -m 0755 \
     build/install/llm_bin_patch/libexec/decomp-acp-gate-helper \
     /opt/decomp-acp-host/decomp-acp-gate-helper
   ```
4. On the final installed inodes, compute content SHA-256 for `/usr/bin/bwrap`, `/usr/bin/prlimit`,
   `/usr/bin/systemd-run`, `/usr/bin/systemctl`, `/usr/bin/bash`, and the gate helper with `sha256sum`. Compute the
   versioned metadata manifests for the agent executable, agent runtime closure, and gate helper with the repository's
   public production algorithm:

   ```bash
   sha256sum /usr/bin/bwrap /usr/bin/prlimit /usr/bin/systemd-run \
     /usr/bin/systemctl /usr/bin/bash /opt/decomp-acp-host/decomp-acp-gate-helper
   scripts/calculate-acp-runtime-manifest.sh /opt/decomp-acp-agent/bin/acp-agent
   scripts/calculate-acp-runtime-manifest.sh /opt/decomp-acp-agent/runtime
   scripts/calculate-acp-runtime-manifest.sh /opt/decomp-acp-host/decomp-acp-gate-helper
   ```

   Run those commands only during trusted provisioning and persist the results in the private configuration. Never
   calculate an expected digest from the live path immediately before launch. The helper script uses the exact
   `AcpRuntimeClosureLimits` encoded by the template; if those limits change, the provisioning computation must use the
   same reviewed values.
5. Copy the template with `install -m 600`, replace every zero digest, change
   `systemdUserRuntimeDirectory` to the dedicated UID, and review the exact ordered argv. The example is the literal
   vector `[/opt/decomp-acp-agent/bin/acp-agent, --stdio, --non-interactive]`; no shell parses it. Add only capabilities
   the agent must support globally. `doctor --workflow all` adds the bounded capability requirements of every selected
   workflow before accepting the handshake.
6. Keep the template's `environment: []` for a literally credential-free local agent. If a workflow genuinely needs a
   secret, add only an exact reviewed binding such as the following and supply the named source in the service
   environment:

   ```json
   "environment": [
     {
       "name": "ACP_AGENT_SECRET",
       "provenance": "secret",
       "valueFromEnvironment": "ACP_AGENT_SECRET"
     }
   ]
   ```

   The configuration stores the source name and provenance, never the value; `inheritParentEnvironment` must remain
   `false`, and no ambient environment is serialized or forwarded. Once a secret binding is configured, preflight
   resolves and forwards that exact variable to the agent even though it never creates a session or sends a prompt.
   Host-native execution can export that one name. Compose requires the same explicit one-name opt-in rather than an
   ambient environment file:

   ```bash
   export ACP_AGENT_SECRET
   docker compose --profile acp-host run --rm --no-deps \
     -e ACP_AGENT_SECRET llm-bin-patch doctor --workflow all --output /output
   ```

Perform the real credential-free initialize preflight before any workflow:

```bash
export ACP_CONFIG_FILE=/absolute/private/path/acp-v1.json
build/install/llm_bin_patch/bin/llm_bin_patch doctor --workflow all --output ./output
```

This uses the same strict factory and production sandbox as agent execution. It sends `initialize`, requires stable ACP
v1 and every configured plus selected-workflow capability, then shuts down and proves cleanup. The checked template
requires no credential and the preflight never sends `session/new` or `session/prompt`. A configured secret is still
available to the launched agent during initialize; do not claim that a third-party agent will ignore it. A missing
capability, incompatible ACP version, agent crash, stale process, or cleanup failure makes the preflight fail.

The Compose `acp-host` profile is only a host-prerequisite qualification surface. It deliberately uses host PID and
cgroup namespaces plus read-only binds of `/sys/fs/cgroup` and the dedicated UID's user bus so the existing production
scope inspection can run. It also declares `userns_mode: host`: Docker UID remapping is deliberately disabled for the
non-root ACP application and runner so their configured numeric UID is the same host identity that owns the user bus
and private control volume. This grants the container process exactly the repository's documented same-UID host trust
boundary. The service has a read-only root, drops all capabilities, sets `no-new-privileges`, and keeps the outer agent
network isolated. It never requests `SYS_ADMIN`, privileged mode, or an unconfined seccomp profile. Therefore only a
local network-free agent is usable. Remote or provider-backed ACP agents are not supported by this namespace today.
Rootless or remapped daemons may reject the host user-namespace mode. If the host user manager,
`systemd-run --scope`, cgroup visibility, nested unprivileged user namespaces, or the container runtime's default
seccomp policy prevents the production checks, `doctor` must fail and the host is unqualified; do not bypass the check.

`doctor --tools-only` remains useful for checking the bundled compiler/decompiler toolchain, but it intentionally does
not resolve `ACP_CONFIG_FILE` or launch an agent and cannot qualify an ACP deployment. The old OpenAI-compatible
`GET /models` probe is available only through exact `--harness legacy-openai`; its variables live in
`.env.legacy-openai.example` and are deprecated compatibility inputs.

The 0.30.1 SDK marks three optional v1 schema extensions used at the contract boundary as `UnstableApi`: additional
session directories, prompt token usage, and message identifiers. Opt-in is deliberately scoped to the adapter code
that reads those fields. They do not change version negotiation: they remain v1 fields, additional directories are
capability-gated, and usage/message identifiers are normalized rather than exposed as SDK types. The upgrade checks
below must review these fields explicitly; removal or wire-shape changes require adapter and subprocess-test changes.

## Process and wire boundary

The public `AcpAgentHarness` has no uncontained production mode. Before it starts an ACP agent it verifies an explicit
Linux boundary made from digest-pinned, canonical, root-owned `bubblewrap`, `prlimit`, `systemd-run`, `systemctl`, and
`bash` executables plus a digest/manifest-pinned static gate helper. Absence, replacement, an unsupported platform, a missing user systemd bus, or inability to create and
inspect the required cgroup-v2 scope is a configuration failure. The production artifact exposes no uncontained
harness constructor, injected boundary/launcher factory, test mode, or fake terminal-boundary entry point. The public
harness always creates the final production boundary itself; tests exercise that same boundary.

The configured agent/terminal executable and ordered argument vector are explicit and are never parsed as shell
syntax. One separately pinned Bash invocation, already inside the transient scope, runs only the constant boundary
script `exec 4<"$1"; shift; exec "$@"`: the private environment-bootstrap path and exact bubblewrap argv are quoted positional
arguments, and no agent-, workflow-, or terminal-supplied byte enters shell syntax. The supervisor starts this fixed
launcher inside the verified scope; the launcher immediately replaces itself with bubblewrap, so only ordinary stdio
crosses the systemd boundary. Mutable
user-installed agent executables and runtime closures require a provisioning-time recursive manifest. At launch they
are copied through identity-bound descriptors into a private closure whose pinned outer container remains exact mode
`0700` for descriptor-relative cleanup; only the mounted `root` subtree is recursively made non-writable, rehashed,
pinned by an open descriptor, and mounted from that private snapshot path. Recursively root-owned,
non-group/world-writable closures may be mounted directly from their immutable path while an open descriptor anchors
identity revalidation. Cross-process `/proc/<pid>/fd` mount paths are not used because user-namespace access to them is
not portable. Links, special entries, mount transitions, excessive depth/count/bytes,
and closures containing bubblewrap, systemd scope tools, or user-namespace launchers are rejected.
Every security executable path is canonical and every ancestor from `/` to the executable is root-owned,
non-group/world-writable, and not writable by the current effective user. POSIX/NFS/rich ACLs and executable capability
xattrs are rejected as authority-bearing metadata. Permitted stable LSM labels and ordinary xattrs are included in the
pinned metadata digest rather than mistaken for write authority. This makes later path execution safe against a
same-UID rename or restored-path ABA within the process boundary, rather than relying on a digest check around a
mutable pathname.

Every outer agent uses `bwrap --unshare-all --unshare-user --new-session --die-with-parent --clearenv
--disable-userns --assert-userns-disabled`, all capabilities dropped, and private `/proc`, `/dev`, and `/tmp`. It sees
no host root, home, ambient secrets, or host network namespace. `--not-a-security-boundary` is never used. Session
`cwd` and
additional-directory paths are private empty anchors: they exist so an agent can form callback paths, but direct
syscalls reveal no host workspace data. The agent itself starts in private `/tmp`. Environment inheritance is
prohibited; only explicit names and typed `PUBLIC` or `SECRET` values are installed.

Each process is placed in a random collision-checked transient systemd user scope whose manager metadata and actual
cgroup-v2 leaf files prove finite `pids.max`, `memory.max`, `memory.swap.max = 0`, `memory.oom.group = 1`, and `cpu.max`,
plus manager `OOMPolicy=kill`, `KillMode=control-group`, a finite runtime maximum, and no delegation. `RLIMIT_NPROC` is
only a loose host-UID backstop, never the process authority; its finite headroom is based on current same-UID Linux
tasks (threads), not merely process leaders. The outer, clean-environment `prlimit` invocation fixes
exact NOFILE, FSIZE, CORE, AS, and CPU limits before systemd creates the scope; the host verifies the helper's effective
soft and hard limits from `/proc` before authorization.

Launch has one post-mount authorization gate. Each launch creates an unnamed environment inode, forces and verifies
mode `0600`, materializes one unpredictable private bootstrap name, and lets the constant Bash launcher open that name
once as fd 4 before replacing itself with bubblewrap. Bubblewrap uses `--clearenv` and
`--ro-bind-fd 4 /decomp-acp-internal/environment`, completes namespaces and mounts, then starts the genuinely static
gate helper (verified ELF with neither `PT_INTERP` nor `DT_NEEDED`) at the reserved internal path. The helper begins
with no caller environment: it accepts only bubblewrap's unavoidable single `PWD` binding when its value exactly
matches `getcwd()` (the direct protocol probe may supply no binding), and rejects every other bootstrap variable.
That bootstrap value is never inherited by the target. The helper normalizes signals, closes surplus descriptors,
opens the exact native target as fd 3 and the environment bind as fd 4, and blocks in a raw one-byte read on ACP stdin.
It accepts only `G`; EOF, a wrong byte, or malformed environment records exits without executing the target. After
`G` it parses bounded, sorted, unique NUL
`NAME=VALUE` records and calls `execveat(fd3, "", ..., AT_EMPTY_PATH)`, so it performs no PATH lookup or post-check
target pathname resolution. Direct script targets are rejected; a workflow must authorize a native interpreter and
pass the script as an explicit read-only argv/data mount.

While the helper is blocked, the host proves its exact executable, fixed argv, process topology/start times and cgroup,
the exact single `PWD=getcwd()` bootstrap environment, namespace/capability state, `read(fd0, ..., 1)`,
target/environment descriptor identities,
and exact limits. It strictly bounds and parses mountinfo and stats every sandbox-visible runtime, staging, helper,
target, and environment bind below `/proc/<helper>/root`; device, inode, type, mode, mountpoint, and read-only/write mode
must match the pinned host authority (bind mount IDs may legitimately differ). The host then descriptor-relatively
unlinks the environment and single-file helper/target snapshots, proves link count zero, rehashes them through retained
descriptors, repeats all binding and waiter attestations, performs the final cancellation check, reserves bounded
launch-evidence capacity, and invokes the broker's internal write-ahead authorization/audit callback. Only then does it
record the authorized launch and attempt exactly one `G` byte. No cancellation, policy, or audit decision follows that
commit: an IOException
cannot distinguish a delivered byte from a peer close, so process outcome is authoritative. Independent or nested
launches use independent helpers and never share a global lock.

Every potentially multi-entry or multi-byte pre-authorization step uses the caller's shared cancellation/wall-deadline
checkpoint: initial boundary preparation and tool probes, policy-only runtime validation, recursive manifesting and
snapshot copy/hardening, the same-UID task scan used only to size the `RLIMIT_NPROC` backstop, systemd attachment
polling, environment validation/sorting/encoding, multi-mount command construction, staging-quota identity checks,
helper/process/mount attestation, bounded `/proc` reads, exact rlimit verification, and canonical policy/evidence
construction. Environment, argv, runtime-mount, staging-root, empty-anchor, command-rule, launch-evidence, audit, and
canonical-metadata collections also have explicit aggregate count and byte ceilings before materialization. A checkpoint failure
enters the same proven cleanup path; cleanup itself is intentionally non-cancellable and retains resources if absence
cannot be proved.
If cancellation wins immediately after `systemd-run` starts but before it publishes `ControlGroup`, cleanup first
terminates the still-unreleased process and accepts success only when the exact unit is `not-found` and a bounded,
exhaustive cgroup-v2 hierarchy walk proves that no directory bearing that random unit name remains. A discovered path
is never used for signaling unless it came from the exact unit metadata; an oversized or deep hierarchy fails closed.

Private cleanup is descriptor/name-bound and bounded across the whole tree by aggregate entry, logical-byte, and depth
budgets; excess retains the pinned tree and surfaces a cleanup-proof failure instead of recursing or allocating without
limit. Cleanup succeeds only after the scope/cgroup, environment, runtime snapshots, and control directory are proven
gone. Cleanup-proof failures are fatal and sticky across repeated release/close calls, retain the unresolved
terminal/scope record, and are never converted to an ordinary policy denial. After a harness observes an unresolved
cleanup proof, later executions on that harness fail with the same fatal cleanup state instead of silently starting
another session. Scope signaling and an independently retained pidfd for the exact launched supervisor process are both
attempted, so a scope-control failure cannot skip direct owned-process termination. Ordered pre-release cleanup signals
an attested bubblewrap process only through a `pidfd_open` handle
after start-time, cgroup-membership, and executable identity are rechecked around the open; `pidfd_send_signal` therefore
cannot target an unrelated process that reused the numeric PID. A kernel/libc without these pidfd primitives fails
boundary preparation closed.

The host trust boundary is the Unix account. A separate hostile process already running as the same UID can use
`ptrace`, `/proc/<pid>/fd`, or owner-only `chmod` powers to mutate otherwise private snapshots between the last
attestation and the one-byte commit, and Linux provides no general revocation of those same-UID powers. Production must
run the engine under a dedicated, uncompromised service UID. The implementation detects deterministic swaps and byte
mutation at every exposed pre-commit hook and never claims protection from an already-compromised peer process under
that UID.

The child gets dedicated pipes:

- stdin and stdout carry UTF-8 newline-delimited JSON-RPC only;
- stdout frames are strictly decoded and validated before the SDK sees them;
- every inbound response ID must match and consume one pending outbound request ID, so unknown and duplicate responses
  are rejected before SDK dispatch;
- stderr is continuously drained into a separate bounded capture, available through `latestDiagnostics()`; and
- one saturating aggregate produced-byte counter covers stdout plus stderr and kills the cgroup on overflow, while
  individual frame and retained-stderr sizes remain independently bounded.

One process serves one execution. The client runs `initialize`, validates the selected version and configured agent
capabilities, creates a session with an absolute `cwd`, sends one text prompt, streams `session/update` events, and
requires exactly one final prompt stop reason. Additional workspace roots require the agent's
`sessionCapabilities.additionalDirectories` capability.

Startup, individual request, prompt idle, total wall-clock, cancellation grace, transport-drain, and shutdown waits
all have finite deadlines. Cancellation sends `session/cancel` once a session exists. Cleanup closes the protocol and
stdin, then escalates from graceful to forced cgroup termination. Exit status, bounded stderr, aggregate produced-output
count/limit/overflow state, containment provider,
network isolation, cleanup-proof state, and any surviving PIDs are retained separately from protocol stdout. Successful
sandbox evidence is published only after a verified gated launch returns; a failed launch never claims containment.

Initial and final workspace digests are computed with a fixed-size streaming buffer. Traversal, hashing, and diffing
check the execution wall deadline, and initial snapshotting also observes cancellation before any process is launched.
When prompt cancellation has already been accepted, the final snapshot deliberately finishes under the wall deadline
so the cancelled result still accounts for changes. `AgentExecutionLimits` has no staged-workspace byte/file-count
field, so aggregate snapshot size limits and stress coverage remain #71 work; streaming bounds per-file memory, not the
number of tracked paths or total staged bytes.

Event consumers are trusted in-process callbacks and must be non-blocking and return promptly. Prompt-update callbacks
are isolated from lifecycle polling, but post-response message-completion and file-change callbacks run synchronously
to preserve event ordering. The harness cannot safely preempt arbitrary blocking callback code, so lifecycle deadlines
are not a bound on a callback that violates this requirement.

Double forks and `setsid` remain inside the verified cgroup and cannot escape teardown. There is deliberately no
portable fallback: production ACP execution currently requires supported Linux descriptor primitives, user namespaces,
bubblewrap, and a working user systemd manager with authority to create the verified scopes. Remote ACP agents require
a future separately brokered transport; permission answers cannot widen network authority.

## Filesystem broker

The client implements the official [ACP v1 file-system](https://agentclientprotocol.com/protocol/v1/file-system)
`ClientSessionOperations.fsReadTextFile` and `fsWriteTextFile` callbacks. The `fs` capability is computed once when a
session starts from that execution's immutable `AgentAccessPolicy`:

- `readTextFile` is true only if at least one effective path rule grants `READ_FILE`;
- `writeTextFile` is true only if at least one effective path rule grants `WRITE_FILE` or `CREATE_FILE`; and
- the whole `fs` capability is null when neither operation is enabled.

The broker does not treat capability advertisement as authorization. Every callback must use an absolute, already
normalized ACP path. It is mapped to exactly one declared workspace root and then to an `AgentWorkspacePath`; the
workflow's exact or recursive path rules must grant the requested read, or the actual create/replace operation for a
write. Relative paths, dot/dot-dot traversal, paths outside a declared root, ambiguous equal roots, unrelated evidence
or generated paths, and workspace-root links fail closed.

Enabled filesystem sessions require the default filesystem provider on Linux `x86_64`/`amd64` or `aarch64`, a mounted
`/proc/self/fd`, stable Unix device/inode identities, and libc `openat`, `linkat`, `renameat2`, `unlinkat`, `fchmod`,
`fsync`, and `listxattr`. The broker pins each canonical root and every child directory as a descriptor, opens path
components with `O_DIRECTORY | O_NOFOLLOW`, and rechecks each descriptor binding through the declared path. Every opened descendant
must retain the root descriptor's `/proc/self/fdinfo` mount ID, so nested filesystem mounts and directory or file bind
mounts fail closed even when they expose the same device/inode numbers. A final read target is first authorized as an
`O_PATH | O_NOFOLLOW` descriptor and then reopened through `/proc/self/fd/<fd>`; the descriptor used for `read` is
compared to the pinned regular-file and mount identity. Consequently a final-name swap cannot redirect the actual read
or turn it into a blocking FIFO open, even if the original name is restored around that open. Reads also require a
stable single-link file; a contained hard link cannot be used as an alternate name for data outside the root.

Writes first create an unnamed inode with `O_TMPFILE`, force its mode to `0600`, and revalidate its descriptor identity.
Only then does `linkat(AT_EMPTY_PATH)` materialize it under an unpredictable parent-relative transaction name. Thus an
open, `fchmod`, or identity failure cannot strand a named temporary; failures after materialization use the same
descriptor/name-bound cleanup as the transaction. The broker writes and `fsync`s through the descriptor. Creation uses
`renameat2(RENAME_NOREPLACE)`, so an entry appearing at the last syscall gap is never overwritten. Replacement uses an
atomic `RENAME_EXCHANGE`, opens both resulting names, and commits only when the displaced entry is the authorized
identity and the installed entry is the prepared temporary with the expected metadata. A mismatch is exchanged back,
the restored identities are verified, and the temporary is removed. Every fallible step after a create rename or
replacement exchange is inside that rollback boundary, including descriptor opens and metadata inspection. The old
replacement inode is moved to a random quarantine name, revalidated immediately at unlink, and only then removed;
there is no rejection point after that irreversible unlink. Cleanup uses the same quarantine-and-revalidate operation
instead of a check/close/path-unlink sequence. Cancellation is rechecked after the final test/race hook and immediately
before both rename commit syscalls. A descriptor reserve is acquired before any named transaction entry exists; it is
released before rollback or cleanup so even a real post-commit `EMFILE` cannot prevent restoration. Deterministic tests
inject failures after each transaction step and temporary-setup step, force native `openat` failures under a low
`RLIMIT_NOFILE`, and place target, cleanup-name, and cancellation changes at the actual syscall gaps.

Plain POSIX replacements preserve the existing permission and special-mode bits and require unchanged ownership.
Hard-linked files and files carrying any extended attribute fail closed: on Linux this includes POSIX ACL, capability,
SELinux, and user-xattr state that an atomic temp-file replacement would otherwise discard. Creation remains `0600`.
Timestamps are those of the newly written file rather than copied from the old inode. This intentionally narrow
metadata contract avoids claiming preservation for ACLs or arbitrary filesystem/provider metadata.

There is deliberately no Java-NIO or path-based fallback. An enabled session receives a configuration failure on
Windows, macOS, unsupported Linux architectures, custom providers, or hosts without the descriptor/syscall primitives
above. Individual filesystems can also reject `O_TMPFILE`, `linkat(AT_EMPTY_PATH)`, or a rename flag; that operation
then fails without falling back to an unsafe move. This portability boundary is stricter than `SecureDirectoryStream` because Java NIO exposes neither an
identity-bound final read reopen nor atomic no-replace/exchange installation.

Reads require regular UTF-8 files and implement ACP's optional one-based `line` and maximum-line `limit`. Writes reject
malformed Unicode, links, non-regular existing targets, and byte-limit violations. `AcpFilesystemLimits` bounds both
directions independently. Each attempted callback produces an immutable `AcpFilesystemAuditRecord` available from
`latestFilesystemAudit()`: sequence, session ID, ACP method, SHA-256 of the requested path, resolved root-relative
policy path when available, outcome, and stable reason. Absolute host paths and file content are never copied into the
audit records.

The filesystem broker still authorizes each callback independently. The outer process boundary closes the former
direct-syscall gap: workspace paths are private empty anchors rather than host binds, so the agent cannot open or race
the host files outside the broker.

## Terminal broker and staging authority

`ClientCapabilities.terminal` is false unless a verified boundary and an explicit immutable
`AcpTerminalExecutionPolicy` both exist and the request's `AgentAccessPolicy` grants `EXECUTE_COMMAND`. Advertisement
is not authorization. Every `terminal/create` must exactly match one rule's command, ordered argv, absolute normalized
cwd, and complete environment map. Shell expansion, PATH lookup, partial argument matches, extra variables, and
alternate cwd values are rejected. Environment names use portable syntax, credential-like names are forbidden, and a
terminal policy may not contain the raw bytes of any non-empty outer value explicitly marked `SECRET`. This raw-byte
check covers command/argv, environment names and values, cwd, executable/runtime mount paths and manifests, and staging
identifiers/paths. `PUBLIC` values are not treated as secrets based on naming heuristics.

This is deliberately not a general information-flow proof. The broker cannot infer arbitrary encodings, hashes, or
other transforms of a secret, nor can it recognize secret-derived data that a trusted workflow already placed in a
staging root. Policy construction, transformation logic, and staged input provenance therefore remain trusted workflow
responsibilities. The sandbox prevents ambient host/API-secret inheritance and the raw-byte check blocks literal
secret authority, but neither mechanism claims semantic taint tracking.

Command executables and runtime mounts use the authenticated closure rules above. The only writable mounts are
explicit workflow staging roots, and authority is honestly the whole mounted root. A production writable root must be
a fresh mode-0700 directory created by `AcpWorkflowStagingRoot.createQuotaBacked` on an otherwise empty dedicated tmpfs.
Its exact mount identity, finite `size`, finite `nr_inodes`, ownership, mode, byte capacity, and inode capacity are
pinned and reverified at use time. A factory-created ordinary root may be granted read-only, but there is no
main-artifact factory or policy mode that upgrades an ordinary directory to writable terminal authority. This
aggregate quota combines with
cgroup pids/memory/CPU, per-file size, open-file, output-retention, produced-output, wall-time, concurrent-terminal, and
total-create limits. It therefore bounds many-small-file, directory, sparse-file, and background-writer attacks without
claiming that `RLIMIT_FSIZE` is an aggregate disk quota. The workflow owns eventual staging-root deletion.

Terminal IDs carry a session-derived tag and random nonce. Callbacks reject cross-session, unknown, released, and
unbound IDs. A created terminal must appear in `ToolCallContent.Terminal` for exactly one tool-call ID; rebinding,
orphaning, or normal prompt completion with an unreleased terminal is a protocol failure. Output retains a bounded tail
and separately counts all produced bytes. Wait, idempotent kill, and release follow ACP v1 semantics; release invalidates
the ID. Timeout, overflow, cancellation, release, prompt failure, and teardown terminate and prove cleanup of the full
cgroup.

`latestTerminalAudit()` retains only sequence, session, method, hashes of request/terminal/tool IDs, decision reason,
network-isolation state, retained bytes, saturated total-produced bytes, and truncation. It never retains command text,
argv, cwd/host paths, environment values, or output. `latestSandboxEvidence()` binds every security tool's canonical
path hash/content digest/mode/metadata digest, effective outer and terminal resource limits, runtime-closure limits, the exact manifested
agent executable and runtime mounts, actual per-launch cgroup controller values, namespace settings, every staging
identity/mode/quota proof, aggregate outer stdout/stderr production, and canonicalized terminal command authority. A length-delimited canonical SHA-256 binds the
complete metadata record. Evidence is absent for every launch that fails before the write-ahead authorization callback;
after the one-byte commit attempt, delivery is inherently outcome-ambiguous and the launch is treated and evidenced as
authorized rather than misreported as a denial.

## Permission requests

Permission answers are advisory and never mutate filesystem, terminal, network, or sandbox policy. The default
noninteractive decider chooses an actually offered reject-once/reject-always option, otherwise cancels. Narrow allow
rules exactly match tool title, tool kind, option label, and allow kind. An interactive `AcpPermissionDecider` may
suspend for a trusted user, but its selected option ID is checked against the offered set. Invalid or duplicate offers,
decider failure, cancellation, and unavailable choices fail closed. Workflow policy must separately grant
`REQUEST_PERMISSION` before an allow can be returned. `ALLOW_ALWAYS` remains an advisory UI answer and cannot create
authority outside the immutable workflow policy. Permission evidence hashes tool/option IDs and always records
`authorityExpanded = false`. The callback's embedded `ToolCallUpdate` is validated, translated, and charged to the
tool-call limit exactly once before terminal content can bind any terminal authority.

## Upgrade policy

An SDK upgrade is intentional work, not an automated version-range update. A change must:

1. confirm that the SDK still identifies protocol v1 as stable and keeps v2 opt-in;
2. review the official v1 schema and release notes for wire or capability changes, including the opt-in v1
   additional-directory, usage, and message-id fields;
3. update the Gradle coordinate and `ACP_KOTLIN_SDK_VERSION` together;
4. run the scripted subprocess tests plus the full test suite; and
5. keep v2 disabled until a project issue explicitly adopts it after it becomes stable.

The lifecycle wrapper remains necessary even when SDK internals change: executable selection, OS process ownership,
stderr retention, resource deadlines, cancellation polling, and process-tree cleanup belong to the host application.
