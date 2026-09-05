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
The provisioning document is schema version 2. Schema-version-1 documents are rejected rather than silently assigned
agent defaults; migrate them by adding the required `session` object and changing `schemaVersion` to `2`.

The checked template leaves `modelId` and `modeId` explicitly `null` and uses an empty ordered `configOptions` array,
so the agent's advertised defaults remain in effect. Either nullable field may instead be omitted. A selected value
uses only the ACP session APIs, for example:

```json
"session": {
  "modelId": "agent-advertised-model-id",
  "modeId": "agent-advertised-mode-id",
  "configOptions": [
    {"id": "reasoning", "type": "select", "value": "high"},
    {"id": "telemetry", "type": "boolean", "value": false}
  ]
}
```

After `session/new`, the harness snapshots that exact response before queued updates can alter SDK state. It validates
the entire configured set against the advertised models, modes, config-option types, and select values before invoking
any setter. It then applies model, mode, and the option array in that deterministic order with the shared request,
cancellation, wall-clock, and cleanup bounds. An absent capability, unknown ID/value, type mismatch, rejected setter,
or timeout fails after session creation but before `session/prompt` or workspace work. No model, mode, or option is
translated into argv, environment, or provider-specific flags. Diagnostics identify only the preference category and
array index, never configured values or peer error text; do not use these fields to carry credentials. Preference IDs
and select-value IDs are non-empty, bounded, well-formed Unicode strings without control characters. Model and mode
setter responses carry no selected-state field in ACP v1; for config options, the returned typed current value and the
SDK state installed from it must both preserve the complete configured prefix before the next setter or prompt is
allowed.

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

### Required credential-free third-party checkpoints

Pull-request CI pins two meaningfully different external ACP implementations. Goose exposes its own coding-agent ACP
server behind an `acp` subcommand. Zed's `codex-acp` is a separate Rust adapter around OpenAI Codex, starts directly
with no subcommand, advertises explicit authentication methods, and rejects an unauthenticated `session/new` before
creating a model session. Core reconstruction and repair code contains no agent-name conditional; these differences
exist only in the pinned provisioning and compatibility evidence.

| Agent | Pinned Linux x86-64 release | Credential-free required case | Current proven boundary |
|---|---|---|---|
| Block Goose | `1.46.0`, archive SHA-256 `a1cf4856a765d07d6b95689a53c7bca21fcc6e6d65c0dfd064fc704052b85a7b` | [`ci-qualify-goose-acp.sh`](../scripts/ci-qualify-goose-acp.sh) | stable-v1 initialize, advertised capabilities, contained clean shutdown; no session or prompt |
| Zed `codex-acp` | `0.16.0`, archive SHA-256 `0a9ad6c31ec9b2b87dccb7e9da3faf5d387e74470d24dbced75a160ed7b22d06` | [`ci-qualify-codex-acp.sh`](../scripts/ci-qualify-codex-acp.sh) | stable-v1 initialize followed by an attempted `session/new`, typed ACP authentication-required `-32000` with absent error data, then contained clean shutdown; no session or prompt |

Both scripts verify the exact release archive and provision a host-specific read-only ELF dependency closure. The
`codex-acp` archive must contain exactly `codex-acp` and `codex-resources/bwrap`; the executable SHA-256 is
`23a9f2af247fc61aa9a895d5ee91a62a35d05a883bddc2c85d1dc6b2be697087` and the bundled helper SHA-256 is
`5a5104807cfbe9b509d0b9fa1c46054ff48dbed5393f30d261b34263ebf0e3fe`. The authentication-boundary case does not
mount or execute that bundled helper. A future authenticated Codex task must qualify it explicitly if the task needs
the agent's inner sandbox.

The agents receive no inherited environment, credential, outer network, terminal authority, permission grant, model
prompt, or oracle path. Goose receives no workspace. The Codex case receives a fresh empty synthetic workspace with
an empty access policy; complete empty filesystem/terminal/permission audits and unchanged directory metadata are
required afterward. It records successful initialize but lifecycle phase `INITIALIZED`, never `SESSION_CREATED`.
After the verified download, neither required case needs network access. A positive Codex or Goose model session will
require separately brokered provider credentials and network and is therefore not part of pull-request CI.

Each CI attempt uploads the Goose results under `acp-goose-compatibility-evidence` and the Codex results under
`acp-codex-authentication-evidence`. Results contain the strict private provisioning document, target metadata,
artifact digests, and structured production-harness evidence. Receipts bind client/SDK/protocol, negotiated identity
and capabilities, elapsed time, containment/tool hashes, resource limits, output accounting, lifecycle boundary,
complete policy-audit counts, terminal outcome, and cleanup result. A skip is not accepted in either lane.

This is still not the complete compatibility matrix from issue #67. Neither lane proves a successful real-agent
session, prompt streaming, authorized edit, permission handling, cancellation, or reconstruction/repair smoke. Those
credentialed cases remain required before B1/B2 can close. The scripted Python fake agent remains a hostile
wire/containment fixture and is not counted as an independent agent. ACP receives authenticated oracle artifacts
read-only in production workflows; these compatibility checkpoints expose no oracle artifact and give ACP no
authority to generate, validate, score, or certify oracle truth.

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

Config-option setters are also checked against the current typed SDK option inventory immediately
before each request. Removal, duplicate IDs/values or a changed option type fails with a
configuration diagnostic and preference index. Diagnostics preview at most four current option IDs
and four values, redact configured environment values, and truncate each preview to 48 characters
plus a truncation marker. These previews are display text, not selectors. The exact initial session advertisement remains a
separate required authority check: later updates cannot authorize a choice absent from it. Existing
post-response checks still verify the complete applied preference prefix. This does not make peer
inventory changes atomic with an RPC or supply an interactive configuration UI.

## Process and wire boundary

### Admission, queue bounds, and cleanup capacity

Every production `AcpAgentHarness` invocation, including directly constructed harnesses, captured repairs, and
doctor preflights, shares one application-process scheduler. Admission occurs before filesystem snapshots or agent
launch. At most four invocations run at once, with one active invocation per primary workspace path. The scheduler
holds at most 64 waiting invocations overall and eight per workspace. Eligible waiters run in FIFO order; a waiter
whose workspace is already active cannot prevent another workspace from using a free global slot.

Waiting consumes the original execution wall-clock budget and has a separate 30-second maximum. Cancellation and
thread interruption remove a queued invocation without launching a process. Queue overflow, elapsed deadlines,
and unavailable cleanup capacity return typed invocation-bound receipts with scheduler phase/reason metadata.
The scheduler creates no threads or secondary executor queue and does not retry work automatically. Active turns
continue using the existing ACP cancellation, terminal teardown, and process containment boundary.

The admission slot covers the full contained invocation through cleanup and final change capture. A failed process
cleanup proof retains its slot and workspace reservation for the application process lifetime; another harness
instance cannot turn an unresolved process into fresh capacity. Such a workspace is unavailable for further turns,
and no new invocation is admitted when all global slots are retained. Operators must resolve the process/cgroup
failure before restarting the application; this mechanism does not certify cleanup merely because a JVM exits.

Workspace grouping uses the exact normalized primary path already present in the request. Captured repairs use a
shared synthetic primary path and therefore conservatively share one active repair slot across projects. Separate
JVMs have separate schedulers. This checkpoint does not provide application-wide project identity,
cancellation of validation subprocesses, or persistent restart scheduling; those remain part of
issue #71. Captured repair also defensively copies its caller-supplied source map before admission; admission does
not yet reserve that input memory. Per-invocation output, terminal, memory, and workspace limits still apply independently.

The web server's owned background executor separately bounds exploration and reconstruction to two active
operations and 32 pending operations per server instance. Its FIFO queue rejects overflow immediately with HTTP
503 and `Retry-After: 1`; it never executes rejected work on the HTTP handler. A job may have only one pending or
active operation. Rejected jobs retain a failed status explaining that admission can be retried. Shutdown interrupts
active workers and marks discarded pending jobs failed with an explicit never-started message. This is background
job admission, not a bound on network connections, uploaded job storage, or cross-process resources. Injected
executors remain caller-owned. Interrupting active workers is not proof of validation subprocess cleanup.

The web CLI registers a JVM shutdown hook before starting its listener. Normal JVM shutdown (including
SIGTERM) calls the same stop path: close the listener, interrupt owned workers, and persist discarded jobs.
After attempting every discarded-job update, stop waits up to five seconds for owned workers to terminate.
A timeout or cleanup error is reported with a fixed diagnostic; it never establishes subprocess cleanup.
Shutdown and successful job-status publication share a lock: once shutdown begins, a worker that catches
interruption and returns normally is recorded as failed with an explicit shutdown diagnostic. Previously
published completion remains intact. This controls the web status only, not artifact acceptance or rollback.
Injected executors are not shut down. The server tracks and discards its pending operations independently
of executor ownership, so late or repeated callback delivery cannot start cancelled work or change a new
owner's job status. Already-claimed work still requires its caller's cancellation/cleanup cooperation.
SIGKILL, power loss, stalled filesystem writes, and
durable recovery of indeterminate external work require the separate #68/#71 recovery mechanisms.

Before startup recovery, a web server acquires a nonblocking exclusive `.web-owner.lock` for its job store.
A second cooperating server fails before changing job status. Same-JVM owners are tracked by canonical store
path to avoid opening another channel to an owned lock file (see the [JDK FileLock platform notes](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/channels/FileLock.html)).
The lock file is never deleted. Stop releases ownership only after owned workers have terminated and no
scheduled operations or admitted HTTP handlers remain. Request admission closes when shutdown begins; the
lifetime includes upload publication and error handling. A handler that outlives stop causes an explicit
incomplete-stop error and retains ownership. Its `finally` path releases ownership when all work is idle,
including after an exception. Other incomplete in-process shutdowns retain ownership until a later successful stop
or JVM exit. The in-process timeout regression holds a worker beyond the grace period, verifies a new server
is still refused, then releases the worker and retries stop before verifying a fresh server can start.
Executor cancellation is requested once; later stop attempts wait for termination without interrupting
workers again while they persist final status.
This is cooperative local-filesystem web ownership, not fencing of arbitrary JobStore callers,
older servers, external subprocesses, lock-file replacement, or network filesystems.
`WebRequestLifetimeTest` holds the production request-admission wrapper across a final store write and an
exception, verifies competing ownership is refused and late requests are not admitted, then verifies handoff.
This is deterministic handler-lifetime evidence, supplemented by the existing HTTP route tests; it does not
qualify stalled kernel I/O or abrupt host failure.
`WebShutdownTest` covers propagated interruption, a worker returning after swallowing interruption, and
a worker that remains blocked past the grace period. The last case verifies the fixed cleanup diagnostic,
then starts a new server and checks that unfinished jobs become interrupted failures without rerunning.
This is benign JVM-worker evidence; it does not cover orphaned external processes or power loss.
The abrupt-death case forcibly terminates the child JVM after two active jobs and one queued job are
persisted. It verifies no worker completion markers appear, then starts a replacement server and checks
that all three jobs become interrupted failures without replay. This exercises OS lock release on process
death and recovery from complete persisted records; it is not interruption during a filesystem write.

Job metadata updates write and force a temporary file in the job directory, atomically replace `job.json`,
then force the directory. There is no non-atomic fallback. An existing reader retains its previous complete
snapshot. Before publication, the writer enforces the same 256 KiB encoded UTF-8 JSON limit as the reader,
including escaping overhead; oversized records fail without replacing an existing record or publishing an upload.
The bounded canonical encoder stops at that output limit, and a filename character cap bounds its preliminary
string-byte accounting. It no longer builds the entire encoded JSON string before checking the limit. New records
use canonical field ordering; existing pretty-printed records remain readable without migration.
A failure before replacement leaves the published record intact. Temporary files are removed on
ordinary failure. A failure after replacement, including directory-force failure, may have published the new
record and is not proof of rollback. Tests cover held readers and interruption before publication.
`JobMetadataPublicationTest` injects exceptions before writing, after a partial write, before/after file force,
before/after replacement, and before/after directory force. A fresh store reads the exact prior record for
pre-replacement failures and a complete new record for post-replacement failures; the input remains intact
and ordinary cleanup removes the temporary file. These exception cases run cleanup and therefore do not
substitute for process death during I/O, abandoned-file reclamation, or power-loss qualification.
`JobMetadataCrashTest` separately halts a benign child JVM at the same eight application I/O boundaries,
including after writing half a private record. It verifies terminal process state and absence of `finally`
cleanup before opening a fresh store. The old or new published record remains complete and the input is
unchanged. Pre-replacement temporary files remain private and are not promoted by interrupted-job recovery.
These files are deliberately retained pending qualified reclamation. The test covers process death at controlled
publication boundaries, not interruption inside a kernel syscall, whole-upload crash publication, or power loss.

Uploads stage their input and metadata together in a private `.upload-` directory beneath the job store.
Before parsing or staging, JobStore rejects input above its 32 MiB read limit and takes an owned byte-array
copy. Metadata, declared size and persisted input all derive from that copy, so later caller mutation cannot
change what is published. This bounds the retained input per upload, not aggregate request memory or storage.
Before staging, the store creates missing directories, resolves the canonical store path, then opens and
forces that directory and each canonical ancestor through the filesystem root, in leaf-to-root order.
Every upload repeats confirmation, including when all directories already exist: a prior failed attempt
may have created them without completing confirmation. Failure to open or force an ancestor stops the
upload before private staging or final publication; existing jobs and newly created empty directories
are retained. There is no fallback that silently accepts unsupported directory-force operations.
The original configured path remains the metadata identity. Provisioning/durability of symlink aliases,
concurrent path replacement and noncooperating filesystem writers remain outside this confirmation
contract. Directory force calls on the tested local filesystem are not a power-loss qualification.
`JobStoreDirectoriesCrashTest` halts a benign child JVM before the first directory force, after the
store force, after its parent force, and after all ancestor forces. The parent observes the exact halt
marker and terminal exit, verifies that ordinary cleanup did not run and that the newly created store
contains no upload or private stage, then starts another JVM. That process must reconfirm the full
existing canonical chain and publish one complete input/metadata record. These are application-boundary
process-death tests; they do not interrupt directory creation or force inside a kernel syscall.
The input and metadata are forced before the directory is atomically renamed to its final job ID; the store
directory is then forced. Metadata records the final input path. Ordinary failures before publication clean
up the staging directory; failures after rename may leave a complete published job even when the caller
receives an error. Startup does not treat staging directory names as job IDs. Tests verify interrupted input
writes leave no partial job and preserve prior jobs. Power-loss injection, abandoned staging/temporary-file
reclamation, and the full supported-filesystem/ancestor-durability qualification remain open requirements.

`GET /api/recovery` exposes a read-only schema-v1 recovery inventory for #242. It reports retained
upload-stage and metadata-temporary counts, scanned entries, observed bytes as a decimal string,
uninspected entries and `inventoryComplete`, with `displayOnly: true`. It returns no paths, filenames,
file contents or I/O exception details. Inspection charges every encountered directory entry against
a 4,096-entry budget, counts at most 128 candidates and accumulates at most 64 MiB of regular-file
lengths. It reads attributes rather than file contents, scans one level inside private stages and job
directories, and does not descend into job reports. Descriptor-relative inspection does not follow child
symlinks. Unknown candidate layouts, inspection errors, unavailable secure directory streams or exceeded
budgets make the inventory incomplete; observed counts and bytes then give lower bounds. An oversized
file is omitted from the byte sum rather than clamped. `uninspectedEntries` counts encountered inspection
failures/unsupported entries, not the unknown number remaining after budget exhaustion.

This is an observation, not an atomic filesystem snapshot or a wall-time bound on filesystem I/O.
The configured root follows the existing store path contract; this does not fence raw filesystem writers.
A complete inventory says only that the scoped scan finished, not that candidates are abandoned or safe
to delete. No files are reclaimed or promoted. Safe reclamation and aggregate storage quotas remain
#242/#71 requirements; #69 may display this summary without interpreting it as completed cleanup.
The web workbench now renders this summary when candidates are retained or inspection is incomplete,
including incomplete scans with zero counted candidates. Incomplete results use an explicit lower-bound
label and explain that additional files or bytes may remain. Complete results still state that retained
files may belong to active work. The panel links to the JSON summary, omits private names and contents,
and reports that no files were deleted. A complete empty scan omits the panel. Refresh performs a new
bounded scan; the job list and recovery inventory are separate observations, not an atomic snapshot.
The metadata and upload abrupt-exit tests also compare the inventory against the actual retained files
after each child JVM terminates. They assert exact candidate counts and byte totals, then verify that
interrupted-job recovery leaves the inventory and private file contents unchanged. A metadata temporary
inside an upload stage contributes to that stage's byte total; the separate metadata-file counter covers
temporaries within published job directories. These checks establish diagnostic coverage for those
controlled crash layouts, without establishing abandonment or permission to reclaim them.

`JobUploadCrashTest` halts a benign child JVM at fourteen controlled input/metadata write, force and
directory-publication boundaries. Before final rename the candidate remains a private stage; afterward a
fresh store sees a complete input and matching metadata. Existing jobs remain unchanged and recovery does
not promote private stages. This covers application-boundary process death, not power loss, interruption
inside kernel I/O, safe stage reclamation or uncertain-response retry deduplication.

Once the final upload-directory rename is attempted, a failure is reported as
`UploadPublicationUncertainException` with the generated job ID. This includes an exception from rename
itself; it does not assume that an exception proves the destination is absent. The web endpoint returns
HTTP 409 with a `Location` for inspecting that job. JSON clients receive `upload_publication_uncertain`,
`job_id`, `job_url`, and `retry_upload: false`; the HTML response offers a Check job link. Underlying I/O
error text is excluded. Inspect the referenced state before another upload; this is not an exactly-once
retry protocol, and a missing record after a crash still needs recovery reconciliation.
`UploadUncertaintyHttpTest` exercises the shared production upload handler over local HTTP with a
directory-confirmation fault. JSON and HTML both return 409 with the same review location as the complete
published job, no private I/O diagnostic and no `Retry-After` header. The fixture verifies each submitted
request creates one job; it does not qualify uncertain-response retry deduplication.

`web --listen-backlog` requests a TCP listen backlog of 64 by default and accepts values from 1 to 4096.
Invalid values fail before the server binds or opens job storage. The underlying TCP implementation controls
overflow refusal or dropping, as described by the [JDK HttpServer contract](https://docs.oracle.com/en/java/javase/21/docs/api/jdk.httpserver/com/sun/net/httpserver/HttpServer.html).
This setting covers connections waiting to be accepted; it does not cap already accepted connections,
idle keep-alive connections, request duration, or stored uploads. Those bounds remain required under #71.

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
so the cancelled result still accounts for changes. Each snapshot now enforces fixed implementation caps of 8,192
visited entries, 4,096 unique regular files, 8 MiB per file and 64 MiB total hashed bytes. Oversized snapshots fail with
RESOURCE_EXHAUSTED and a bounded phase/limit diagnostic; no partial change set is returned. These observation limits
do not establish aggregate staged-storage/inode quotas, descriptor-bound inventory completeness or concurrent-workflow
resource accounting. Those broader #63/#71 requirements and stress qualification remain open.

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
identity/mode/quota proof, aggregate outer stdout/stderr production, and canonicalized terminal command authority.
Each successful launch additionally binds the canonical environment content, working directory, stdin disposition,
stderr-merge choice, staging-root and private-empty-anchor digests/counts, and both the configured source manifest and
effective mounted closure manifest for every executable/runtime mount. A length-delimited canonical SHA-256 binds the
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

### Reproducing the web job recovery matrix

Run `python3 scripts/verify-web-job-recovery.py` from a provisioned checkout with cached Gradle
dependencies. This offline command selects eleven benign storage/web test classes covering upload and
metadata publication, directory preparation, controlled JVM exits, ownership/shutdown, retained-file
inventory and HTTP presentation. It does not select the patch reproduction lane or certify full B-series
release readiness. Keep unrelated Gradle invocations separate while it runs.

Each invocation creates a unique directory under `build/web-job-recovery-verification/` with workspace
temporary files, isolated fresh JUnit/HTML reports, Gradle output and a JSON manifest. The manifest records
the source commit, dirty-worktree flag and tracked-diff digest, exact command, required suites, runtime
and test-filesystem details, totals and report digests. For reproducible source identity, run a clean
committed checkout; the diff digest does not capture untracked source contents. JVM option environment
variables are removed for this scoped run and temporary storage is directed into its evidence directory.
The runner disables test output reuse and fails on a nonzero build exit, missing/unexpected/duplicate
suites, empty or malformed reports, failures, errors or skips. An interrupted run without a terminal
manifest is incomplete evidence. Its own lock prevents concurrent invocations of this runner.

### ACP SDK upgrades

The bounded `acp/v1/wire-contract.json` corpus currently freezes 49 SDK-decoded and re-encoded
JSON-RPC messages. It includes the production model/mode setters, select and boolean configuration
setters, flat and grouped session inventories, terminal token usage, session-info and configuration/mode/command/usage updates, and the original
prompt/filesystem/terminal/permission lifecycle. `AcpV1WireContractGoldenTest` rejects missing or
unvalidated entries and pins both Maven and SDK-reported versions. A golden update documents wire
compatibility only; it does not implement advertised authentication, resume, or operator behavior.

An SDK upgrade is intentional work, not an automated version-range update. A change must:

1. confirm that the SDK still identifies protocol v1 as stable and keeps v2 opt-in;
2. review the official v1 schema and release notes for wire or capability changes, including the opt-in v1
   additional-directory, usage, and message-id fields;
3. update the Gradle coordinate and `ACP_KOTLIN_SDK_VERSION` together;
4. review and run the versioned golden corpus, operator preference exchanges, scripted subprocess
   tests and full test suite; and
5. keep v2 disabled until a project issue explicitly adopts it after it becomes stable.

The lifecycle wrapper remains necessary even when SDK internals change: executable selection, OS process ownership,
stderr retention, resource deadlines, cancellation polling, and process-tree cleanup belong to the host application.

### Operator authentication inventory

Preflight returns an invocation-local `authentication` inventory containing at most 32 advertised
methods. IDs are exact and bounded to 256 UTF-8 bytes; duplicate or blank IDs fail admission.
Names/descriptions are bounded before redacted previews are retained. Unknown variants remain
explicitly `unknown`, and every method currently reports `loginSupported=false`: this inventory
is not an authentication action or grant. The printable doctor descriptor includes only the count
and normalized inventory digest. Default object string representations omit method IDs and previews.

The digest commits to ordered IDs, variant categories, names and descriptions. It excludes extension
metadata and variant-specific credential/terminal payloads, so it cannot authorize a login request or
serve as a full auth-policy commitment. Exact IDs are available only to explicit operator API consumers;
those consumers must not print them without redaction. This result stays outside invocation acceptance
receipts and session/project archives. Login/logout, interactive surfaces and credential-state handling
remain tracked by #265/#70, with fresh advertised-method validation required before any future dispatch.

Use `llm_bin_patch doctor --auth-methods` to inspect advertised method previews explicitly.
The normal doctor report retains only inventory count/digest. Inspection prints quoted, redacted
ID/name/description previews, variant category and the current unsupported-login status; previews
may be truncated and are not exact selection tokens. This option cannot be combined with
`--tools-only`; selecting the legacy harness fails without a legacy connectivity probe. No login,
logout, session or model prompt is initiated. CLI output does not imply authentication readiness.

Invalid authentication advertisements produce `PROTOCOL` with the bounded
`invalidAuthenticationInventory` reason during preflight. A dedicated inventory-validation failure
keeps malformed peer data distinct from unrelated configuration/redaction errors. Contained scripted
preflight cases cover duplicate IDs, method-count overflow, blank IDs and oversized names, with
verified cleanup and no complete execution evidence or authentication action.

The web dashboard also has an explicit **Inspect authentication methods** button. It starts one
asynchronous inspection per server via `POST /api/operator/auth-methods` with the operator-action
header; `GET` on the same path reads idle/inspecting/ready/failed status without launching work.
Responses contain redacted previews and `loginSupported=false`, never raw method IDs. A concurrent
start returns 409. The admitted background task participates in the existing handler lifetime so
server shutdown does not release store ownership while it is still running. Its production harness
is retained across inspections, preserving unresolved-cleanup refusal. Configuration is selected on
first use; restart the server to change that selection. No credentials or inspection status are
persisted in project records. This does not provide login/logout, durable operator state, or automatic
cancellation when a browser disconnects; production preflight keeps its existing deadline/cleanup bounds.

Optional Chromium check (with the Playwright dependency described for progress verification):

```sh
java -cp 'build/libs/*:build/oracle/gcc/kotlin-boot-runtime/*' \
  scripts/fixtures/AuthenticationDashboardFixture.java build/auth-dashboard.html
DECOMP_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright \
  node scripts/verify-authentication-browser.cjs build/auth-dashboard.html build/auth-browser/new-run
```

The fixture renders the production dashboard and mocks status responses. It checks explicit-only
inspection, preview rendering/escaping, failure, retry and empty inventory; trace/screenshot/result
files use a fresh evidence directory. It does not establish independent-agent authentication.

**Cancel inspection** posts an explicit cancellation request to
`/api/operator/auth-methods/cancel`. A request acknowledgement is not a terminal cleanup result:
the view continues polling until inspection finishes, and late acknowledgements cannot overwrite
a terminal result or a later inspection. The server's cancellation token reaches the preflight
scheduler, launch and initialize waits. Shutdown requests cancellation as well, while admitted-task
ownership remains held until completion. The preflight overload preserves a cancelled invocation's
receipt in `AcpPreflightCancelledException`; cleanup failures retain their original failed outcome.
Only that terminal cancellation is rendered as `cancelled`. Login/logout cancellation and durable
operator authentication state are still separate unsupported work.
