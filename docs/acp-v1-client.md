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
   This is a non-provider agent binding, not a provider credential channel; follow the
   [provider credential ownership boundary](#provider-credentials-and-current-availability) below.
   Host-native execution can export that one name. Compose requires the same explicit one-name opt-in rather than an
   ambient environment file:

   ```bash
   export ACP_AGENT_SECRET
   docker compose --profile acp-host run --rm --no-deps \
     -e ACP_AGENT_SECRET llm-bin-patch doctor --workflow all --output /output
   ```

### Provider credentials and current availability

The production outer-agent namespace currently has no network access. Its
credential-free checkpoints cover the boundaries in the table below. Positive
provider-backed sessions require the separately qualified transport owned by
[#238](https://github.com/minsago-elite/decomp_thing/issues/238), which remains
unavailable in this deployment contract.

That transport requires an operator-owned broker/relay to keep provider
credentials outside the agent, analyzed program, candidate build and terminal
children. The agent receives an admitted invocation/session-bound model channel;
its channel identity, destination policy, bounds, cancellation and revocation
must be qualified together. Authentication and session lifecycle remain with
[#70](https://github.com/minsago-elite/decomp_thing/issues/70).

The explicit `provenance: "secret"` environment binding above forwards the named
value to the agent during initialize. It therefore cannot carry a provider
credential for the brokered transport contract. The strict schema-v2
[provisioning parser](../src/main/kotlin/decompengine/acp/AcpHarnessProvisioning.kt)
accepts `schemaVersion`, `implementationId`, `agent`, `session` and `sandbox` at
the root; there is no provider-policy or broker-channel setting in this document.
Changing an environment value, a permission answer or the Compose network cannot
qualify the missing transport. Provider reachability, an advertised auth method
and a successful initialize each retain their own limited evidence scope.

### Running the provisioned preflight

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

### Pinned required cases and unsupported capability policy

The release versions and archive commitments above identify the two implementations for this matrix. The
classification below is the required-case definition, not evidence that a positive agent workflow succeeded.
`Required` applies to both pins. Missing authentication, provider access or a required capability leaves a case
unqualified; it does not turn that case into an unsupported exemption or a successful skip.

| Case | Goose `1.46.0`: requirement and retained checkpoint coverage | `codex-acp` `0.16.0`: requirement and retained checkpoint coverage |
|---|---|---|
| Initialize | Required; stable ACP v1 initialize is covered by the credential-free checkpoint. | Required; stable ACP v1 initialize is covered by the credential-free checkpoint. |
| Advertised capabilities | Required; the checkpoint records negotiation. Capabilities needed by each positive workflow still need qualification. | Required; the authentication-boundary verifier checks the pinned advertisement. Positive workflow capability use still needs qualification. |
| Session creation | Required; a successful session is unqualified and is not attempted by the initialize-only checkpoint. | Required; a successful session is unqualified. The retained `session/new` authentication-required rejection is a negative boundary, not session creation. |
| Prompt streaming | Required; unqualified. No model prompt is sent by the credential-free checkpoint. | Required; unqualified. No model prompt is sent by the authentication-boundary checkpoint. |
| Authorized file edits | Required; unqualified. The initialize-only checkpoint exposes no workspace. | Required; unqualified. An unchanged empty workspace and empty audit do not prove an authorized edit. |
| Permission handling | Required; unqualified. A positive task must exercise the standard permission policy. | Required; unqualified. No permission request or grant occurs in the authentication-boundary checkpoint. |
| Cancellation | Required; unqualified for an active real-agent turn. Initialize-only shutdown is not turn cancellation. | Required; unqualified for an active real-agent turn. Authentication-required shutdown is not turn cancellation. |
| Clean shutdown | Required; the credential-free initialize boundary is covered. Shutdown after a positive session/workflow remains unqualified. | Required; the credential-free authentication boundary is covered. Shutdown after a positive session/workflow remains unqualified. |
| Reconstruction | Required; unqualified. Use the standard factory/workflow and production validators. | Required; unqualified. Use the standard factory/workflow and production validators. |
| Repair | Required; unqualified. Use the standard factory/workflow and production validators. | Required; unqualified. Use the standard factory/workflow and production validators. |

No agent-specific unsupported waiver is defined for those ten required cases. A required case that cannot run must
retain its unsupported, authentication-required or failure outcome and continue to block complete qualification.
The credential-free Codex rejection must not be counted as a positive required session, edit, reconstruction or
repair result. Positive runs require a separately qualified provider/authentication environment; this table
adds no permission, credential, network route or execution authority.

Optional capability advertisement is a separate classification:

| Optional advertised feature | Goose `1.46.0` | `codex-acp` `0.16.0` |
|---|---|---|
| Audio prompts | No support classification is locked by the initialize-only verifier; inspect the qualified negotiation before use. | Unsupported by the pinned advertisement: the verifier requires `promptAudio=false`. |
| MCP over SSE | No support classification is locked by the initialize-only verifier; inspect the qualified negotiation before use. | Unsupported by the pinned advertisement: the verifier requires `mcpSse=false`. |
| Additional session directories | No support classification is locked by the initialize-only verifier; inspect the qualified negotiation before use. | Unsupported by the pinned advertisement: the verifier requires `sessionAdditionalDirectories=false`. |

These optional exclusions do not waive a required case. The
[Codex boundary verifier](../scripts/support/AcpCompatibilityAuthenticationProbe.java) checks those exact false
flags; the [Goose initialize verifier](../scripts/support/AcpCompatibilityPreflight.java) records negotiation
without locking those optional values. An untested optional feature is not inferred unsupported or usable.
Production reconstruction and repair continue to use protocol/capability handling, with no agent-name branch
added for this matrix. Keep the pins, required-case definition and actual qualified outcomes distinct when
reviewing an agent, SDK, runtime or provider-policy change; the complete current matrix must be qualified again.

### Machine-readable required-case and result bindings

[`contracts/acp/v1/required-cases.json`](../contracts/acp/v1/required-cases.json) records the same two pins and ten
required cases per agent. It binds the client version, SDK artifact/reported version and stable protocol. The
ordinary CI metadata check compares these declarations with the existing Gradle dependency, wire corpus and
hash-locked agent scripts. It runs only authored data controls; it does not launch an agent or supply a real matrix.

The [metadata verifier](../contracts/acp/v1/verify.py) has four modes:

```bash
python3 -B contracts/acp/v1/verify.py definition
# RELEASE_COMMIT is the exact 40-character source commit being qualified.
mkdir -p ./build/acp-release-bindings
python3 -B contracts/acp/v1/verify.py template --release-commit "$RELEASE_COMMIT" \
  > ./build/acp-release-bindings/results.json
python3 -B contracts/acp/v1/verify.py inspect \
  --release-commit "$RELEASE_COMMIT" --definition-sha256 "$DEFINITION_SHA256" \
  --manifest ./build/acp-release-bindings/results.json
python3 -B contracts/acp/v1/verify.py verify \
  --release-commit "$RELEASE_COMMIT" --definition-sha256 "$DEFINITION_SHA256" \
  --manifest ./build/acp-release-bindings/results.json
```

The release consumer must obtain `RELEASE_COMMIT` and `DEFINITION_SHA256` from its trusted release inputs. The
digest commits to the exact definition bytes from that release, including whitespace. A branch name, abbreviated
commit or zero placeholder is refused. Historical consumers may pass the retained definition with `--definition`;
changing a definition is a new qualification input, not a migration of old results into current evidence.

`template` writes all twenty cases as `UNQUALIFIED`, with null runtime/provider policy and no artifacts. These
unknowns must remain explicit until evidence exists. `inspect` validates the metadata and lists blocking cases;
its successful exit means the declarations are well formed. `verify` also requires every required case to have a
positive binding and exits unsuccessfully for missing, failing, skipped, unsupported, authentication-required or
observation-only results. A retained failure may have null runtime/provider policy; the context digest binds those
unknowns and the report lists incomplete contexts. A positive binding requires both exact contexts. Neither mode
requests a run, fetches an artifact, reads its payload or grants execution,
credential or network authority. Both inspection reports always say `releaseQualified=false` and
`artifactPayloadsIndependentlyVerified=false`, even for a structurally complete authored manifest.

The version-one result document has the following closed fields:

| Object | Required fields and meaning |
|---|---|
| Root | `schemaVersion=1`, `scope=acp-required-case-result-bindings`, exact `releaseCommit`, `definitionSha256`, identical `client`/`sdk`/`protocolVersion`, both `agents`, and `artifacts`. |
| Agent | Exact definition `pin`, `runtime`, `providerPolicy`, and exactly one result for each required case. |
| Runtime | `implementation`, exact `version`, `os`, `architecture`, and `containmentPolicy` with `id`, `version`, and `sha256`. |
| Provider policy | `id`, exact `version`, `sha256`, and `mode` (`credential-free`, `brokered`, or `unavailable`). A positive required-case result requires the brokered policy. |
| Case result | `caseId`, `outcome`, and an `artifact` identifier; only `UNQUALIFIED` uses a null reference. Negative outcomes remain negative. |
| Artifact | Unique `id`, exact `agentId`, covered `cases`, `scope`, matching `sourceCommit` and `contextSha256`, plus `repository`, `runId`, `runAttempt`, immutable `artifactId`, `bytes`, and full-object `sha256`. |

`contextSha256` is SHA-256 of the ASCII JSON produced with sorted keys, compact separators and ASCII escaping for
this object: `{releaseCommit, definitionSha256, client, sdk, protocolVersion, agent, runtime, providerPolicy}`.
Here `agent` is the exact pin object. The verifier's `context_digest` implements that encoding. Each artifact must
match its agent's full version context and source commit. References across agents/cases, unused artifacts,
conflicting declarations of the same repository/artifact identity, unknown fields and duplicate JSON keys are
refused. Repository identity comparisons ignore ASCII casing. Inputs are bounded to one MiB; metadata and exception
details are not echoed on refusal.

Artifact scopes are `positive-required-case`, `negative-required-case`, `credential-free-initialize`, and
`credential-free-authentication-boundary`. A `PASS` binding requires the positive scope. A non-null provider policy
on a credential-free artifact must itself have mode `credential-free`; brokered or unavailable labels are refused.
Credential-free artifacts
can retain only initialization, advertisement and their own shutdown boundary; the authentication-boundary scope
also permits the attempted session-creation case. They cannot bind edits, prompts, permission grants, cancellation,
reconstruction or repair. `OBSERVED` and `AUTH_REQUIRED` preserve these narrower outcomes and block completeness;
credential-free shutdown does not substitute for shutdown after a positive workflow.

These are declarations and integrity references, not independent attestations of payload contents. The release
consumer must independently authenticate the producer and exact checkout, retain and hash the actual immutable
objects, verify their case/outcome and runtime/provider-policy evidence, and enforce all remaining oracle,
validation, event, lineage and cleanup gates. A hash supplied beside an unverified `PASS` cannot establish any of
those facts. No completed release result manifest is supplied by this definition or its authored controls. The
existing positive-agent/provider and full release requirements remain open; updating metadata alone never proves
the required rerun after a version or policy change.

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

Waiting consumes the original execution wall-clock budget and has a separate 30-second maximum.
Caller-provided cancellation/deadline observers run outside the shared scheduler lock. Initial lock
acquisition uses bounded polling slices, and elapsed observer/lock time is checked against the queue
deadline before admission, even if capacity is available. Observer callbacks must still return promptly:
the scheduler cannot preempt arbitrary caller code, and a blocked eligible FIFO head can delay later
waiters. A blocked workspace observer does not hold the mutex needed for other eligible work, state
inspection or permit release. Cancellation and
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

### Job-store ownership and initialization

The supported web-store path uses the default filesystem provider on Linux. The
native descriptor adapter admits `amd64`, `x86_64` and `aarch64` and requires its
Linux descriptor/rename operations to be available. Store and ancestor directories,
stable lock files and reserved upload names are application-controlled. The local
filesystem must support exclusive JVM file locks, directory force and the required
atomic moves. Locking or publication failure is a refusal; there is no non-atomic
fallback. Network filesystems, concurrent namespace replacement and arbitrary
noncooperating writers are outside this contract. These prerequisites describe
admission, not qualification of every filesystem or power-loss durability.

| Writer or operation | Required participation |
| --- | --- |
| `UploadServer` and its `WebJobService` uploads, lifecycle changes and maintenance | Hold the web root owner through initialization, admitted requests and owned work. The service acquires the workflow root owner before recovery or publication and retains it until quiescence. |
| `WorkflowAttemptStore` state, acceptance and pin mutations | Hold its exclusive root lease and lifetime transactions. A closed store cannot authorize another write. An independently opened store conflicts with an active service owner. |
| Low-level `JobStore.createFromUpload`, `updateStatus`, `recoverInterruptedJobs`, and report-directory creation | The caller must already own the root, directly through `WorkflowAttemptStore` or through the service's tracked lifetime. Per-instance `@Synchronized` methods do not establish cross-instance or cross-process ownership. Bypassing that participation is unsupported. |
| Workflow/report callbacks and their progress writers | Finish writes inside their owned operation lifetime. An untracked background writer or subprocess cannot inherit a right to mutate storage after the callback returns. External process recovery remains separately unqualified. |
| `UploadStagingRecovery` | Run before request/work admission under root ownership. Reclaim only the private versioned stage namespace after complete inspection; retain unknown data and published jobs. Reads never invoke this cleanup. |

A web server acquires a nonblocking exclusive `.web-owner.lock` before binding its
listener. The workflow store also retains `.workflow-owner.lock`; the two files
serve distinct ownership layers. Same-JVM web owners use the canonical existing
store path to reject contenders before opening another lock channel (see the
[JDK FileLock platform notes](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/channels/FileLock.html)).
A missing root initially has in-process web exclusion only; creating it upgrades
to the cross-JVM lock before application work. Neither lock file is deleted or
replaced as a stale-lock cleanup operation. A pathname, PID or leftover lock file
alone never proves that another writer is absent. Provisioning/durability of
symlink aliases and hostile path replacement remain outside the directory
confirmation contract; canonical lock identity does not establish namespace fencing.

Under its acquired workflow lease, shared-service initialization confirms the
store and every canonical ancestor before upload-stage cleanup or workflow
recovery. This covers the streamed publisher as well as the legacy upload path.
Failure retains prior job/input bytes and any newly created empty directories,
releases the failed admission's lease, and reports fixed
`STORE_DURABILITY_UNAVAILABLE` without provider exceptions or paths. A later
explicit attempt reconfirms the full chain. The streamed-upload tests require
ownership before confirmation, no stage/body consumption on refusal, complete
ancestor confirmation on retry and byte-identical prior evidence. Their bounded
fixture receipt records the runtime, filesystem provider and observed filesystem
types; source edits alone do not qualify a host or filesystem.

Current server initialization then reconciles private upload stages and calls
`WorkflowAttemptStore.recoverAll`. Malformed individual legacy/workflow records
remain unavailable for inspection; they do not authorize guessed repairs or
analysis replay. Unknown/unsafe upload staging and store-wide recovery refusals
fail initialization. Legacy active statuses are projected as interrupted using
workflow recovery state while the original `job.json` remains unchanged.

The separate low-level `JobStore.recoverInterruptedJobs` legacy API retains its
4,096-entry, 64 MiB aggregate metadata and 256 KiB per-record bounds. It completes
inspection and encodes proposed replacements before changing statuses. Invalid
records, exhausted bounds or unencodable replacement data refuse the scan without
status writes; a later publication failure may leave already reconciled records.
Those legacy scan semantics are not the current server startup path and do not
supply a deadline for stalled native I/O or fencing of direct concurrent writers.

Failed binding releases the acquired web owner. Failed storage initialization
closes admission before starting the unconfigured JDK dispatcher only to release
its bound listener; no application context is installed yet. Independent cleanup
steps preserve the original failure and retain distinct secondary failures. Outer
ownership is retained if service close cannot confirm completion. Failed `start`
unwinds its lifecycle lock before dispatcher cleanup; queued requests cannot
force cleanup to wait on that same lock. Duplicate start refusal leaves a running
server intact. Stop-before-start and interrupted start preserve original metadata
and refuse later admissions.

Stop releases ownership only after owned workers, scheduled operations and admitted
HTTP handlers finish. Upload publication and error handling remain inside the
handler lifetime. A timed-out handler causes an explicit incomplete-stop result
and retains ownership until its final exit; other incomplete cleanup requires a
successful retry or JVM exit. Cancellation is requested once. A late old-owner
cleanup retry must leave a replacement owner's lease and bytes intact, and old
requests remain refused after handoff.

`WebRecoveryAdmissionTest` covers queued requests, duplicate start, stop-before-start,
initialization refusal, interrupted start, stop/admission races and listener bind
failure. Its seven scenarios must be actual discovered JUnit methods; four formerly
nested local functions supplied no executed coverage. `WebRequestLifetimeTest`
retains a final admitted-handler write and exception across a failed stop, then
checks replacement ownership, refused old writes and late cleanup retry.
`WebShutdownTest` covers competing benign JVMs, propagated/swallowed interruption,
the grace-period timeout and abrupt JVM death. These controls do not establish
orphaned external-process cleanup, stalled-kernel-I/O deadlines, power loss, ACP
session recovery or release qualification. Complete current Actions results and
supported configuration evidence remain required.

Job metadata updates write and force a temporary file in the job directory, atomically replace `job.json`,
then force the directory. There is no non-atomic fallback. An existing reader retains its previous complete
snapshot. Before publication, the writer enforces the same 256 KiB encoded UTF-8 JSON limit as the reader,
including escaping overhead; oversized records fail without replacing an existing record or publishing an upload.
Upload admission also encodes a reservation record before staging: the longest supported status, a
40-character timestamp allowance, and a 500-character status message at worst-case JSON escaping size.
Thus an accepted filename leaves room for later bounded status updates; existing oversized legacy
records are not rewritten or migrated by this admission check.
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

The publication outcomes below apply to the existing atomic local-store protocol. “Visible” describes
process-observable state, not proof of power-loss durability.

| Boundary | Published state and failure handling |
| --- | --- |
| Store/ancestor preparation, before private staging | No candidate job is published. A preparation failure retains existing jobs and any newly created empty directories; retry repeats all confirmations. |
| Metadata before/during write, before/after file force, before replacement | The old published record remains complete. The candidate is private. Ordinary cleanup removes its temporary file; abrupt exit leaves it retained. |
| Metadata atomic replacement attempt | An exception does not prove whether replacement occurred. Re-read the published record before deciding its state; no non-atomic fallback or rollback is claimed. |
| Metadata after replacement, before/after directory force | The complete new record is visible. A force/confirmation error does not restore the old record or confirm durability. |
| Upload input/metadata writes and forces, before/after private-stage force | No final candidate job is visible. Existing jobs remain intact. Ordinary cleanup removes private staging where possible; abrupt exit retains it without promotion. |
| Upload atomic rename attempt | Any rename exception is an uncertain-publication outcome carrying the generated job ID, even if the destination is absent when checked. |
| Upload after rename, before/after store-directory force | The complete input and matching metadata are visible together. A confirmation error returns uncertainty and does not delete the published destination. |
| Upload after successful confirmation | Return the published job. This is one submitted upload's result, not deduplication of independently repeated submissions. |

For an uncertain upload, HTTP returns 409 with `Location` and a “Check job” link; JSON also supplies
`job_id`, `job_url` and `retry_upload:false`. Inspect that same job rather than automatically submitting
another upload. A missing or unreadable result leaves the outcome unresolved and requires operator
investigation; it does not establish rollback or authorize a duplicate-free retry. Explicit resubmission
can create another job. Job publication does not establish analysis completion or an accepted source revision.

The clean-commit consolidated run at `0cd6f6a` passed 100 tests with no failures/errors/skips on
Temurin 21.0.12+8, Linux 7.1.8 and XFS. Evidence is retained at
[the tracked manifest](evidence/web-job-recovery/20260905T142816Z-g5bs2nae/manifest.json) and matching JUnit XML reports with exact commands,
suite results, XML digests and runtime/filesystem identity. `JobMetadataPublicationTest` covers eight
exception boundaries; `JobMetadataCrashTest` covers eight abrupt-exit boundaries including a half-record;
`JobUploadCrashTest` covers fourteen upload boundaries including partial input/metadata. Fresh readers
verify complete old/new metadata, complete published inputs and matching metadata, unchanged existing
jobs, terminal child state and absence of ordinary cleanup after abrupt exit. HTTP uncertainty tests
verify the reconciliation response and exclude private I/O diagnostics. These prove #242's publication
outcome and complete-record criteria at the tested application boundaries. They do not close writer
ownership, safe reclamation, power-loss/kernel-I/O qualification or the entire recovery milestone.

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

The stop-reason mapping assertion retains a bounded header projection of the
prelaunch observation already attached to its mapped failure. It reports only
support status, first observed phase/kind, elapsed/remaining samples and last
entered/returned phases. The assertion does not resample, traverse arbitrary
causes, render phase/leaf payloads or invoke another operation. Missing, ambiguous,
oversized or foreign records and malformed selected headers remain unavailable.
The unused phase/leaf payload is not validated or rendered. The pure
assertion controls cover that projection and private-text omission. Production
budgets, native observations, launch/refusal/cleanup policy and every original
stop-reason assertion are unchanged. A later passing mapping case cannot explain
an earlier launch timeout or prove its cleanup; full prelaunch diagnosis remains
open.

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

Workspace snapshots admit regular files only when their observed link count is exactly one,
matching the filesystem broker's read/replacement policy. Other link counts fail with
`WORKSPACE_VIOLATION` and `unsupported-link-count` before the file-budget/hash callback runs.
This applies to both initial and final snapshots, including aliases whose names are all
allowlisted. Existing descriptor/path revalidation, metadata comparisons and mutation authority
checks still apply to admitted files.

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

The selected storage/web classes are declared in `SUITES` in
`scripts/verify-web-job-recovery.py`. Required case names come from each class's literal zero-argument
`@Test` declarations. The corpus covers publication, controlled JVM exits, ownership/shutdown,
retained-file inventory and HTTP presentation; it also retains supporting integration checks. A complete
case inventory supplies the inputs to the supported fault/configuration acceptance audit.

#### Reuse existing core reports

Primary Actions verification reuses the core JVM invocation. While its reports are still at their
original location, the report-only command is:

```sh
python3 scripts/verify-web-job-recovery.py \
  --reports build/test-results/test \
  --output build/web-job-recovery-inventory.json
```

Use `build/test-results/full-suite` after the CI retention step renames the directory. For downloaded
reports, point `--reports` at their repository-local `test-results/full-suite` directory. `--reports` and
`--output` must be supplied together and resolve inside the repository. This mode inspects XML without
invoking Gradle and permits unrelated core suites alongside the required corpus.

The schema-3 inventory records every required method, declaration-source commitment, suite XML
byte/hash commitment, actual outcome and matching per-case configuration record. Missing, duplicate,
malformed, failing or skipped required cases and missing/misbound records fail verification. Retain the
CI checkout/compile evidence separately: the inspector's source snapshot does not authenticate which
source produced supplied reports.

#### Run an isolated reproduction

From a provisioned checkout with cached Gradle dependencies, run:

```sh
python3 scripts/verify-web-job-recovery.py
```

This offline mode invokes Gradle for the declared corpus, with fresh JUnit/HTML reports, Gradle output,
JVM temporary storage and a schema-2 terminal manifest under a unique
`build/web-job-recovery-verification/` directory. Fixture factories retain their repository-local roots
and explicit parents; those roots need not be inside the invocation's evidence directory. Their actual
filesystem observations are attached to their own case records.

The manifest retains source commit/tree, dirty-worktree and tracked-diff bindings, exact command,
declaration/report commitments, observed runtime/filesystem details and outcomes. Use a clean committed
checkout; the tracked-diff digest does not capture untracked source contents. The runner disables test
output reuse and refuses nonzero builds, unexpected/missing/duplicate suites, malformed or empty
reports, failures, errors, skips and missing case configuration. An interrupted run without a terminal
manifest is incomplete. Its lock serializes this runner; keep unrelated Gradle invocations separate.

Both modes keep no-root cases and unsupported block-size observations explicit and retain
`fullMatrixQualified=false`. Record the tested native-host architecture, filesystem properties,
fault/restart boundaries and unsupported/skipped cases in the acceptance matrix. The store contract
admits `amd64`/`x86_64` and `aarch64`; compiler-target coverage does not establish native-host coverage.
Observed fixture facts do not grant immutable-host, process execution or safe reclamation authority.
Neither mode selects the patch reproduction lane or certifies B-series release readiness.

### ACP SDK upgrades

The bounded `acp/v1/wire-contract.json` corpus currently freezes 58 SDK-decoded and re-encoded
JSON-RPC messages. It includes the production model/mode setters, select and boolean configuration
setters, flat and grouped session inventories, load request/responses, authentication/logout shapes, terminal token usage, session-info and configuration/mode/command/usage updates, and the original
prompt/filesystem/terminal/permission lifecycle. `AcpV1WireContractGoldenTest` rejects missing or
unvalidated entries and pins both Maven and SDK-reported versions. A golden update documents wire
compatibility only; it does not implement advertised authentication, resume, or operator behavior.

An SDK upgrade is intentional work, not an automated version-range update. A change must:

1. confirm that the SDK still identifies protocol v1 as stable and keeps v2 opt-in;
2. review the official v1 schema and release notes for wire or capability changes, including the opt-in v1
   additional-directory, usage, and message-id fields;
3. update the Gradle coordinate, `ACP_KOTLIN_SDK_VERSION`, Java probe/evidence pins,
   `contracts/acp/v1/required-cases.json` and pinning tests together, as identified
   in the source-owner table below;
4. review and run the versioned golden corpus, operator preference exchanges, scripted subprocess
   tests and full test suite; and
5. keep v2 disabled until a project issue explicitly adopts it after it becomes stable.

The lifecycle wrapper remains necessary even when SDK internals change: executable selection, OS process ownership,
stderr retention, resource deadlines, cancellation polling, and process-tree cleanup belong to the host application.

### Qualifying an agent or runtime change

Qualification belongs to an exact combination of client, SDK/protocol, agent,
runtime closure, host, workflow and provider policy. Retain the old combination's
results with their original identities. An upgrade needs a new result for every
required case in the [two-agent matrix](#pinned-required-cases-and-unsupported-capability-policy).
The current pins are SDK `0.30.1`, stable protocol `1`, Goose `1.46.0` and
`codex-acp` `0.16.0`; these identify the checked contract rather than a claim
about the newest upstream release.

| Changed input | Owning source and review obligation |
|---|---|
| Client SDK/protocol | Update the exact Gradle dependency and [`AcpProcessConfiguration.kt`](../src/main/kotlin/decompengine/acp/AcpProcessConfiguration.kt) together with the hard-coded SDK evidence fields in [`AcpCompatibilityPreflight.java`](../scripts/support/AcpCompatibilityPreflight.java) and both the provenance check and evidence field in [`AcpCompatibilityAuthenticationProbe.java`](../scripts/support/AcpCompatibilityAuthenticationProbe.java). Review all v1 serializer/capability changes and the scoped optional-v1 opt-ins. |
| SDK pin assertions and current documentation | Review the literal SDK assertions in [`AcpAgentHarnessTest`](../src/test/kotlin/decompengine/acp/AcpAgentHarnessTest.kt) and [`AcpOperatorSurfaceContractTest`](../src/test/kotlin/decompengine/acp/AcpOperatorSurfaceContractTest.kt), plus the artifact/reported-version fields in the wire corpus and its golden test below. Update current setup/recovery version references; retain historical evidence with its original pins. |
| Wire contract | Review the versioned [`wire-contract.json`](../src/test/resources/acp/v1/wire-contract.json) and [`AcpV1WireContractGoldenTest`](../src/test/kotlin/decompengine/acp/AcpV1WireContractGoldenTest.kt). Every changed message needs an explained compatibility result; a changed golden file alone supplies no runtime result. |
| Independent agent/archive | Review the exact release URL/version, archive/member digests and target metadata in [`ci-qualify-goose-acp.sh`](../scripts/ci-qualify-goose-acp.sh) or [`ci-qualify-codex-acp.sh`](../scripts/ci-qualify-codex-acp.sh), plus the corresponding Java probe and acquisition controls. Preserve archive-layout and member verification. |
| Machine-readable case and result bindings | Update the exact client, SDK artifact/reported version, stable protocol and agent version/archive size/digest pins in [`required-cases.json`](../contracts/acp/v1/required-cases.json) together with their build/wire/probe/script owners. Review the declaration and [`verify.py`](../contracts/acp/v1/verify.py) schema/scope rules plus [`test-acp-release-manifest.py`](../scripts/test-acp-release-manifest.py) when cases or metadata semantics change. The ordinary CI source-pin and data controls must pass. Retain old definition bytes/digests and result identities; a changed definition requires a new digest and fresh source/context-bound results. |
| Executable/runtime/helper | Re-provision the reviewed immutable executable/runtime/helper commitments at their final paths, and bind the actual host architecture and containment prerequisites. Keep the existing ownership, mode, resource and cleanup checks. |
| Factory/session configuration | Review the schema version, canonical factory commitment, ordered argv, explicit environment provenance and advertised preferences. A changed identity must pass [session reconciliation](acp-session-recovery.md#conversation-decisions). |
| Provider/auth policy | Qualify the broker/channel and advertised auth lifecycle under their owning contracts. Provider credentials stay in the operator broker; the current network-free checkpoints cannot establish a positive model session. |

Use this order for an upgrade proposal:

1. Record the old and proposed exact combination, the intended workflows and the
   upstream compatibility changes. Keep stable-v1 default negotiation and its
   explicit v2 boundary. Preserve historical evidence instead of rewriting its
   identities to the new pins.
2. Review all affected source owners in the table together. Keep the required
   case definition, optional capability observations and actual outcomes
   separate. An untested optional feature remains unknown; a missing required
   capability remains a blocking outcome for that required case.
   Update the versioned declaration with any changed literal pins or required
   cases, then require its ordinary metadata check and data controls. Bind new
   results to the exact new definition digest and current runtime/provider-policy
   context; changing metadata cannot requalify retained results from an old combination.
3. Obtain current-source normal Actions evidence for wire serialization,
   provisioning, advertised preferences, filesystem/terminal/permission
   enforcement, lifecycle, recovery and packaging. Bind the actual checkout and
   compiled tree, test selection, raw reports, exact artifact hashes and every
   failure/skip/truncation. Required checks need fresh execution evidence;
   retained old reports keep their original source identity.
4. Obtain the applicable exact-pin credential-free agent checkpoints. Their
   initialize/authentication-required results retain the limited scopes above.
   Complete all required positive session, streaming, edit, permission,
   cancellation, reconstruction and repair cases through the standard factory,
   admitted provider/auth environment and production validators. Preserve failed,
   unsupported and cleanup-unverified outcomes; an agent stop reason cannot
   promote a revision or waive a required result.
5. Audit persisted identity and recovery against the changed combination before
   continuing a stored conversation. Retain accepted source and old session
   evidence, quarantine incompatible identities, and keep unknown process cleanup
   blocked. Recreating a conversation requires its explicit recorded policy.
6. Record the release decision against the complete required result population.
   The machine-readable manifest owned by
   [#770](https://github.com/minsago-elite/decomp_thing/issues/770) must bind the
   client/SDK/schema, agent/runtime/provider-policy versions, exact release
   commits and immutable result artifacts. That manifest and full
   [#72](https://github.com/minsago-elite/decomp_thing/issues/72) release
   qualification remain open; this procedure supplies no missing result rows.

Retain any previously qualified distribution, provisioning and identity-bound
evidence with its original qualification scope for rollback. Record an absent
qualified rollback combination in the release decision. A rollback selects its
recorded combination and follows
the same session/accepted-source reconciliation rules. Reusing a directory name,
changing a version string or deleting a journal cannot establish compatibility
or resolve unknown cleanup. The source, runtime and provider trust boundaries
continue to apply throughout the upgrade.

### Operator authentication inventory

Preflight returns an invocation-local `authentication` inventory containing at most 32 advertised
methods. IDs are exact and bounded to 256 UTF-8 bytes; duplicate or blank IDs fail admission.
Names/descriptions are bounded before redacted previews are retained. Removable control
characters are normalized in both preview input and private values before literal and credential-pattern
matching, so later stripping cannot reconstruct a secret. Raw input/private-value limits still apply
before normalization.
Authentication ID/name/description previews also conceal normalized private values and delimited
private fragments after redaction and truncation. The existing 4096-value and 1,048,576-unit input
bounds apply before filtering or duplicate suppression. Short normalized private values match
anywhere; one-to-seven-unit letter/number tokens are checked against the complete normalized private
values, including fragments split across methods/fields and format/combining insertions. Private
invisible units are withheld too. Existing eight-unit blocks retain the guarantee for every contiguous
private fragment of at least 15 units. A shared character alone does not classify an otherwise
unrelated identifier as private: public advertised identifiers still have useful redacted previews.
Two 65,536-bit indexes prefilter character membership. Short-token searches charge at most 64 Mi
private-value units per capture, with a 4096-entry cache; exhaustion withholds unchecked text.
A literal fixed `[redacted]` marker is reduced to that constant alone, unless it contains a normalized
whole private value. Arbitrary encodings and undelimited short substrings inside unrelated words
are outside this matching guarantee. Exact IDs remain private inventory data, never public selection
authority. The separate long-fragment diagnostic projector retains its existing policy.
The private index is local to capture and never serialized. Full-payload commitments remain unchanged. Truncation preserves UTF-16
surrogate pairs. Redaction checks its 16,384-unit working-text limit after every replacement, before
another replacement can expand inserted markers; exceeding it produces an omission marker. A single
replacement can transiently allocate up to ten times that limit. The complete SDK-serialized
method array, including retained variant-specific fields and extension metadata, must also fit
64 KiB of canonical JSON, 16 levels, 4096 nodes, 16 KiB per string and 64 KiB total string bytes.
Each number token in the SDK-serialized array is limited to 256 characters, including its sign, decimal point and exponent.
This explicit numeric admission policy also applies to extension metadata and unknown variant payloads.
Floating-point tokens use `OracleJson` binary64 canonicalization, which rejects non-finite and nonzero
subnormal results; inventory commitments do not preserve arbitrary-precision decimal representations.
Excess payloads fail preflight as invalid authentication inventories with normal cleanup. The bound
applies after the existing transport frame and SDK decoding limits; it is not a raw-input parser limit.
Unknown variants remain
Unknown variants remain
explicitly `unknown`, and every method currently reports `loginSupported=false`: this inventory
is not an authentication action or grant. The printable doctor descriptor includes the count,
scoped inventory commitment and logout advertisement/support flags. Default object string representations omit method IDs and previews.

The `sdk-auth-methods-hmac-sha256-v2` commitment covers the ordered, complete SDK-serialized method
array, including retained extension metadata and variant-specific fields. HMAC-SHA-256 authenticates
the UTF-8 format name, a zero byte and the bounded canonical JSON array using a private random
256-bit key generated once per JVM. The key is never persisted or exposed. This replaces the public
unkeyed digest, which could reveal low-entropy secret values through offline guess checking.
JSON object key order is normalized; array order remains significant. Ready web inspection returns
`inventoryCommitment`, `inventoryFormat` and `inventoryScope`; the doctor descriptor carries the same
information. Compare commitments only within the same format and scope. The random scope ID and
key change after JVM restart, requiring fresh inspection rather than cross-process digest comparison.
The public scope ID does not expose the key. Raw variant payloads are not retained in the operator projection.
The commitment covers SDK-retained fields, not unknown fields discarded by SDK decoding, configured
identity, credential validity or logout authority. It cannot authorize login by itself. Exact IDs are
available only to explicit operator API consumers;
those consumers must not print them without redaction. This result stays outside invocation acceptance
receipts and session/project archives. Login/logout, interactive surfaces and credential-state handling
remain tracked by #265/#70, with fresh advertised-method validation required before any future dispatch.

Use `llm_bin_patch doctor --auth-methods` to inspect advertised method previews explicitly.
The normal doctor report retains inventory count/scoped commitment and logout advertisement/support flags. Inspection prints quoted, redacted
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
first use, caching both a selected harness and any configuration-selection failure; restart the server to change that selection, including after correcting an initially invalid configuration. No credentials or inspection status are
persisted in project records. This does not provide login/logout, durable operator state, or automatic
cancellation when a browser disconnects; production preflight keeps its existing deadline/cleanup bounds.

Optional Chromium check (with the Playwright dependency described for progress verification):

```sh
java -cp 'build/libs/*:build/oracle/gcc/kotlin-boot-runtime/*' \
  scripts/fixtures/AuthenticationDashboardFixture.java build/auth-dashboard.html
DECOMP_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright \
  node scripts/verify-authentication-browser.cjs build/auth-dashboard.html build/auth-browser/new-run
```

The fixture renders the production dashboard and writes its exact `APP_CSS` to the adjacent
`<dashboard.html>.css` file. The verifier serves that stylesheet, checks it loads and affects layout,
and records both HTML and CSS hashes. It mocks status responses. It checks explicit-only
inspection, preview rendering/escaping, failure, retry and empty inventory; trace/screenshot/result
files use a fresh evidence directory. It does not establish independent-agent authentication.

**Cancel inspection** posts an explicit cancellation request to
`/api/operator/auth-methods/cancel`. Status and admission responses include an
application-generated `inspectionId`; cancellation must include that exact value in
`X-Decomp-Inspection-Id`. Missing identity during an active inspection returns 400,
and an old identity returns 409 without changing the current cancellation signal.
Identity matching, setting the signal, terminal publication and new admission share
one lock. The browser captures the ID for each cancellation request and only enables
cancellation after learning it from admission or a status response. A request acknowledgement is not a terminal cleanup result:
the view continues polling until inspection finishes. HTTP, network, or malformed status-response
failures display a retry notice and keep cancellation available once an inspection ID is known,
without enabling a new inspection. If admission omitted the ID, cancellation remains disabled
until a successful status response supplies it.
A 409 start response attaches the page to the existing inspection. Late acknowledgements cannot overwrite
a terminal result or a later inspection. The server's cancellation token reaches the preflight
scheduler, launch and initialize waits. Shutdown requests cancellation and waits for the tracked
inspection thread to finish, using the provider's own cleanup deadlines without a shorter web timeout.
An interrupted shutdown caller continues waiting and has its interrupt flag restored afterward.
Launch and shutdown share an admission lock, and admitted-task ownership remains held until completion.
An injected inspector must return after its own cleanup; a stuck inspector can delay graceful shutdown.
Forced JVM termination still cannot establish cleanup. The preflight overload preserves a cancelled invocation's
receipt in `AcpPreflightCancelledException`; cleanup failures retain their original failed outcome.
Only that terminal cancellation is rendered as `cancelled`. Login/logout cancellation and durable
operator authentication state are still separate unsupported work.

The pinned v1 wire corpus now also freezes the agent-managed authentication advertisement,
`authenticate` request/empty response and `logout` request/empty response. Logout advertisement
is the distinct `agentCapabilities.auth.logout` field; the baseline fixture omits it and advertises
no auth methods. Method selection carries the exact advertised `methodId`. These are serializer
and JSON-RPC envelope checks against SDK 0.30.1, not enabled login/logout behavior, external identity
verification, permission to send an unadvertised method, or draft-v2 compatibility. The operator
implementation still reports login unsupported until its lifecycle and authority requirements pass.

The auth golden includes the SDK-emitted `type: "agent"` discriminator. The SDK accepts its absence
as the agent-managed variant, but encoding normalizes it to the explicit discriminator; the fixture
freezes the emitted shape instead of treating omitted input defaults as byte-preserving round trips.

Preflight separately preserves presence of `agentCapabilities.auth.logout` as `logoutAdvertised`.
It always reports `logoutSupported=false` until the explicit logout lifecycle is implemented and
qualified. An empty method list does not imply absent logout advertisement. The ready web inspection
response exposes both flags; the stable doctor descriptor names both explicitly. The existing method
digest deliberately excludes this capability and must not be used to authorize logout. This capture
retains no logout extension payload and sends no logout RPC.

The additional `initialize-auth-variants.response` fixture freezes SDK v1 advertisements for
`env_var`, `terminal` and an unknown type. Typed checks retain environment variable names/flags and
setup links, terminal arguments/environment, and unknown raw extension data. All three project
inventory variants remain `loginSupported=false`. A contained scripted preflight inspects those
advertisements and completes cleanup without accepting any post-initialize request. This qualifies
advertisement decoding and inspection only; it does not qualify credential handoff, terminal login,
link handling, an authenticate exchange for those variants, or an independent external agent.

Initial model/mode ID rejection and initial configuration option/value rejection now include the
exact session-creation advertisement's bounded choice previews. The same formatter serves current
configuration-inventory mismatches: at most four JSON-quoted IDs/values, with a fifth-entry lookahead
for an omission marker, configured-environment redaction, and 48-character prefixes plus truncation
markers. All configured model/mode IDs, option IDs and select values are redacted across every preview,
including when an earlier preference fails. Whitespace-only preference IDs remain in the private
set. After JSON quoting and omission formatting, the formatter checks the complete preview again;
if a replacement marker or formatting recreates any private ID, it withholds the entire hint as
an empty string. A fixed replacement cannot be safe for arbitrary configured identifiers. This
does not change exact-match selection for admitted redaction configurations. The separate allowance
of at most 130 identifiers of 256 characters is independent of the environment redaction budget.
The complete rejection message is checked after adding labels, boolean-choice text and hint
boundaries, for both initial advertisements and current-inventory failures. Unsafe hints can be
withheld while retaining a separately redacted base message. If all readable output is withheld,
a bounded, dynamically selected nonblank indicator preserves the typed failure contract without
using an unchecked fixed fallback. Failure kind, reason and preference-index fields remain unchanged;
message redaction does not widen selection authority or send a setter request.
Environment redaction admits at most 4,096 supplied values and 1,048,576 UTF-16 code units in total
before blank filtering or de-duplication; raw duplicates and blank text count toward those limits.
Over-budget configuration uses the existing fixed redaction-limit rejection. Each preview replacement
also stops when an intermediate exceeds 16,384 code units and uses the secret-aware omission fallback.
These are display hints, not exact selection tokens or additional setter authority. Capability
absence and type/ambiguity rejection keep their existing typed outcomes. No setter or prompt is sent
when the requested preference fails the initial advertisement check.

A stop request publishes startup cancellation before waiting for the server lifecycle lock. Recovery
checks it before inspection, between entries, after inspection and before each status update; an
interrupted recovery thread is also cancelled without clearing its interrupt flag. Cancellation before
publication reports that recovery statuses were unchanged. Cancellation after publication begins
reports that some statuses may have changed, and a later explicit startup can reconcile remaining
pending jobs. Request admission also checks the cancellation flag, covering a stop request racing the
last startup check. These cooperative checks do not interrupt a filesystem operation already blocked
inside the kernel, and ownership remains held until startup/cleanup returns.

The early stop signal is shared by startup recovery, HTTP admission, background submission, queued
callback claims and successful-completion publication. A callback delivered after observing the stop
signal is discarded with the existing never-started outcome; an active operation returning after that
signal is recorded as failed rather than complete. The signal also requests authentication-inspection
cancellation before cleanup waits on the lifecycle lock. Signalling alone does not release ownership
or prove resource cleanup; `stop` still closes the listener and waits for the existing lifetime rules.

Job metadata decoding now enforces the writer's depth/node/string limits and supported top-level/ELF
field sets. Text must be JSON strings, numeric fields must be JSON integers, input size must fit
0–32 MiB, and unsigned ELF version/header/count fields must fit their declared widths. Unknown fields
are rejected rather than silently dropped by a recovery rewrite. Older records may still omit
`updated_at` or omit/null `status_message`. The existing signed-Long wire representation of the unsigned
ELF entry point is preserved. Invalid records remain retained and cause startup inspection to fail
before recovery status publication; this validates metadata structure, not the uploaded file's identity.

Dashboard listing uses the same read-only scanner as startup recovery: at most 4,096 encountered
store entries and 64 MiB of metadata, with 256 KiB per record and strict schema validation. A complete
scan is required before returning sorted jobs. Unreadable records and exhausted budgets produce an
explicit HTTP 503 “Job listing unavailable” page with fixed diagnostics; they no longer silently remove
jobs from a successful listing. Listing never rewrites or removes records. After records are repaired
or the store fits the limits, a later request can succeed. These limits do not provide pagination,
aggregate storage admission or an atomic snapshot against noncooperating writers.
