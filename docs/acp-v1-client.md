# Stable ACP v1 client

`AcpAgentHarness` is the subprocess-backed implementation of the provider-neutral agent execution contract. It uses
the official Kotlin SDK from Maven Central:

```text
com.agentclientprotocol:acp:0.30.1
```

The dependency is exact rather than a range. The SDK's stable `LATEST_PROTOCOL_VERSION` is `1`; the harness also
sends `protocolVersion = 1` with `supportedProtocolVersions = {1}` and uses only the v1 `Client` types. ACP v2 types
are draft, require an explicit SDK opt-in, and are not imported or negotiated here. The no-op SLF4J binding is pinned
alongside the SDK to keep SDK logging silent in CLI and test hosts; subprocess stderr remains separately captured.

The 0.30.1 SDK marks three optional v1 schema extensions used at the contract boundary as `UnstableApi`: additional
session directories, prompt token usage, and message identifiers. Opt-in is deliberately scoped to the adapter code
that reads those fields. They do not change version negotiation: they remain v1 fields, additional directories are
capability-gated, and usage/message identifiers are normalized rather than exposed as SDK types. The upgrade checks
below must review these fields explicitly; removal or wire-shape changes require adapter and subprocess-test changes.

## Process and wire boundary

The configured executable must be an absolute, normalized executable path. Its argument list is passed directly to
`ProcessBuilder`; no shell command string is constructed. The child starts in the request's first absolute workspace
root. Environment inheritance is an explicit configuration switch, and exact overrides can be supplied.

The child gets dedicated pipes:

- stdin and stdout carry UTF-8 newline-delimited JSON-RPC only;
- stdout frames are strictly decoded and validated before the SDK sees them;
- every inbound response ID must match and consume one pending outbound request ID, so unknown and duplicate responses
  are rejected before SDK dispatch;
- stderr is continuously drained into a separate bounded capture, available through `latestDiagnostics()`; and
- total stdout, individual frame, and retained stderr sizes are bounded.

One process serves one execution. The client runs `initialize`, validates the selected version and configured agent
capabilities, creates a session with an absolute `cwd`, sends one text prompt, streams `session/update` events, and
requires exactly one final prompt stop reason. Additional workspace roots require the agent's
`sessionCapabilities.additionalDirectories` capability.

Startup, individual request, prompt idle, total wall-clock, cancellation grace, transport-drain, and shutdown waits
all have finite deadlines. Cancellation sends `session/cancel` once a session exists. Cleanup closes the protocol and
stdin, then escalates from graceful exit to process-tree termination and forced termination within the configured
shutdown window. Exit status, bounded stderr, forced-termination state, and any surviving PIDs are retained separately
from protocol stdout. Diagnostics distinguish any tree-termination escalation from an accepted termination request for
the root agent process. A naturally observed nonzero exit remains a process crash even when a valid final prompt
response arrived first. Once host termination escalation begins, a subsequent nonzero exit is treated as cleanup
because the portable process API cannot distinguish a signal-caused exit from a concurrent natural exit at that point.

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

The portable lifecycle tracks the launched process and repeatedly discovers and terminates its ordinary descendants.
It is not OS containment: a deliberately daemonizing child can double-fork or create a new session before discovery
and become unreachable through Java `ProcessHandle`. Process-group/cgroup or Windows Job Object containment, shutdown
recovery, and stress proof remain explicit work in issues #61 and #71. Until that lands, diagnostics and tests prove
cleanup only for the launched process and descendants that remain discoverable; they do not prove categorical cleanup
of adversarial daemon escapes.

Filesystem and terminal capabilities are not advertised by this lifecycle layer. Permission requests are denied by
default using an offered reject choice, or cancelled when no reject choice exists. The dedicated filesystem and
terminal/permission issues add policy-aware brokers without changing this process lifecycle.

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
