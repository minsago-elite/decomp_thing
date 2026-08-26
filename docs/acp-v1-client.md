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
JNA is independently pinned to `5.19.1` for the small Linux filesystem syscall boundary described below.

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

Terminal capabilities are not advertised by this lifecycle layer. Permission requests are denied by default using an
offered reject choice, or cancelled when no reject choice exists. The terminal/permission issue adds its broker without
changing this process lifecycle.

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

This boundary governs only calls routed through the ACP filesystem callbacks. The exchange validation and rollback
defend callback-local interleavings, but they do not turn the configured agent executable into an OS sandbox or stop it
from racing the broker with arbitrary direct host syscalls (including further changes during rollback). Preventing that
adversarial actor, and terminal/syscall containment generally, remains the separate #61 process-sandbox boundary.

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
