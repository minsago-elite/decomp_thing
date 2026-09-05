# Agent execution contract

Reconstruction and trace-guided repair use the versioned `decompengine.agent` contract. The contract is deliberately
independent of ACP, JSON-RPC, HTTP, and any model response schema. A harness receives an objective and edits an
explicitly authorized workspace; source patches embedded in assistant text are not part of the contract.

## Request boundary

An `AgentExecutionRequest` contains:

- one or more named, absolute, normalized workspace roots;
- immutable text context inputs, separate from writable workspace files;
- exact or recursive path rules and a global operation allowlist;
- wall-clock, idle, turn, tool-call, output-byte, and optional token limits; and
- a cancellation token that can change state while an execution is active.

Workspace paths are root-qualified, normalized relative paths. A path rule cannot grant command execution, network
access, or permission escalation implicitly; those operations must be present in the global allowlist. Transport
implementations remain responsible for enforcing the request for the complete session.

## Streaming and completion

`AgentHarness.executeReceipt` streams monotonically sequenced events to its caller. The event union represents assistant
message chunks, plan snapshots, tool-call progress, permission decisions, and digest-backed file changes. A final
`AgentExecutionResult` carries a transport-neutral stop reason, optional session/resume reference, optional usage,
summary text, and the complete set of workspace changes.

File changes contain a workspace path, create/modify/delete kind, before and after SHA-256 digests, and an optional
result size. Ordinary workspace invocations leave candidate content in the authorized workspace. Captured repair
invocations instead return bounded file content through the filesystem broker while the canonical project remains
outside the agent's file grants. Consumers independently reconcile content, reported digests and workflow policy
before accepting a change. See [workflow acceptance](acp-change-acceptance.md) for the two paths and their limits.

The returned `AgentExecutionReceipt` binds the immutable request and access policy to exactly one terminal outcome
and that invocation's provider evidence. ACP evidence includes negotiated implementation/capabilities, lifecycle,
policy audits, containment and cleanup. Consumers retain the receipt before interpreting the result; a later
`latestDiagnostics` lookup cannot substitute for this binding. The compatibility `execute` method and
`receipt.requireResult()` expose returned results or throw the corresponding typed failure.

The normal stop reasons are `COMPLETED`, `NO_CHANGES`, `REFUSED`, `CANCELLED`, and `LIMIT_EXHAUSTED`. Cancellation and
limit exhaustion are explicit stops because they can legitimately retain streamed evidence or partial workspace
changes. Failed receipts carry an `AgentFailure` classified as invalid request,
configuration, authentication, authorization, availability, transport, protocol, workspace violation, timeout,
process crash, resource exhaustion, or internal failure. Failures may include a session reference, a retryability
signal, and non-sensitive diagnostic details.

An agent's `COMPLETED` stop reason reports turn completion. Workflow validation separately determines whether source
may be accepted and what assurance that acceptance carries; a complete ACP receipt alone does not prove build,
behavior or release qualification.

## Current production and compatibility paths

`AcpHarnessFactory` selects `AcpAgentHarness` when the harness setting is omitted or explicitly `acp`. It loads the
strict private `ACP_CONFIG_FILE` document and binds its identity into factory provenance. Missing or invalid
configuration and unknown harness names fail before model-driven work. CLI reconstruction, repair and patch, web
reconstruction, and doctor use this factory. See [operator provisioning](acp-v1-client.md#operator-provisioning-and-preflight)
for supported host and agent capabilities.

`RepairClientAgentHarness` adapts the deprecated direct OpenAI-compatible one-shot client and requires the explicit
`legacy-openai` selection. It interprets chat-returned replacement JSON, validates each target against the request, atomically
replaces each authorized file with rollback on installation failure, and returns first-class `AgentFileChange`
records. Its provenance remains explicitly deprecated and carries no ACP protocol, SDK or containment claim.
The planned built-in harness is separate roadmap work; this compatibility adapter does not implement it.

The shared interface permits additional harnesses without moving provider response parsing into reconstruction or
repair logic. Each adapter must still satisfy the consuming workflow's acceptance and evidence requirements.
