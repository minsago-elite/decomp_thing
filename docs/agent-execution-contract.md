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

`AgentHarness.execute` streams monotonically sequenced events to its caller. The event union represents assistant
message chunks, plan snapshots, tool-call progress, permission decisions, and digest-backed file changes. A final
`AgentExecutionResult` carries a transport-neutral stop reason, optional session/resume reference, optional usage,
summary text, and the complete set of workspace changes.

File changes contain a workspace path, create/modify/delete kind, before and after SHA-256 digests, and an optional
result size. The changed content lives in the workspace. Consumers validate the reported digest before accepting a
change, so a provider never needs to encode a source replacement in conversational output.

The normal stop reasons are `COMPLETED`, `NO_CHANGES`, `REFUSED`, `CANCELLED`, and `LIMIT_EXHAUSTED`. Cancellation and
limit exhaustion are explicit stops because they can legitimately retain streamed evidence or partial workspace
changes. Unexpected failures raise `AgentExecutionException` with an `AgentFailure` classified as invalid request,
configuration, authentication, authorization, availability, transport, protocol, workspace violation, timeout,
process crash, resource exhaustion, or internal failure. Failures may include a session reference, a retryability
signal, and non-sensitive diagnostic details.

## Current compatibility path

`RepairClientAgentHarness` adapts the original OpenAI-compatible one-shot client. It is the only non-MVP component
that interprets chat-returned replacement JSON: it validates every target against the generic request, atomically
replaces each authorized file with rollback on installation failure, and returns first-class `AgentFileChange`
records. Bounded module reconstruction and
trace-guided repair depend only on `AgentHarness`; a future ACP client or built-in harness can replace the adapter
without changing those workflows.
