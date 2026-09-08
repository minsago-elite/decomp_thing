# Built-in agent loop v1

`BuiltinAgentHarness` is an optional implementation of the existing `AgentHarness` contract.
It consumes the neutral `ModelProvider` API and an invocation-owned `BuiltinToolSession`.
The production factory continues to select ACP; no legacy one-shot path is relabeled built-in.

The state machine prepares context, requests a model action, authorizes each registered tool,
executes the tool, observes its result, and independently validates model completion before
terminating. Model text and streamed tool/finish events do not dispatch tools. The returned
proposal must pass registered JSON schemas, unique call IDs and the remaining tool-call budget
before the first effect. Actual authorization occurs through the trusted session before each call.

The harness carries the original execution deadline and cancellation to the provider and tool
session. It bounds model calls (including reported retries), tool calls, repeated canonical
actions, context serialization, output bytes, individual tool results, trace records and aggregate
input/output usage. Initial context is packaged with explicit selection and retrieval metadata;
overflow without supported retrieval, mandatory metadata overflow and later history overflow produce
explicit exhaustion. Context is sorted by input ID;
tool results retain their call IDs. Action identity sorts JSON object keys and excludes the model's
chosen call ID, so renaming a repeated action cannot evade its limit.

The loop supplies its remaining input allowance as the provider's serialized-request ceiling and
its remaining output allowance as the provider token ceiling. It reconciles reported/estimated
usage before authorizing tool effects. The adapter's one-byte token equivalent is documented in
[the provider contract](builtin-model-provider-v1.md). Pricing and shared hierarchical reservations
remain #82 work; paid requests and successful responses cannot authorize candidate publication.

## Terminal evidence and acceptance

Every invocation returns a request-bound `AgentExecutionReceipt`. `BuiltinLoopEvidence` records
the exact built-in terminal status, immutable state/hash records, model/tool counters, token usage,
whether any usage was estimated, and cleanup completion. It retains no provider/tool payloads.

| Built-in status | Shared contract outcome |
| --- | --- |
| completed | completed; trusted session validation succeeded with candidate changes |
| no-change | no-changes; trusted session validation succeeded with no changes |
| validation-required | completed; the receipt explicitly retains outstanding workflow validation |
| refused | refused |
| cancelled | cancelled |
| exhausted | limit-exhausted |
| invalid-action | protocol failure with explicit built-in status |
| provider-failed | classified failure with explicit built-in status |
| tool-failed | failure, including cleanup that could not be confirmed |

The existing shared `COMPLETED` result means the harness turn ended, not that a reconstruction is
accepted. The validation-required distinction lives in first-class receipt evidence rather than
changing that established contract. The workflow alone can accept and publish a revision after its
source, build, behavior and provenance checks. All tool edits remain candidate edits, including when
the session reports validation succeeded. Cleanup failure overrides an otherwise successful outcome.

## Current qualification boundary

Run the deterministic suite with:

```bash
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' --console=plain
```

The loop tests use a memory-backed scripted tool authority and cover all terminal statuses,
multi-step turns, invalid batches, policy denial, duplicate/repeated calls, context/output/usage/
call/trace limits, cancellation, deadlines, cleanup failure and deterministic receipt metadata.
They do not prove filesystem/process containment, build correctness or real-provider behavior.

#73 remains open. Production #74 tool sessions must delegate to the existing ACP descriptor,
permission, sandbox and process-cleanup authority and share its admission limits. Injected provider
and tool implementations must cooperate with the control token and deadline; arbitrary blocking
callbacks cannot be forcibly reclaimed by an in-process loop. Durable redacted transcripts,
checkpoints, interrupted candidate reconciliation and validated restart belong to #75. Production
workflow/factory/archive integration and the versioned real-provider comparative gate remain C1/C2
requirements. This checkpoint does not claim those outcomes.
