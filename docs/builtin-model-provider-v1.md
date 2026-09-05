# Built-in model provider contract v1

The optional C-series implementation starts at `decompengine.builtin.provider.ModelProvider`.
It is separate from the deprecated one-shot repair adapter. ACP remains the production factory
default; this component does not yet select or implement a built-in workflow harness.

`ModelRequest` snapshots messages, registered tool definitions, call limits and cancellation.
It carries no provider URL, model configuration or authorization header. Messages can contain
assistant tool requests and correlated tool results. Tool parameters and arguments are JSON
objects; provider-specific function envelopes are confined to the adapter. A proposed tool call
does not grant filesystem or process authority and a model finish reason does not accept a revision.

The adapter maps streamed text, complete tool calls, usage, retry events and finish reasons to
neutral events. A normal response distinguishes stop, tool requests, output length and refusal.
Incomplete streams, invalid tool arguments, unknown tools, contradictory finish reasons, duplicate
call IDs and unsupported legacy function calls fail before any tool event is dispatched.
Errors expose a fixed classification and optional HTTP status, never response bodies or exception
causes containing provider data. HTTP 404 reports model/endpoint unavailability; a generic 400
cannot reliably distinguish unsupported tools from other invalid requests without provider-specific
error-body interpretation. A configured lack of tool support fails before HTTP admission.

The OpenAI-compatible adapter uses the documented
[Chat Completions streaming format](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events).
It explicitly requests usage. When usage is missing, the result marks estimates and charges one
serialized request UTF-8 byte per input token and one decoded text/argument byte per output token.
This measured equivalent is deliberately conservative, not a claim of tokenizer accuracy. Reported
usage is checked for nonnegative counts and the configured output-token ceiling. A hierarchical
reservation/cost ledger remains #82 work.

Connection establishment, each full HTTP attempt, stream inactivity and the enclosing call have
separate deadlines. Cancellation is polled during headers, streamed body reads and retry waits.
The publisher uses bounded demand and storage; raw response bytes and individual SSE events have
separate ceilings. Streams and the HTTP client close on every terminal path. There is no model
subprocess or filesystem capability in this adapter.

Only explicit HTTP 408, 429, 500, 502, 503 and 504 responses can be retried, with bounded exponential
jitter, a fixed retry count, and the original overall deadline. Retry-After seconds or HTTP dates
set a minimum delay; guidance above the configured delay budget terminates the request. Connection
failures and interrupted successful streams are not automatically replayed because their server-side
acceptance is unknown. Redirects are never followed.

Production endpoints require HTTPS without userinfo, query strings or fragments. Plain HTTP requires
an explicit loopback fixture opt-in and a numeric loopback host. The adapter does not inspect ambient
credentials or environment values. Its configured credential and explicitly supplied request secrets
are redacted from text, including across stream fragments; decoded tool arguments containing a
declared secret fail instead of silently changing the proposed action. Configuration, request, message,
call, response and text-event `toString()` methods omit payloads. Callers remain responsible for
declaring any additional sensitive input and for durable transcript/archive redaction in #75.

## Verification and remaining scope

Run the credential-free local HTTP fixture suite with:

```bash
./gradlew --offline test --tests 'decompengine.builtin.provider.*' --console=plain
```

The first checkpoint passes 19 tests with zero failures, errors or skips. It exercises incremental
text delivery before server completion, Unicode text, interleaved tool arguments and tool history,
measured/estimated usage, configuration, error classification, retry guidance/exhaustion, malformed
streams, secret redaction and decoded secret rejection, request/response/event ceilings, cancellation,
idle/request/overall deadlines, redirects, length and refusal.

This is local adapter evidence. #9 remains open: durable evidence redaction, full request-allocation
bounds, strict hostile JSON validation and shared admission/release integration need additional work.
No real-provider execution, built-in loop/tool containment, reconstruction, repair, restart, scheduler
or comparative release qualification is established by this checkpoint. C0–C2 remain open.
