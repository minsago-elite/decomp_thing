# ACP provider broker building block

This checkpoint supplies policy, framing, bounded response quarantine, and a host owner for the
restricted provider channel described by the open provider transport issues. It is not connected to
`AcpHarnessFactory`, the ACP SDK, the Linux boundary, or a packaged guardian. The default production
configuration still has no provider channel. This document does not qualify a provider or agent.

## Policy and authority

`AcpProviderTransportPolicy.DISABLED` is the default. An internal approval issuer constructs an
immutable descriptor for exactly `https://chatgpt.com/backend-api/codex/responses`, the Responses
create operation, one model and reasoning setting, cached ChatGPT access-token authentication,
the Codex gateway Responses adapter, an opaque credential reference, and finite limits. Unknown
endpoints, enum values, missing keys, extra keys, noncanonical values, and nonpositive limits are
refused. There is no proxy, redirect, WebSocket, arbitrary CONNECT, or peer-selected upstream URL.

The host owner accepts credential material already resolved by a future operator-owned resolver.
This module reads no auth file. Credentials never appear in the framing protocol, descriptor,
request evidence, or exception causes. The only JDK network backend is private; the deterministic
control seam is internal and cannot be selected by production configuration.

The existing factory does not call `openForProtectedQualification`. That internal API is reserved
for a later explicitly configured protected qualification path. Its existence is not admission or
compatibility evidence. Broker snapshots always state `adapterQualified=false` and
`providerCostCancellationProven=false`.

The approved descriptor is not proof that the ChatGPT backend accepts the gateway request shape.
The adapter inserts a finite `max_output_tokens` ceiling and commits both the admitted request
body and transformed wire body separately. Acceptance of that field and the generic provider's
body/header combination remains unqualified. There is no fallback transform, retry, or wider
endpoint after an error. Account-specific headers beyond the implemented account ID, including
applicable FedRAMP handling, require a separately reviewed credential/adapter contract.

## Ownership and limits

A broker owner binds the actual immutable `AgentExecutionRequestBinding`, a fresh random channel,
the approved descriptor, and a fresh invocation commitment. The caller supplies the remaining
enclosing deadline; it cannot exceed the admitted request's wall timeout. The effective duration
and output token ceiling are the minima of policy and admitted-request limits. A trusted SDK owner
must bind the actual session and turn once before any backend request. A channel cannot be reused
with another owner, replayed sequence, later invocation, or after revocation.
Every typed admission denial irreversibly revokes the owner. One bounded denial classification
is retained separately; a refused pre-dispatch request has no invented wire commitment. This
prevents repeated rejected bodies from bypassing the invocation's finite request/parse contract.

The first adapter serializes requests: one outstanding request, no queued requests, zero retries,
and a finite total request count. Wire request bytes, upstream response bytes, and reported usage
are cumulative across the invocation. Each network item and quarantined SSE event has a fixed
chunk cap. Response events are coalesced into bounded queued byte chunks, so network coalescing
does not turn three small events into a false overflow. The JDK executor has a finite task queue;
one private periodic lifecycle task advances cancellation, wall and idle checks even if the
consumer stops reading.

Header limits are enforced when JDK response metadata is delivered. This does not claim that the
application bounded allocations already made by the JDK's HTTP header parser. Actual TLS, parser
settings, concrete HTTP teardown, and runtime qualification remain required before this adapter is
accepted for production.

Cancellation, timeout, process/session termination, and broker failure must revoke the owner.
Revocation is irreversible and clears the channel. Queued provider bytes are discarded on failure.
Closing cancels subscriptions and exchanges and shuts down the owned client, executors, and
lifecycle task under the declared cleanup grace. Only actual local owner termination can produce
`VERIFIED`; failure retains the owner with `UNVERIFIED`. Future cancellation is best effort and
does not prove that a remote provider stopped computing, charging tokens, or retaining a request.

## Framed stdio contract

All integer fields use network byte order. A frame is an exact 18-byte header followed by its
declared payload:

| Field | Encoding |
| --- | --- |
| Magic | Four ASCII bytes `ACPP` |
| Version | `u8`, exactly 1 |
| Tag | `u8`, closed set below |
| Sequence | `u64`, positive signed-Long range for provider frames, zero for setup/ACP bytes |
| Payload length | `u32`, validated against static, tag, and caller bounds before allocation |

| Tag | Direction | Payload |
| --- | --- | --- |
| 1 `ACP_BYTES` | Both | Nonempty opaque ACP bytes, at most 64 KiB; sequence zero |
| 2 `PROVIDER_REQUEST` | Guardian to host | Channel bytes `[32]`, then one nonempty bounded JSON body |
| 3 `PROVIDER_RESPONSE_HEADERS` | Host to guardian | HTTP status `u16`, content-type byte length `u16`, ASCII type |
| 4 `PROVIDER_RESPONSE_CHUNK` | Host to guardian | Nonempty bounded safe response bytes |
| 5 `PROVIDER_RESPONSE_END` | Host to guardian | Exactly one closed terminal-code byte |
| 6 `PROVIDER_CANCEL` | Both | Empty payload for the active sequence |
| 7 `CHANNEL_OPEN` | Host to guardian | Exactly 152 bytes, once before other frames; sequence zero |

Setup contains channel `[32]`, policy SHA-256 `[32]`, invocation binding SHA-256 `[32]`, eight
positive `u32` bounds (request bytes, response bytes, header bytes, header fields, chunk bytes,
queued chunks, request count, output tokens), then three positive `u64` millisecond durations
(remaining overall, idle, cleanup). All durations have fixed ceilings. Remaining overall may be
less than idle or cleanup because model execution and cleanup have distinct deadlines. The host
order verifier checks the independently expected policy, invocation, and channel in constant time;
guardian syntax validation alone is not that admission proof.

Headers permit only status 200 with literal `text/event-stream`, or status 400–599 with an empty
type. No upstream error body or other header is forwarded. Terminal codes are 0 completed,
1 authentication, 2 authorization, 3 resource exhausted, 4 timeout, 5 cancelled, 6 unsupported
operation, 7 unsupported model, 8 malformed request, 9 malformed response, 10 transport,
11 revoked, 12 secret exposure. A normal completed end requires status 200; failures may end
before headers. Cancellation can be followed only by cancelled/revoked terminal classification.
Provider sequences start at one and advance exactly. Response byte accounting never resets
between requests. Unknown tags, wrong directions, malformed lengths, replay, and ordering errors
poison the order verifier rather than accepting a partial exchange.

## Response quarantine

Only audited Responses SSE events are supported. Complete events are quarantined under byte,
event-count, decoded-byte, and parse-work limits before release. Strict UTF-8, duplicate JSON key,
nesting and token guards reject ambiguous data. Secret matching covers raw and normalized wire
bytes, decoded JSON strings, and bounded logical delta streams. A possible credential prefix
retains complete events until disproved or the bounded quarantine refuses the stream. Error,
failed, incomplete, unknown, and malformed events expose no raw provider body.

The completed event remains held until upstream EOF, terminal usage checks, and parser finish
succeed. Missing or excessive declared usage and later trailing data therefore cannot release a
successful completion first. Provider usage is observed data, not an independent billing proof.

## Qualification boundaries

Credential-free controls exercise the building block through an internal deterministic backend;
they do not qualify the concrete JDK network backend or TLS. The guardian and SDK are not wired
by this checkpoint. Existing containment arguments, native gate descriptors, receipt schemas,
Actions configuration, and production authentication are unchanged.

The pinned bridge's gateway configuration is supported by its source, but actual ChatGPT backend
compatibility still needs a bounded protected inference turn through the production boundary.
Native tool commands also have a user-namespace compatibility gap, and a shared private loopback
listener does not prove provider-channel separation from native command descendants. No full-access
mode is authorized by this contract. Separate ACP terminal/candidate launches retain their existing
network isolation.

The standard reconstruction consumer requires an authenticated filesystem change and actual
target creation. Stock bridge 2.2.2 does not provide the required real ACP filesystem callbacks.
The adapter does not qualify other native rendering modes, including plan-mode markup removal.
A future integration must bind and qualify its actual session mode before making a redaction claim.
A nonce response or final-text C response therefore cannot qualify the production reconstruction
workflow or close the independent-agent interoperability matrix. An exploratory effectiveness
measurement must retain that distinction and execute independent source/behavior validation.
