# ACP provider credential broker

This document covers the host-side broker that holds model-provider credentials and transport authority
for one admitted ACP invocation ([#959](https://github.com/minsago-elite/decomp_thing/issues/959), part of
[#238](https://github.com/minsago-elite/decomp_thing/issues/238)). It consumes the transport policy and
routing checks described in [`acp-provider-transport-policy.md`](acp-provider-transport-policy.md).

The broker is implemented in
[`AcpProviderBroker.kt`](../src/main/kotlin/decompengine/acp/AcpProviderBroker.kt) and
[`AcpProviderCredentialSource.kt`](../src/main/kotlin/decompengine/acp/AcpProviderCredentialSource.kt).
No production path opens a broker yet. The ACP factory still has no provider channel, and the contained
agent still has no network access.

## Opening a broker

`AcpProviderBroker.open` takes the approved policy, the admitted `AgentExecutionRequest`, an operator
credential source and a destination resolver. The caller opens the broker before it starts any ACP session or
prompt. Opening checks these, in order, and refuses with a typed `AcpProviderBrokerFailure` at the first that
fails:

1. The policy must be `Approved`, otherwise `TRANSPORT_DISABLED`.
2. The credential source must match the policy's credential reference and resolve to usable material,
   otherwise `CREDENTIAL_UNAVAILABLE` with the `AcpProviderCredentialFailure` reason. This step makes no
   network request and no resolver call.
3. The resolver resolves the policy host once. Every returned address goes through
   `AcpProviderRouting.destinationRefusal`. If any address is refused, or the resolver is unavailable, the open
   fails with `DESTINATION_REFUSED`.

The first admitted address is pinned for the broker's lifetime as a numeric `InetSocketAddress` on port 443.
Only the address bytes are kept, so nothing later re-resolves the name or makes a reverse lookup. The protected
resolver and its runtime profile are #1510, which is not on master. Until it lands,
`AcpProviderDestinationResolver.UNAVAILABLE` is the production default and the production entry point always
refuses with `DESTINATION_REFUSED`.

## Credential source

`LOCAL_CODEX_CACHED_AUTH` resolves to `AcpProviderCredentialSource.LocalCodexCachedAuth`, which reads
`auth.json` in the operator's Codex home on the host. The operator supplies the Codex home path to the
host broker. The policy never carries it, and neither the agent nor its request can select it. The source is
read again for each broker, so nothing is cached across invocations.

The file must be a regular file, not a symbolic link, at most 64 KiB, and not accessible to its group or to
others. It must be strict UTF-8 JSON with no duplicate keys. Only `tokens.access_token` and the optional
`tokens.account_id` are used. The access token must be a JWT whose `exp` claim is later than the current time.
The signature is not checked: this is a local availability check, and the provider still authenticates the
token. The broker never refreshes the token and never writes the file.

| Failure | Meaning |
| --- | --- |
| `MISSING` | No `auth.json` in the Codex home. |
| `UNREADABLE` | A symbolic link, a non-regular or oversized file, group or other access, or a read error. |
| `MALFORMED` | Not strict JSON, duplicate keys, or a token or account ID with the wrong syntax or no `exp`. |
| `MECHANISM_UNSUPPORTED` | An API-key login, a logged-out cache, or an `auth_mode` other than `chatgpt`. |
| `EXPIRED` | The access token's `exp` is not later than now. |

Failures carry fixed text built from enum names. They never include a credential value or a host path, and
they keep no cause.

## Invocation-bound channel

The broker creates a fresh 32-byte random channel capability. `grantChannel` hands it over exactly once as an
`AcpProviderChannelGrant`, and the grant can only be written to the host-owned private channel stream. It is
never an environment variable, argument or file. Analyzed programs, candidate build and validation processes
and ACP terminal children therefore cannot inherit it through process ancestry or find it through filesystem
visibility. Even a copied capability authorizes nothing without the private channel.

`identity.invocationBindingSha256` binds the policy descriptor digest, the admitted request binding and a fresh
nonce. Two brokers for the same request have different bindings.

Each `AcpProviderChannelRequest` carries the capability in the frame's reserved field, a sequence number, the
exact request-head bytes the contained relay received (ending with the empty line) and the body bytes. `exchange` refuses with `CHANNEL_REFUSED` when the broker is
closed, no grant was made, the capability differs (compared in constant time) or the sequence is not the next
one. One request may be outstanding. A sequence is consumed when the frame is admitted, whether or not the
request is then forwarded, so a refused frame cannot be replayed with a corrected head.

## Forwarding

After the frame is admitted, the request goes through these checks. A request that fails one sends nothing
upstream.

1. `AcpProviderRouting.route` must route the exact head bytes, otherwise `ROUTE_REFUSED` with the routing
   refusal. Routing requires one canonical `Content-Length` and refuses `Transfer-Encoding`, `Expect` and the
   other unsupported framing fields, as well as a declared length above the request bound.
2. The body must be exactly the routed `contentLength`, nonempty, and one strict UTF-8 JSON object with no
   duplicate keys. Otherwise the request is refused with `REQUEST_REFUSED`.
3. A body whose decoded names or strings contain the capability or the access token is refused with
   `SECRET_EXPOSURE`.

The upstream request line is the policy method and endpoint path. Its headers are
`Routed.upstreamHeaders()` (the policy host, the operation's request and response media types, and the
validated `Content-Length`), followed by the broker's own `Authorization` and optional `ChatGPT-Account-ID`
from the credential. No agent header or framing is copied. The validated body is sent as admitted, so the
validated length frames it exactly.

The broker connects through the module TLS client `AcpProviderUpstreamTls`. In production, `connect` opens a
direct `Proxy.NO_PROXY` connection to the pinned address, re-checks it with `destinationRefusal`, and keeps the
policy host as the TLS identity: PKIX platform trust, SNI and HTTPS hostname verification, TLS 1.3 or 1.2 only.
A refused address is `DESTINATION_REFUSED`. A certificate for another name, or from an untrusted issuer, fails
with `TLS_REFUSED` before any request byte is sent. Other connection failures are `TRANSPORT`.

## Responses

The response head must be strict HTTP/1.1, with CRLF line endings, no folded lines, and fields and bytes
within the policy bounds.

- A 3xx status is refused with `REDIRECT_REFUSED` before its headers are read, so no `Location` is parsed or
  followed.
- A 1xx status, including `101 Switching Protocols`, is refused with `MALFORMED_RESPONSE`.
- Any other non-200 status returns only the status. The error body is never read, because it can echo
  request material.
- A 200 response must have exactly one `text/event-stream` content type. Its body may be close-delimited,
  `Content-Length` or chunked without trailers. Anything ambiguous is `MALFORMED_RESPONSE`, and a body larger
  than the response bound is `RESPONSE_TOO_LARGE`.
- A body that contains the capability or the access token is refused with `SECRET_EXPOSURE` and is not
  returned.

The whole body is read before it is returned. Streaming buffers and backpressure belong to #960.

## Sandbox launches

`requireNoProviderAuthority` checks an `AcpSandboxLaunch` for any purpose: agent, terminal, candidate or
analysis. It refuses with `SECRET_EXPOSURE` when the capability or a credential value appears in an argument,
an environment name or value, or the working directory. It refuses with `CREDENTIAL_SOURCE_VISIBLE` when a
read-only mount source, a staging root or the working directory is the credential source, lies inside it or
contains it, including through a symbolic link. The source paths stay protected after the broker closes.

The credential and capability live only in host JVM memory, and upstream sockets are host-owned descriptors
that child processes do not inherit. The integration control starts a child process while an upstream TLS
connection is open and checks that its environment and descriptors contain no token, capability, credential
path or socket.

## Closing

`close` drops the credential, zeroes the capability and closes any in-flight upstream connection. A request on
a closed broker is refused with `CHANNEL_REFUSED`. An in-flight exchange also fails with `CHANNEL_REFUSED`,
whatever I/O error or early EOF the close caused. A close during the TLS handshake takes effect when the
handshake returns or reaches its timeout; prompt revocation is #961.

## Evidence

`identity` holds only the policy descriptor digest, the invocation binding, the request binding digest, the
authentication mechanism and the credential reference. Evidence may retain these. Broker, grant, request and
result `toString` values are redacted.

## Tests

The tests use no real credentials and make no external connection. Hosted CI stays credential-free.

- `AcpProviderCredentialSourceTest` covers each credential failure against synthetic `auth.json` files under
  `build/test-tmp/acp-provider-broker/`.
- `AcpProviderBrokerTest` is the integration control. It uses a synthetic Codex login, and a test CA and leaf
  certificate generated at run time and written under `build/test-tmp/acp-provider-broker/`. A synthetic
  resolver returns a public numeric address. A recording connector connects to a local TLS server on 127.0.0.1
  instead, and then completes the module client's `handshake` with `withTestTrustAnchors`, so certificate and
  host name verification are the production checks. The control shows that:
  - the credential is checked before any resolution or connection;
  - the pinned numeric address is used without re-resolution;
  - SNI and hostname verification use the policy host;
  - redirects are refused without a second connection;
  - the upstream head is exactly the policy-owned headers and the credential headers, and the body is the
    validated body;
  - capability and sequence binding hold;
  - routing, framing and disclosure refusals send nothing upstream;
  - responses are redacted;
  - sandbox launches are checked;
  - a child process inherits nothing;
  - closing aborts an in-flight exchange.

## Not covered here

- Session and turn binding, deadlines, budgets, concurrency and streaming: #960.
- Revocation, stale-channel rejection across restarts and typed provider outcomes: #961.
- Provenance records: #962.
- The contained-side relay that carries channel frames from the sandbox, factory wiring and qualification:
  #963 to #965.
- The protected destination resolver: #1510.
