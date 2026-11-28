# ACP model-provider transport policy

This document covers the typed, immutable policy for the restricted model-provider transport
([#958](https://github.com/minsago-elite/decomp_thing/issues/958), part of
[#238](https://github.com/minsago-elite/decomp_thing/issues/238)). The policy states which provider
destination and operations a contained ACP agent may reach, how the transport authenticates, and the
limits that apply. The later issues in the chain enforce it: the credential broker
([#959](https://github.com/minsago-elite/decomp_thing/issues/959)), budgets
([#960](https://github.com/minsago-elite/decomp_thing/issues/960)), revocation
([#961](https://github.com/minsago-elite/decomp_thing/issues/961)) and provenance
([#962](https://github.com/minsago-elite/decomp_thing/issues/962)).

The policy and routing decisions are implemented in
[`AcpProviderTransportPolicy.kt`](../src/main/kotlin/decompengine/acp/AcpProviderTransportPolicy.kt) and
[`AcpProviderRouting.kt`](../src/main/kotlin/decompengine/acp/AcpProviderRouting.kt). No production path
issues or consumes an approved policy yet. The ACP factory still has no provider channel, and the
contained agent still has no network access.

## Default and approval

`AcpProviderTransportPolicy.DISABLED` is the default. A disabled transport refuses every route,
response and destination check before inspecting it.

An `Approved` policy can only be issued from explicit operator policy. The operator boundary,
`fromOperatorPolicy`, takes canonical string fields. Every field is required. Unknown keys, unknown
enum values and noncanonical numbers are refused, and nothing is defaulted or inferred. Failure
messages never repeat a field value and keep no exception cause, so a secret pasted into the wrong
field is not copied into logs.

| Key | Accepted values |
| --- | --- |
| `mode` | `disabled` (no other key allowed) or `approved` |
| `runtimeAdapter` | `CODEX_GATEWAY_RESPONSES_V1` |
| `endpoint` | `https://chatgpt.com/backend-api/codex/responses`, exactly |
| `operation` | `RESPONSES_CREATE` |
| `authenticationMechanism` | `CHATGPT_CACHED_ACCESS_TOKEN` |
| `credentialReference` | `LOCAL_CODEX_CACHED_AUTH` |
| `model` | One identifier matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` |
| `reasoning` | `MINIMAL`, `LOW`, `MEDIUM`, `HIGH` or `XHIGH` |
| `tlsVerification` | `PLATFORM_TRUST_HOSTNAME_VERIFIED` |
| `privateDestinations` | `DENIED` or `PERMITTED` |
| `maximumRequestBytes` | 1 to 8 MiB |
| `maximumResponseBytes` | 1 to 64 MiB |
| `maximumHeaderBytes`, `maximumHeaderFields` | 1 to 64 KiB, 1 to 256 |
| `maximumChunkBytes`, `maximumQueuedChunks` | 1 to 64 KiB (and at most the response bound), 1 to 16 |
| `maximumRequests`, `maximumOutputTokens` | 1 to 64, 1 to 65,536 |
| `overallTimeoutMillis`, `idleTimeoutMillis`, `cleanupTimeoutMillis` | 1 ms to 30 min; idle and cleanup at most overall |

Retries are fixed at zero, outstanding requests at one, and queued requests at zero. There is no
proxy, redirect, WebSocket or base-URL key. A key such as `allowProxy` is refused as unknown.

The runtime adapter is a closed catalog entry. It fixes the single approved endpoint, the operations
it implements, its authentication mechanism and the credential sources it accepts. The operator must
still state the endpoint explicitly, and the endpoint must match the catalog entry exactly. Scheme,
case, port, user info, query, fragment, percent-encoding, dot segments, trailing slash, trailing-dot
host and IP-literal variants are all refused.

`descriptorSha256` is a SHA-256 over a canonical, credential-free listing of every approved field.
Evidence can retain it as the redacted policy identity. Its schema label is
`acp-provider-transport-policy-v2`, which keeps its digests separate from the unmerged #1502 draft,
whose descriptor had different fields.

## Authentication with a local Codex login

`LOCAL_CODEX_CACHED_AUTH` names the operator's local Codex CLI ChatGPT login cache. The policy holds
only that reference, never a path, token or account identifier. The future host broker (#959)
resolves it outside the analysis sandbox. The agent, analyzed programs, candidate processes,
archives and logs never receive it.

`CHATGPT_CACHED_ACCESS_TOKEN` means the broker uses the cached access token as it is. The transport
never refreshes tokens, so it has no second destination. An expired token is an authentication
failure (#961). The operator renews the login with their own Codex CLI on the host. Hosted CI stays
credential-free: the tests use only synthetic policy values and literal addresses.

## Routing

The contained agent talks to a relay over its invocation-bound channel (#959). It never names the
upstream destination. `AcpProviderRouting.route` checks each request head the relay receives, in
this order, and refuses before anything is forwarded:

1. A disabled policy refuses with `TRANSPORT_DISABLED`.
2. More header fields or head bytes than the policy bounds: `REQUEST_HEAD_TOO_LARGE`. A non-token
   method or header name, control or non-ASCII characters, or a fragment: `MALFORMED_REQUEST`.
3. `CONNECT` with any target: `CONNECT_REFUSED`. Absolute-form (any scheme), authority-form and
   asterisk-form targets: `PROXY_REQUEST_REFUSED`. Any query: `QUERY_REFUSED`.
4. Zero or several `Host` headers, several `Content-Length` headers, or `Content-Length` together
   with `Transfer-Encoding`: `MALFORMED_REQUEST`. The single `Host` value is otherwise ignored.
5. `Forwarded`, `X-Forwarded-*`, `X-Original-*`, `X-Rewrite-URL`, `X-Host`, `X-HTTP-Host`,
   method-override, `Proxy-Authorization` and `Proxy-Connection` headers:
   `ROUTING_OVERRIDE_REFUSED`.
6. `Upgrade`, `HTTP2-Settings`, or `Connection: upgrade`: `PROTOCOL_UPGRADE_REFUSED`.
7. The target must equal the operation's relay path (`/responses`) byte for byte, with no decoding,
   normalization, case folding or prefix match, or the request is refused with
   `OPERATION_UNSUPPORTED`. A different method is refused with `METHOD_UNSUPPORTED`.

An admitted request routes to the policy endpoint with the policy descriptor digest. The upstream
host, path and scheme always come from the policy.

Each upstream response status goes through `responseStatusRefusal`. The policy declares no redirect
destinations, so every 3xx response is refused unfollowed with `REDIRECT_UNDECLARED`.

## Destination addresses

`destinationRefusal` checks every address resolved for the approved endpoint before any connection.
If one address is refused, the whole set is refused, so an adapter cannot fall back onto a
host-local destination. IPv4-mapped, NAT64 well-known-prefix and 6to4 addresses are classified by
the IPv4 address they embed.

- Public unicast addresses are admitted.
- Private addresses (10/8, 172.16/12, 192.168/16, 100.64/10 and IPv6 ULA fc00::/7) are admitted
  only when the operator sets `privateDestinations` to `PERMITTED`. This covers deployments where
  split-horizon DNS resolves the provider host to a private address. The permission is never
  inferred from the endpoint, the agent request or the resolved address.
- Loopback, unspecified, link-local (including 169.254.169.254), multicast, broadcast, reserved,
  benchmarking, documentation, IETF-protocol (Teredo, ORCHID) and IPv6 addresses outside 2000::/3
  are always refused.

Resolution itself is not part of this policy. The resolver and its runtime profile are tracked
separately in #1510.

## TLS and proxies

`upstreamSslParameters` derives the upstream TLS parameters from the JVM defaults: HTTPS
endpoint identification, SNI set to the policy host, and TLSv1.3 or TLSv1.2 only. It fails if
neither protocol is available. `requireMandatoryUpstreamTls` refuses parameters without HTTPS
identification, with other protocols or with another server name. It also refuses whenever the
`jdk.internal.httpclient.disableHostnameVerification` JVM property is present, whatever its value.

The adapter must use the platform PKIX trust store and connect directly (`Proxy.NO_PROXY`). Ambient
proxy settings never apply.

## Not covered here

- Credential resolution, the relay listener and the upstream HTTP client: #959.
- Request body, model and token checks, plus enforcement of the byte, time and count limits: #960.
- Revocation and typed provider outcomes such as authentication failure or timeout: #961.
- Provenance records: #962.
- Fixture and real-agent qualification, operator setup and preflight: #963, #964 and #965.
- A `providerTransport` section in the ACP provisioning document. The schema-2 document has no
  provider setting, so production configurations cannot select an approved policy.

Open PR [#1502](https://github.com/minsago-elite/decomp_thing/pull/1502) holds the earlier draft of
this policy together with a broker, framing protocol and native guardian. This module keeps that
draft's names, endpoint, enums and bounds so the draft can rebase onto it. It omits the draft's
credential-free fixture authority and factory permits, which belong to #959 and #963.
