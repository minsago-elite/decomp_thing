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

The policy is implemented in
[`AcpProviderTransportPolicy.kt`](../src/main/kotlin/decompengine/acp/AcpProviderTransportPolicy.kt), the
routing decisions in [`AcpProviderRouting.kt`](../src/main/kotlin/decompengine/acp/AcpProviderRouting.kt),
the address classes in
[`AcpProviderAddressRegistry.kt`](../src/main/kotlin/decompengine/acp/AcpProviderAddressRegistry.kt), and the
upstream TLS client in [`AcpProviderUpstreamTls.kt`](../src/main/kotlin/decompengine/acp/AcpProviderUpstreamTls.kt).

These are building blocks. Their guarantees take effect only once the #959 broker consumes them.
No production path issues or consumes an approved policy yet. The ACP factory still has no provider
channel, and the contained agent still has no network access.

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
| `model` | One model ID matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` |
| `reasoning` | `MINIMAL`, `LOW`, `MEDIUM`, `HIGH` or `XHIGH` |
| `tlsVerification` | `PLATFORM_TRUST_HOSTNAME_VERIFIED` |
| `privateDestinations` | `DENIED` or `PERMITTED` |
| `addressTranslation` | `NONE` or `WELL_KNOWN_NAT64` |
| `maximumRequestBytes` | 1 to 8 MiB |
| `maximumResponseBytes` | 1 to 64 MiB |
| `maximumHeaderBytes`, `maximumHeaderFields` | 1 to 64 KiB, 1 to 256 |
| `maximumChunkBytes`, `maximumQueuedChunks` | 1 to 64 KiB (and at most the response bound), 1 to 16 |
| `maximumRequests`, `maximumOutputTokens` | 1 to 64, 1 to 65,536 |
| `overallTimeoutMillis`, `idleTimeoutMillis`, `cleanupTimeoutMillis` | 1 ms to 30 min; idle and cleanup at most overall |

`model` is a public model ID, never a credential. Its character set and length bound keep it a
plain identifier: no spaces, slashes, `=` or control characters.

Retries are fixed at zero, outstanding requests at one, and queued requests at zero. There is no
proxy, redirect, WebSocket or base-URL key. A key such as `allowProxy` is refused as unknown.

The runtime adapter is a closed catalog entry. It fixes the single approved endpoint, the operations
it implements, its authentication mechanism and the credential sources it accepts. The operator must
still state the endpoint explicitly, and the endpoint must match the catalog entry exactly. Scheme,
case, port, user info, query, fragment, percent-encoding, dot segments, trailing slash, trailing-dot
host and IP-literal variants are all refused.

`descriptorSha256` is a SHA-256 over a canonical, credential-free listing of every approved field.
Every configurable field changes it. Evidence can retain it as the redacted policy identity. Its
schema label is `acp-provider-transport-policy-v2`, which keeps its digests separate from the
unmerged #1502 draft, whose descriptor had different fields.

## Authentication with a local Codex login

`LOCAL_CODEX_CACHED_AUTH` names the operator's local Codex CLI ChatGPT login cache. The policy holds
only that reference, never a path, token or account identifier. The future host broker (#959)
resolves it outside the analysis sandbox. The agent, analyzed programs, candidate processes,
archives and logs never receive it.

`CHATGPT_CACHED_ACCESS_TOKEN` means the broker uses the cached access token as it is. The transport
never refreshes tokens, so it has no second destination. An expired token is an authentication
failure (#961). The operator renews the login with their own Codex CLI on the host. Hosted CI stays
credential-free: the tests use only synthetic policy values, literal addresses and throwaway
loopback TLS identities.

## Routing

The contained agent talks to a relay over its invocation-bound channel (#959). It never names the
upstream destination. The relay reads the request head, at most `maximumHeaderBytes` bytes up to and
including the empty line, and passes those exact bytes to `AcpProviderRouting.route`. The checks
below run in order, and the relay must send nothing upstream unless the request is admitted.

1. A disabled policy refuses with `TRANSPORT_DISABLED`.
2. The head is parsed strictly under RFC 9112. The byte bound counts the request line, every field
   line and the terminating empty line; too many bytes or field lines is `REQUEST_HEAD_TOO_LARGE`.
   The following are `MALFORMED_REQUEST`:
   - a non-ASCII byte or a bare CR or LF;
   - anything after the first empty line, or leading empty lines;
   - a request line that is not `method SP target SP HTTP/1.1` with single spaces;
   - a non-token method, or a target outside visible ASCII or containing a fragment;
   - obs-fold, whitespace before a field colon, or a non-token field name;
   - any control character other than HTAB, or DEL, in a field value.
3. `CONNECT` with any target: `CONNECT_REFUSED`. Absolute-form (any scheme), authority-form and
   asterisk-form targets: `PROXY_REQUEST_REFUSED`. Any query: `QUERY_REFUSED`.
4. Zero or several `Host` fields, or several `Content-Length` fields: `MALFORMED_REQUEST`. The single
   `Host` value must match RFC 9112 `uri-host [ ":" port ]` with the RFC 3986 grammar, or the request
   is `MALFORMED_REQUEST`. This check is stricter than the grammar: the host must be nonempty, a
   port must be 1 to 5 digits no greater than 65535, and an IP-literal must be an IPv6 address
   (IPvFuture and zone identifiers are refused). The validated value is then discarded; the
   upstream `Host` always comes from the policy.
5. `Transfer-Encoding` (any coding, including `chunked` and `identity`), `TE`, `Trailer`, `Expect` or
   `Content-Encoding`: `REQUEST_FRAMING_UNSUPPORTED`. The only supported body is identity-encoded
   and delimited by one Content-Length.
6. `Forwarded`, `X-Forwarded-*`, `X-Original-*`, `X-Rewrite-URL`, `X-Host`, `X-HTTP-Host`,
   method-override, `Proxy-Authorization` and `Proxy-Connection` fields:
   `ROUTING_OVERRIDE_REFUSED`.
7. `Upgrade`, `HTTP2-Settings`, or `Connection: upgrade`: `PROTOCOL_UPGRADE_REFUSED`.
8. The target must equal the operation's relay path (`/responses`) byte for byte, with no decoding,
   normalization, case folding or prefix match, or the request is refused with
   `OPERATION_UNSUPPORTED`. A different method is refused with `METHOD_UNSUPPORTED`.
9. A missing Content-Length is `REQUEST_FRAMING_UNSUPPORTED`. A value that is not canonical decimal
   (`0` or a nonzero digit followed by at most nine digits; no sign, list, whitespace or leading
   zero) is `MALFORMED_REQUEST`. A length above `maximumRequestBytes` is `REQUEST_BODY_TOO_LARGE`.

An admitted request returns `Routed`, which carries the policy endpoint, the policy descriptor
digest and the validated body length. The upstream host, path and scheme always come from the
policy.

The relay then reads exactly `contentLength` body bytes. It must never forward the client's raw
head, header fields or framing. It rebuilds the upstream request from `Routed.upstreamHeaders()`,
which returns `Host` (the policy host), `Content-Type` and `Accept` (the operation's media types) and
`Content-Length` (the validated length). The broker appends only its own credential headers (#959).
Body content, model and token checks are #960.

Each upstream response status goes through `responseStatusRefusal`. The policy declares no redirect
destinations, so every 3xx response is refused unfollowed with `REDIRECT_UNDECLARED`.

## Destination addresses

`destinationRefusal` checks every address resolved for the approved endpoint before any connection.
If one address is refused, the whole set is refused, so an adapter cannot fall back onto a
host-local destination.

The address classes are pinned to dated IANA registry snapshots, transcribed into
`AcpProviderAddressRegistry.kt` with their source URL and the SHA-256 of the transcribed XML:

- IPv6 Global Unicast Address Space, last updated 2025-10-10 (the ALLOCATED rows);
- IPv6 Special-Purpose Address Space, last updated 2025-10-09 (every row);
- IPv4 Special-Purpose Address Space, last updated 2025-10-09 (every row).

Nothing is fetched at build, test or run time. Updating a snapshot is a reviewed source change.

- **Public IPv4:** any address outside the IPv4 special-purpose registry and multicast (224.0.0.0/4).
- **Public IPv6:** an address inside an ALLOCATED global unicast block and outside every IPv6
  special-purpose row. Gaps between allocations, for example 2001:1000::/23 or 2001:6000::/19, and
  RESERVED space such as 2d00::/8 or 3fff::/20 are refused.
- **Private:** the Private-Use and Shared Address Space rows (10/8, 172.16/12, 192.168/16, 100.64/10)
  and Unique-Local fc00::/7 are admitted only when the operator sets `privateDestinations` to
  `PERMITTED`. This covers deployments where split-horizon DNS resolves the provider host to a
  private address. The permission is never inferred from the endpoint, the agent request or the
  resolved address.
- **IPv4-mapped** addresses are classified as the IPv4 address they carry.
- **Well-known NAT64:** 64:ff9b::/96 is refused unless the operator sets `addressTranslation` to
  `WELL_KNOWN_NAT64`. Even then, only an embedded public IPv4 address is admitted. An embedded
  private or special-purpose address is refused, even when private destinations are permitted.
- **Everything else is refused**, including every other special-purpose row: those that are globally
  reachable (anycast, AS112, AMT, ORCHIDv2) as well as 6to4, Teredo, local-use NAT64,
  documentation, benchmarking, discard and segment routing.

The `addressTranslation` guarantee covers only the well-known prefix. An address synthesized from a
network-specific NAT64 prefix falls inside an allocated global block and cannot be told apart from
native IPv6 by its bytes. The classifier treats it like any other address in that block. Preventing
or classifying network-specific synthesis belongs to the resolver contract (#1510), which also
covers resolution itself.

## TLS and proxies

`AcpProviderUpstreamTls` is the only upstream TLS client, and `connect` is its only entry point. It
builds its own `SSLContext` from a PKIX trust manager initialized with the JVM platform trust store,
which is the standard `javax.net.ssl.trustStore` configuration. No member accepts a trust store,
trust manager, key manager, hostname verifier, TLS context or TLS parameters. Every socket:

- verifies the policy hostname with HTTPS endpoint identification;
- sends the policy hostname as SNI;
- negotiates only TLSv1.3 or TLSv1.2.

`connect` first applies `destinationRefusal` to the given numeric address. It then opens a direct
connection (`Proxy.NO_PROXY`) to port 443 of that address and completes the handshake. The policy
hostname, never the address, stays the TLS identity, so ambient proxy settings and DNS never apply
at this step. A failed check closes the socket.

The handshake tests are credential-free. Throwaway self-signed identities are generated by keytool
at runtime under `build/test-tmp` and deleted afterwards. A loopback server is started in the test
JVM. The client runs in a forked JVM whose only trust customization is the standard
`javax.net.ssl.trustStore` properties. Loopback is not an admissible destination for `connect`, so
the forked probe reaches the private TLS layer by reflection. The production code has no
test-specific trust path. The tests prove four cases:

- platform trust rejects an untrusted chain that names the policy host;
- a configured root does not trust a different chain for the policy host;
- a certificate trusted through the configured root but naming another host is rejected;
- a trusted certificate for the policy host completes a modern handshake, and the server observes
  the policy SNI.

## Not covered here

- The credential broker that applies these checks (#959) is described in
  [the provider credential broker](acp-provider-credential-broker.md).
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
