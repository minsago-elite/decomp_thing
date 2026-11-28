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

The read is bound to pinned inodes, not to names. The broker opens the Codex home's real path as a directory
descriptor, and `auth.json` below it as an `O_PATH` descriptor without following a link. Every check runs on
those pinned inodes:

- The directory is owned by the broker's user and not writable by its group or others.
- The file is a regular file, owned by the broker's user, not accessible to its group or others, and has
  exactly one link, so no other name exposes the same inode.

The pinned file is then reopened non-blocking through its descriptor, its identity is checked again, and it is
read within 64 KiB. A name swapped after the checks, including for a FIFO, cannot supply other bytes or block
the read. The file must be strict UTF-8 JSON with no duplicate keys. Only `tokens.access_token` and the optional
`tokens.account_id` are used. The access token must be a JWT whose `exp` claim is later than the current time.
The signature is not checked: this is a local availability check, and the provider still authenticates the
token. The broker never refreshes the token and never writes the file.

| Failure | Meaning |
| --- | --- |
| `MISSING` | No `auth.json` in the Codex home. |
| `UNREADABLE` | A symbolic link, FIFO or other non-regular file, an oversized file, another owner, group or other access, a second link, a directory others can write, or a read error. |
| `MALFORMED` | Not strict JSON, duplicate keys, or a token or account ID with the wrong syntax or no `exp`. |
| `MECHANISM_UNSUPPORTED` | An API-key login, a logged-out cache, or an `auth_mode` other than `chatgpt`. |
| `EXPIRED` | The access token's `exp` is not later than now. |

Failures carry fixed text built from enum names. They never include a credential value or a host path, and
they keep no cause.

The access token is key material. The account ID is not, but it identifies the operator's account and is
sent only upstream, so the broker treats it as secret too: it is matched in request bodies, responses and
sandbox launch inputs exactly like the token. The resolved credential also records where it came from: the
device and inode keys of the file, its directory and every ancestor of that directory, and the file's size and
SHA-256, for the launch checks below. None of these is secret, and they outlive the credential.

The owner the checks expect is the broker's own user. A test control injects another owner to show that a
cache owned by someone else is refused; production always uses the process's own user.

## Invocation-bound channel

The broker creates a fresh 32-byte random channel capability. `deliverChannelCapability` writes it once to the
host-owned private stream to the contained relay, and the broker takes ownership of that stream and closes it on
`close`.

- The stream is reserved under the broker lock, so a failed delivery cannot be retried on another stream. A
  second delivery, or one after close, is refused with `CHANNEL_REFUSED`.
- The write happens outside the lock that `close` needs, so a stream that never drains cannot stop `close` from
  revoking and zeroing the capability. `close` also closes the stream, which unblocks the write.
- The stream is handed a temporary copy, never the broker's own array, and the copy is zeroed after the write.
- If the write does not finish within the policy idle bound, a watchdog closes the stream.
- Delivery is committed only if the write finished first and the broker is still open. Otherwise the stream is
  closed and delivery is refused for good.

The capability is never an environment variable, argument or file. Analyzed programs, candidate build and
validation processes and ACP terminal children therefore cannot inherit it through process ancestry or find it
through filesystem visibility. Even a copied capability authorizes nothing without the private channel. Until
the contained-side relay is wired, the private stream is whatever the caller passes; this checkpoint does not
yet attach it to a real sandbox descriptor.

`identity.invocationBindingSha256` binds the policy descriptor digest, the admitted request binding and a fresh
nonce. Two brokers for the same request have different bindings.

Each `AcpProviderChannelRequest` carries the capability in the frame's reserved field, a sequence number, the
exact request-head bytes the contained relay received (ending with the empty line) and the body bytes. A
capability field that is not exactly 32 bytes is refused with `CHANNEL_REFUSED` when the frame is decoded.
`exchange` refuses with `CHANNEL_REFUSED` when the broker is closed, no capability was delivered, the capability
differs (compared in constant time) or the sequence is not the next one. One request may be outstanding. A sequence is consumed when the frame is admitted, whether or not the
request is then forwarded, so a refused frame cannot be replayed with a corrected head.

## Forwarding

After the frame is admitted, the request goes through these checks. A request that fails one sends nothing
upstream.

1. `AcpProviderRouting.route` must route the exact head bytes, otherwise `ROUTE_REFUSED` with the routing
   refusal. Routing requires one canonical `Content-Length` and refuses `Transfer-Encoding`, `Expect` and the
   other unsupported framing fields, as well as a declared length above the request bound.
2. The body must be exactly the routed `contentLength`, nonempty, and one strict UTF-8 JSON object with no
   duplicate keys. Otherwise the request is refused with `REQUEST_REFUSED`.
3. A body whose decoded names or strings contain the capability, the access token or the account ID is refused
   with `SECRET_EXPOSURE`.

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
within the policy bounds. Every byte of the head, including the final LF, counts against the head bound.

- A 3xx status is refused with `REDIRECT_REFUSED` before any header is parsed, including `Location`, so none
  is followed.
- A 1xx status, including `101 Switching Protocols`, is refused with `MALFORMED_RESPONSE`.
- Any other non-200 status returns only the status. The error body is never read, because it can echo
  request material.
- A 200 response must have exactly one `text/event-stream` content type and identity content coding: any
  `Content-Encoding` other than `identity` is `MALFORMED_RESPONSE`, so the bytes checked are the bytes the agent
  decodes. Its body may be close-delimited, `Content-Length` or chunked without trailers. Anything ambiguous is
  `MALFORMED_RESPONSE`, and a body larger than the response bound is `RESPONSE_TOO_LARGE`.
- Before release, the body is parsed as the event stream the agent will consume. It must be strict UTF-8 with
  LF or CRLF line ends and no byte-order mark, contain only `data`, `event`, `id` and `retry` fields or
  comments, end every event with an empty line, and carry one strict JSON object as each event's data.
  Anything else is `MALFORMED_RESPONSE`.
- The supported Responses event shapes are checked for the fields a consumer reads:
  - text, refusal, reasoning and argument deltas need a string `delta`;
  - `response.output_text.done` and the reasoning `.done` events need a string `text`;
  - the function-call and MCP argument `.done` events need a string `arguments`;
  - output item events need an `item` object with a string `type`, and string `arguments` when present;
  - response lifecycle events need a `response` object;
  - optional `item_id` values must be strings, and indexes non-negative integers.
  Other event types are allowed and scanned generically.
- The capability, the access token and the account ID are matched in the raw text, every field value and
  comment, and every decoded JSON name and string. A string that is itself a JSON object or array is decoded
  one layer further and scanned again. That covers function-call and MCP `arguments` and MCP `output`, in
  deltas, in `*.done` events and in completed items, including the final text and arguments in
  `response.completed`.
- Deltas are joined as a consumer joins them, per event type and `item_id`, and for content deltas per
  (`item_id`, `content_index`) or (`item_id`, `summary_index`). When those keys are absent the deltas join in
  arrival order, because Codex emits text deltas without indexes. All deltas are also joined in arrival order.
  Each joined value is matched as text and, when it is JSON, one decoded layer further.
- So JSON escapes such as `\u0074`, secrets inside argument JSON, and values split across one item's deltas with
  unrelated events in between are caught. A match is `SECRET_EXPOSURE`, and the body is zeroed and not returned.

This scan is defense in depth against accidental reflection of the credential, such as a provider error or a
model echoing a header. It is not a defense against an adversarial provider, and no pattern scan can be,
because such a provider could encode the value, for example in base64. The approved provider is inside the
trust model. The primary guarantee is structural: the agent never holds the credential and never receives it
through the broker interface. The credential lives only in the host broker and is written only into upstream
request headers.

The whole body is read before it is returned. Streaming buffers and backpressure belong to #960. Compatibility
with the real Codex gateway's event framing, such as its terminal event and any keepalive comments, is
qualified later with the real-agent lane (#964).

## Sandbox launches

`requireNoProviderAuthority` checks an `AcpSandboxLaunch` for any purpose: agent, terminal, candidate or
analysis.

- **Secrets.** It scans every input that becomes the sandbox argv, environment or mount set: the command,
  environment names and values, the working directory, both sides of every read-only mount, the staging roots
  and the empty directories. If the capability, the access token or the account ID appears in any of them, the
  launch is refused with `SECRET_EXPOSURE`.
- **Host sources.** It checks every host source the launch makes visible (mount sources and staging roots) with
  `requireEffectiveLaunchCarriesNoProviderAuthority`, below. The working directory is a sandbox path, so it is
  only checked by path against the credential source.

`requireEffectiveLaunchCarriesNoProviderAuthority` takes the final effective argv (for example a boundary's
bubblewrap command with its bind paths), environment and host sources. A boundary calls it before those inputs
reach a command observer or launch evidence. It scans the argv and environment for secrets, then checks each
source, and it fails closed:

- The source must resolve to a real path. A source that cannot be resolved is refused with
  `LAUNCH_SOURCE_UNVERIFIED`; a resolution error never counts as admission.
- A source that is, contains or lies inside the credential source by lexical or real path is refused with
  `CREDENTIAL_SOURCE_VISIBLE`.
- The source is walked without following links, within the boundary's existing runtime-closure limits
  (100,000 entries and depth 64 by default).
  - Every entry's device and inode is compared with the credential file and its directory, and the source
    itself also with their ancestors. A match anywhere below the source, such as a hard link to `auth.json` in
    an unrelated directory or an alternate bind, is refused with `CREDENTIAL_SOURCE_VISIBLE`.
  - An entry that cannot be read, a tree beyond the entry limit, or a directory at the depth limit is refused
    with `LAUNCH_SOURCE_UNVERIFIED`.

The path and identity checks stay in force after the broker closes. The secret checks stop then, because the
broker no longer holds the values.

Two further entry points bind the check to the exact objects a boundary mounts:

- `requirePinnedSourcesExcludeCredential` takes the descriptors the boundary pinned for its sources. It checks
  each one's identity has not changed, then walks the pinned object through its descriptor, not through a name.
  The boundary must hold those descriptors open from this check until the mount.
- `credentialForbiddenRuntimeFiles` returns the credential file as a `ForbiddenRuntimeFile` (device, inode,
  size and SHA-256). The boundary's own pin-time source walk, `PinnedReadOnlyMount.pin` through
  `buildRuntimeManifest`, refuses an entry with the same inode, or with the same size and digest. So a hard link
  or a byte-identical copy below a mount is refused when the boundary pins the object it actually mounts.

**Deferred: boundary wiring.** No boundary calls these checks yet, because no factory path opens a broker. The
`LinuxBubblewrapBoundary` integration that lands with the contained-side relay must do three things:

- call `requireEffectiveLaunchCarriesNoProviderAuthority` on its final bubblewrap argv, environment and sources
  before its command observer and launch evidence;
- call `requirePinnedSourcesExcludeCredential` with the descriptors it pinned, held until the mount;
- merge `credentialForbiddenRuntimeFiles` into the forbidden set it passes to `PinnedReadOnlyMount.pin`.

Descriptor isolation and host `/proc` isolation through the real boundary are qualified then too.

The credential and capability live only in host JVM memory, and upstream sockets are host-owned descriptors
that child processes do not inherit. The integration control starts a child process while an upstream TLS
connection is open and checks that its environment and descriptors contain no token, capability, credential
path or socket.

## Closing

`close` drops the credential, zeroes the capability, closes the private channel stream and closes any in-flight
upstream connection. A request on
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
  `build/test-tmp/acp-provider-broker/`. Its race controls swap the name after the pinned checks, for a
  world-readable replacement file and for a FIFO, and show that the pinned bytes are read without blocking.
- `AcpProviderBrokerTest` is the integration control. Each scenario runs in a fresh JVM with an empty
  environment apart from a fixed `PATH`, its temporary directory under `build/`, and one trust customization:
  the standard `javax.net.ssl.trustStore` properties. They name a test CA generated at run
  time under `build/test-tmp/acp-provider-broker/`, so the broker uses the module TLS client's production
  platform-trust code, and the test JVM's own trust is never changed. Each scenario uses a synthetic Codex
  login and a synthetic resolver that returns a public numeric address. A recording connector connects to a
  local TLS server on 127.0.0.1 instead. A loopback server is not an admissible `connect` destination, so the
  connector reaches the client's private layered handshake by reflection, as the #958 TLS probe does.
  Certificate checks, SNI and host name verification are therefore the production code. The control shows
  that:
  - the credential is checked before any resolution or connection;
  - the pinned numeric address is used without re-resolution;
  - SNI and hostname verification use the policy host, and platform trust without the test root refuses;
  - redirects are refused without a second connection;
  - the upstream head is exactly the policy-owned headers and the credential headers, and the body is the
    validated body;
  - the capability is delivered once to a broker-owned stream, never again, and is erased on close;
  - a delivery blocked on a stream that never drains cannot stop `close`, and the idle bound closes it;
  - capability and sequence binding hold;
  - routing, framing and disclosure refusals send nothing upstream;
  - responses are redacted, including escaped and split echoes, and the event stream and content coding are
    strict;
  - sandbox launches are checked, and the source walk fails closed and finds a hard link below an unrelated
    mount, through a path, a pinned descriptor and the boundary's own forbidden-file walk;
  - secrets inside function-call and MCP argument JSON, and secrets split across one item's deltas with
    unrelated events in between, are caught;
  - a child process inherits nothing;
  - closing aborts an in-flight exchange.

## Not covered here

- Session and turn binding, deadlines, budgets, concurrency and streaming: #960.
- Revocation, stale-channel rejection across restarts and typed provider outcomes: #961.
- Provenance records: #962.
- The contained-side relay that carries channel frames from the sandbox, factory wiring and qualification:
  #963 to #965.
- The protected destination resolver: #1510.
