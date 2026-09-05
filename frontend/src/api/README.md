# Versioned client contract boundary

This is the frontend portion of [#159](https://github.com/minsago-elite/decomp_thing/issues/159).
It implements the representative schemas in [the shared v1 contract](../../../contracts/web/v1/contract.schema.json),
not every endpoint reserved by [the API design](../../../docs/web-api.md). It does not implement
HTTP controllers, durable jobs, event subscriptions, uploads, source reads or Git operations.

From `frontend/`, run `npm run api:generate` after an intentional shared schema change;
`npm run api:check` compares deterministic output without writing. Typecheck/build and the contract
test enforce drift checks. The generator accepts only its reviewed draft-07 subset and fails on
new keywords or unsupported forms. It emits TypeScript aliases and the runtime schema from the
same bytes, with their source hash. Runtime validation enforces string bounds, conditional
constraints and evidence relationships that structural TypeScript types cannot express.
No runtime validator package or environment lookup is added.

`decodeResponse(text, kind)` parses bounded JSON, checks the version/kind and known fields, then
returns a typed envelope. Unknown response object fields are discarded recursively, including
inside event variants. They never reach presentation state. Producer fixture checks use
`decodeContract(text, {mode: 'producer'})`, which rejects additional fields. Request encoding
always uses the closed producer schema; the fixture wrapper is removed before sending `data`.
Unknown kinds/event discriminators/adapter versions produce `unsupported_contract`; unknown enums
or other invalid known fields produce `invalid_response`. Neither result can become success or
accepted evidence. Callers retain the previous snapshot as stale and disable dependent mutations;
that state-management behavior belongs to each consuming feature.

The parser rejects duplicate keys, non-finite JSON numbers and malformed Unicode. Defaults cap
JSON at 1 MiB, nesting at 40, values at 50,000 and schema traversal at 250,000 steps. Configured
byte limits can only lower the default. Unsigned 64-bit quantities and addresses stay strings;
event ordering uses `BigInt`. The cross-field checks mirror the shared Python fixture verifier.
The representative report vocabulary recognizes adapter version 1, unversioned legacy exploration
and revision-validation producer version 2. A future producer version must gain reviewed adapter
support; an explicit unavailable/unsupported report may carry its version without a summary.
These client checks validate contract consistency, not the authenticity of execution or acceptance.

`createApiClient({basePath})` uses same-origin `/api/v1` URLs, credentials, JSON negotiation and
`X-Request-ID` correlation. It exposes typed `get`, `post`, `upload` and `deleteSession` calls. `get`/`post`
return the entire typed response envelope. HTTP errors expose `ApiClientError` with a local `code`,
optional HTTP `status`, bounded `requestId` and server `serverCode`; errors omit bodies, URLs,
server messages and tokens. Current mutation requests require explicit in-memory CSRF, an
idempotency key and a strong `If-Match` guard. Single-use session creation and logout are the
specified exceptions to the idempotency/ETag requirement; logout still requires CSRF.

The client performs one fetch per call, with no automatic retries. The default deadline is
30 seconds, configurable up to 120 seconds. It covers fetch and streamed response reads.
Callers pass an `AbortSignal` for obsolete navigation; aborting transport does not cancel a
workflow. Body reads enforce actual byte counts and strict UTF-8, release readers on failure,
and abort/cancel pending reads at the deadline. Redirects and arbitrary origins are rejected.
The client does not persist session material, generate mutation intent, or infer endpoint
capabilities from its available schema types.

The [shared path helpers](../app/paths.ts) implement the frontend URL portion of
[#154](https://github.com/minsago-elite/decomp_thing/issues/154). `appPath` and `apiPath` normalize
the configured prefix, capped at the contract's 256 characters. `apiPath(basePath, route, query)`
takes a route relative to `/api/v1` and decoded query values. Query construction encodes values
once; an already encoded query in `route` is validated and preserved byte for byte. Mixing both
query forms, duplicate keys, malformed escapes, control characters, unsafe numbers and URLs over
4,096 characters is rejected. Resource path segments use the contract's case-sensitive opaque ID
grammar; encoded IDs, dot segments, trailing slashes and arbitrary origins are rejected.

`apiResourcePath` builds identity-bound event, snapshot and artifact-content links.
`validateResourceHref` checks a server link against the caller's configured prefix, resource kind
and exact IDs without rewriting it. Event links allow only one `after` cursor and known polling
options (`transport=poll`, optional `limit` 1–200); snapshot and content links allow no query.
The helper accepts root-relative resource URLs, matching the wire contract, so consumers do not
need to infer or trust an origin from response content. These functions construct and validate
URLs; they do not open a stream, start a download or establish an endpoint capability.

The API client passes its configured prefix into decoding. Standalone decoders default to `/`;
use `decodeContract(text, {basePath: '/nested/'})` or the fourth `decodeResponse` argument for a
nested deployment, including synthetic fixtures. Semantic checks enforce bootstrap prefix identity,
artifact content links (including artifacts nested in reports), and the matching job/run snapshot
link in retention-gap events. A schema-shaped link to another prefix or resource is a decoder
error. Cursors and identity strings are never converted to numbers or decoded recursively.

`tests/api-contract.test.ts` runs all shared positive/negative fixtures, drift and malformed input
checks. `tests/api-client.test.ts` uses in-process synthetic responses for headers, identity,
errors, cancellation, byte bounds and no-retry behavior. These are client tests; they do not replace
golden HTTP/server tests, packaged-browser checks or the remaining #159 endpoint surface.

`upload(file, settings)` sends one browser-owned multipart `binary` part and requires CSRF
and a caller-retained idempotency key. It rejects If-Match because it creates a resource.
The browser chooses the Content-Type boundary; response decoding, byte limits, redirect
rejection and cancellation use the same bounded transport. Only `201 job` confirms upload
publication. Upload views use a 120-second deadline, keep File bytes in memory, and retain one
bounded key/filename/size ticket in tab sessionStorage for explicit retries after reload. The view uses a fresh X-Upload-ID and polls the session-bound uploadProgress endpoint
for actual request bytes received, independently of its durable retry key. Unknown
Content-Length leaves the percentage indeterminate while preserving the byte count.
