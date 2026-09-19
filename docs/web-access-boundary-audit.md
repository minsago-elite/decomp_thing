# D10 local access boundary audit

This audit reviews #161 at implementation checkpoint `4269c51`, with additional
response-level CORS assertions in this PR. It establishes criteria 3 and 5 for the
implemented routes. It does not complete #161 or D10, certify future handlers, or
substitute rejection of remote binding for the planned proxy qualification.

| #161 acceptance criterion | Finding | Evidence and remaining work |
| --- | --- | --- |
| 1. Loopback default; remote exposure requires explicit supported configuration | Partial | Both UI modes validate loopback configuration before listening. Non-loopback startup is denied. The supported authenticated remote profile and its fixture remain #216 work. |
| 2. Session creation/expiry/reauthentication without credential persistence or disclosure | Partial | Shared single-use exchange, digest-only records, monotonic idle/absolute expiry, logout/restart revocation and in-memory CSRF have deterministic tests. Packaged SPA/legacy login and restoration pass. Browser expiry/history-cache lifecycle has controlled-model coverage, not full browser qualification. Explicit local bootstrap fragments are the #149 operator handoff, removed before exchange; they are not query/path credentials. |
| 3. Authorized same-origin mutations and anti-CSRF protection | Satisfied for implemented routes | All four implemented mutation families below use LocalWebAccess. Session exchange is the documented single-use-token exception to cookie/CSRF, not an unguarded mutation. Denied uploads/starts leave job bytes unchanged and invoke no workflow callback. |
| 4. Explicit localhost aliases and supported proxy Host/Origin policy | Partial | Local canonical Host/Origin pairing, explicit aliases, duplicate/oversized headers, cross-site Fetch Metadata and forwarding rejection are tested. No authenticated production proxy is implemented or qualified; #216 remains open. |
| 5. JSON API methods/body types without permissive production CORS | Satisfied for implemented routes | Policy enforces methods and JSON/multipart types before mutation handlers. Known reads use explicit read policies; API negotiation rejects excluded JSON. HTTP tests now assert absence of every Access-Control-* response header across legacy and v1 helpers, including denied responses. |
| 6. Reload/reconnect/downloads share authorization; GET is read-only | Partial | Packaged cookie restoration, polling/recovery and artifact access/revocation pass. HTTP tests cover source/artifact views and unchanged retained bytes. Resumable event-stream/reconnect qualification remains under #174; fixed legacy polling and bounded v1 event pages are not proof of the complete planned stream contract. |

## Implemented mutation inventory

The only HTTP listener is `UploadServer`'s root context. Its legacy router and
`WebApiController.route` own dispatch. Future action, cancellation, deletion and
Git adapters must be audited when added; an unavailable capability is not evidence
that its eventual operation is qualified.

| Mutation family | Route and body type | Authorization before operation |
| --- | --- | --- |
| Session exchange | POST `/api/v1/session` in each mode's base path; JSON | Shared WebSessionController transport preflight, query/Accept checks, then LocalWebAccess validates Origin/body and atomically consumes a bounded one-use operator token. No job operation is called. |
| Session logout | DELETE `/api/v1/session`; JSON | Same shared handler; LocalWebAccess checks cookie, Origin and CSRF before revocation and cookie expiry. |
| Upload | Legacy POST `/jobs`; v1 POST `/api/v1/jobs`; multipart | Both authorize with multipartUpload before passing request bytes to WebJobService. v1 additionally checks idempotency/progress headers; neither upload executes a workflow. |
| Legacy workflow admission | POST `/jobs/J/explore` and `/jobs/J/reconstruct`; JSON | Legacy router calls jsonMutation before service dispatch. The existing service ownership/lifecycle and bounded executor checks still apply. Tests inject inert callbacks. |

Unknown mutation routes pass transport/mutation checks before a miss, or a known
read/public route rejects their method without executing anything. API read routes
explicitly reject mutation methods. This is method rejection, not an alternative
authorization path to a job operation.

## Read and public-route inventory

Legacy dashboard/job/source/artifact views, job/event JSON and namespace misses
require a session before reading private state. Only exact `/login` and the
stylesheet are public reads. `/api/v1/session/csrf` is a private GET with no-store
session projection and JSON negotiation; it cannot mint a session.

SPA assets and allowlisted client shells are public and contain no job state.
All v1 bootstrap, upload-progress, job collection/detail, runs/detail, report,
snapshot/event and artifact-content reads authorize before service access.
Unknown API namespaces also pass access policy before their error response.
These rules do not certify every retained report field, artifact inventory or
future stream implementation; privacy and storage audits retain their own scope.

## Evidence and limits

Relevant HTTP/service tests are `LocalWebAccessTest`, `WebSessionControllerTest`,
`LegacyWebSessionTest`, `UploadServerTest`, `WebApiControllerTest` and the shutdown
fixtures. The complete web/journal selection contains 178 tests. It covers exact
and denied Origins, session/CSRF failures, method/media policy, authenticated
uploads, session-shared reads, no callback on denial, recovery and revocation.
The additional CORS assertions run on the actual responses from the production
local server; a source search alone is not the evidence for this property.

Six tests in `scripts/legacy-session.test.mjs` evaluate the actual embedded script
against controlled responses/timers. They cover expired restoration, timer expiry,
late successful reads, peer-message validation, logout, 401 and page lifecycle.
They do not simulate a production proxy or prove browser scheduling guarantees.

Retained browser evidence:

- [Legacy authentication](evidence/web-legacy-session-browser-20260905.json): inert upload remains uploaded, authenticated polling/reload/recovery and artifact read, logout denies subsequent access.
- [SPA session regression](evidence/web-legacy-session-spa-regression-20260905.json): fragment removal before fetch, cookie attributes/base path, restoration, logout, consumed-token denial and empty browser storage.
- [Legacy invalidation](evidence/web-legacy-session-invalidation-20260905.json): idle peer clears after notification; polling peer without BroadcastChannel clears on a server 401; no peer mutation.

Each browser report identifies its own source/artifact versions. They precede this
assertion/documentation audit; no production behavior changes here. Reports disclose
inert fixtures, test-owned journal/status edits, test-only Chrome --no-sandbox,
unchanged installation and confirmed cleanup. No native analysis, live provider,
remote workflow or third-party target was exercised.
