# Digest-bound exploration artifacts

Issues: #165 and #192. Exploration report responses now include a sourceArtifact
when bounded stable bytes were observed, even when those bytes cannot produce a
valid summary. The descriptor identifies the exact observed size and SHA-256,
job/run binding, fixed display name and a server-owned content URL. It is not a
claim that producer observations, isolation or reconstruction were validated.

The opaque artifact ID binds the job and run through a digest and includes the
content SHA-256. It is reproducible across server restart and is interpreted only
under its job URL. The resolver selects a matching retained attempt from the
bounded durable snapshot and opens only its fixed exploration.json namespace.
No supplied artifact ID is decoded into a filesystem path. Unknown/cross-job IDs
return 404. If current bytes have a different digest, the endpoint returns 409
ARTIFACT_CHANGED and requires a refreshed report. It never serves replacement
bytes under the old descriptor. Old bytes are not retained in a separate blob store.

GET/HEAD `/api/v1/jobs/{jobId}/artifacts/{artifactId}/content` requires the existing
private session policy and rejects query parameters. Both methods resolve and
verify the digest; HEAD returns the same Content-Length without a body. Range and
conditional headers are explicitly unsupported and return 400 UNSUPPORTED_HEADER.
Content is served as an application/octet-stream attachment named exploration.json,
with no-store, no-referrer, nosniff and `sandbox; default-src 'none'` CSP headers.
The descriptor's application/json is the producer file's media type, not permission
to render it as trusted application content.

The resolver keeps the existing 1 MiB report read ceiling and copies one bounded
snapshot before the HTTP write. It does not keep a filesystem descriptor open while
a client receives bytes. The existing ordinary HTTP deadline and bounded executor
apply. This is not a general large-artifact streaming implementation; catalog
pagination, large-file streaming/abort qualification and retention leases remain
outstanding under #192/#172.

The attempt evidence view displays exact byte count and SHA-256 and uses a normal
browser download anchor. It does not fetch a whole-file JavaScript Blob. The page
explains that the digest identifies observed bytes without validating producer
claims, and that changed bytes need a refreshed descriptor.

Verification: 192 frontend tests, lint, 180 web/jobs tests, the typechecked bundle
and distZip passed. Tests cover exact-byte resolver output, invalid/cross-job IDs,
replacement refusal, private HTTP authorization, attachment/CSP/nosniff headers,
HEAD size/body semantics and explicit Range refusal. Existing report projection,
history, ownership and bounded-read tests remain green.


The actual packaged history-mode browser journey passed a native anchor download
to a disposable download directory. Saved bytes exactly matched the retained
exploration fixture, the browser stayed on the pinned earlier-attempt URL, and all
retained job/report bytes remained unchanged. Existing history/session/recovery
checks also passed. [Retained report](evidence/web-exploration-download-20260905.json).
Pinned Chrome used test-only --no-sandbox. No fixture execution occurred.
