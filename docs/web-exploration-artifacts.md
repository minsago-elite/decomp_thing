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
strong-ETag conditional semantics now follow the general artifact reader in
[web-api.md](web-api.md#attempt-artifact-catalog-and-streamed-downloads).
Content is served as an application/octet-stream attachment named exploration.json,
with no-store, no-referrer, nosniff, frame denial and the shared sandboxed inert CSP headers.
The descriptor's application/json is the producer file's media type, not permission
to render it as trusted application content.

The exploration ID uses the same `<family>_<binding>_<sha256>` scheme as the general
artifact catalog. Content is now delivered by its digest-bound pinned stream (#552) instead
of a copied 1 MiB snapshot; the report projection keeps its own 1 MiB read ceiling.

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
