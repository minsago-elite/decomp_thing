# Server-observed upload progress

Authenticated `POST /api/v1/jobs` accepts an optional `X-Upload-ID` containing 32
lowercase hexadecimal characters. This is a fresh identity for one HTTP transfer,
separate from the durable Idempotency-Key reused for retries. Duplicate progress IDs
within the initiating session return 409 UPLOAD_ID_REUSED without replacing a record.

`GET /api/v1/uploads/{uploadId}` returns the typed `uploadProgress` envelope to that
same authenticated session. Unknown, expired and other-session observations return
404; malformed IDs do not select paths. Reads never admit uploads, initialize storage
or start execution. The endpoint rejects query parameters and uses the existing JSON
negotiation, no-store and correlated-request headers.

The closed data object contains uploadId, receivedBytes, nullable totalBytes, state
and nullable jobId. Byte quantities are canonical unsigned decimal strings. The
counter observes actual request-stream reads below parser buffering, including
multipart headers and delimiters. It can include the single byte that proves an
over-limit request. totalBytes is the declared Content-Length, when present; it is
an advisory denominator and never replaces actual parser limits. Chunked transfers and
declared lengths beyond the supported ceiling have no denominator. Requests pass
through bounded streaming admission rather than rejecting large declared lengths
while the browser is still sending the entire body. The parser stops at the ceiling
plus one rejection byte; arbitrary oversized transfers can still lose their HTTP
response when the connection closes, so retry context remains necessary.

States distinguish receiving, validating, published and unconfirmed. Completing the
multipart parser changes receiving to validating; ELF validation, file/directory
syncing and atomic publication still follow. Only a successful publisher return
(including durable receipt replay) sets published with a jobId. All other returns
are unconfirmed, without a jobId; this does not prove that no job exists after a
publication uncertainty. Progress is not the durable receipt or an execution result.

Observations are in-memory and session-bound, capped at 256 entries. Terminal entries
expire after two monotonic minutes and may be evicted earlier for capacity. Active
entries are never evicted to admit another entry. Full active capacity returns 503.
Restart or renewed sessions do not restore progress; the durable upload retry key
continues to recover admission independently.

The SPA polls after 500 ms and then at most once per second, with one read in flight.
It stops timers and aborts reads when upload settles or the view is destroyed.
Unavailable observations degrade to a waiting message. The UI displays measured
request bytes and separates receiving from validation/publication. Only the validated
POST response navigates to the job; a progress observation never starts a workflow.

[Packaged browser evidence](evidence/web-upload-progress-20260905.json) records measured
partial transfer, cancellation cleanup and same-key retry. See
[upload workbench qualification](web-upload-workbench.md) for test scope and limits.
