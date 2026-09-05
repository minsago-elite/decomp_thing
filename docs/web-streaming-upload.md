# Streaming upload and atomic publication checkpoint

The legacy route and authenticated `POST /api/v1/jobs` stream their one `binary` multipart part into
private staging. It no longer buffers the full HTTP body or converts binary data
to text. The compatibility `MultipartUpload.parse(ByteArray, ...)` helper uses the
same parser for existing callers; that helper necessarily still returns a byte array.

The parser bounds the complete request to 32 MiB, headers to 8 KiB and the boundary
to 70 ASCII characters. It counts actual input bytes, including multipart overhead,
regardless of Content-Length. Header decoding is strict UTF-8. Only a single file
part named `binary` is accepted, with Content-Disposition and optional Content-Type;
extra/duplicate headers, extra parts and epilogues are rejected. The display filename
is bounded to 255 characters and stripped of directory components. It never selects
a filesystem path. Browser filenames containing literal percent escapes remain
literal display text; they are not decoded into path syntax.

Delimiter matching preserves binary bytes, including CRLF, trailing `--`, partial
boundary prefixes and boundary-shaped sequences followed by ordinary bytes. Input
and output buffers are each 64 KiB. A receipt contains byte count, SHA-256 and at most
the first 64 payload bytes; it does not certify ELF validity or publish a job.
Cancellation and source/sink failures propagate without a successful receipt.

## Publication and ownership

Under the service's exclusive job-root lease, each upload writes into an owner-only
`.upload-stream-v1-*` directory. The publisher independently bounds and hashes the payload,
validates the ELF header through the existing metadata reader, writes final-path
job metadata, syncs both files and the staging directory, then atomically renames
the complete directory to a fresh job ID and syncs the parent. The uploaded binary
retains the existing owner-executable permission; upload itself never executes it.
Identical deliberate legacy uploads create distinct job IDs.

Before-rename errors remove the known staging files and directory. After-rename
errors retain the complete job and report uncertain publication. The service blocks
new work until it is closed and storage is reopened; callers must inspect storage
before retrying a legacy upload. Authenticated v1 requests can replay their retained
receipt after storage is reopened, including after publication uncertainty.

Both production HTTP adapters return 409 for uncertain publication and retain the
canonical job identity in a `Location` header. Legacy uploads link to `/jobs/{id}`;
JSON includes `job_id`, `job_url` and `retry_upload: false`, while HTML provides a
reconciliation link. Authenticated v1 uploads link to the base-path-aware
`api/v1/jobs/{id}` resource and retain the existing error envelope with
`RECOVERY_REQUIRED`, the job ID in its message and `retryable: false`. Neither
response includes the filesystem exception or a `Retry-After` hint. The job can
remain unavailable through the running service until storage is reopened; a link
is reconciliation evidence, not confirmation of successful publication. Further
uploads and workflow admission remain fenced during that uncertainty.

A process crash may leave an unpublished `.upload-stream-v1-*` directory; those directories
are excluded from job identity enumeration. [Startup staging recovery](web-upload-staging-recovery.md)
now reconciles the reserved private namespace under the exclusive lease, after bounded
identity/type checks. Unexpected entries are preserved and reported explicitly.

At most two streaming uploads run per service. Each requires at least 64 MiB of
reported free space at admission. This is a staging headroom check, not a reservation
against unrelated writers or a total retained-data quota. Streaming does not hold the
service monitor, so existing status reads can proceed. Shutdown interrupts upload
threads and retains storage ownership until all of them actually exit, including
when the bounded shutdown wait expires. HTTP request deadlines close stalled bodies.

## Authenticated upload and retries

The v1 endpoint requires a current browser session, exact request origin, CSRF token,
JSON response negotiation and one `Idempotency-Key` of 16–128 ASCII letters, digits,
underscores or hyphens. It rejects query parameters and If-Match. Content-Length is
validated when present; the parser enforces the actual complete-body ceiling for
chunked requests too. Bootstrap advertises the 32 MiB complete-request limit.
Successful admission returns `201 job` and a base-path-aware Location, without execution.

Keys belong to the authenticated local owner, shared by that owner's browser sessions,
so a renewed session after server restart can retry. A hash binds the key to the owner,
POST method and canonical v1 collection target. The first 128 hash bits select the job
identity; the full hash is checked in the receipt, so a collision fails without replacement.
The request intent includes normalized display filename, actual payload size and SHA-256;
multipart boundary changes do not change intent. A different key deliberately creates a
new job for identical content. A reused key with different intent returns 409.

The original job representation and hashes are synced in `upload-receipt.json` alongside
job metadata before their shared directory rename. Same-key concurrent admissions are
serialized at publication under the exclusive root owner. A retry stages and hashes the
body, then returns the original `201 job` and `Idempotency-Replayed: true`, even if live
status has changed. Missing or inconsistent retained records return 503 without replacing
the existing job. Keys are not consumed by validation failures before publication.
Receipts currently remain with jobs indefinitely (at least the contract's 24-hour minimum).
Future application deletion must retain tombstones through that minimum; deletion and
receipt expiration are not implemented. Manual removal of storage is outside this guarantee.

## Evidence and remaining scope

At the authenticated upload checkpoint, all 126 web/jobs tests passed, including multipart split/byte-preservation tests, a 4 MiB
incremental source, actual request ceilings, invalid/multiple parts, UTF-8 display
names, cancellation and sink failure. Publication tests cover visibility only after
rename, invalid ELF, faults before and after rename, complete retained uncertain
results and duplicate-content identity. Service tests cover two concurrent blocked
uploads, responsive status reads, capacity rejection and retained ownership during
an unresponsive upload's shutdown.

Additional tests cover authenticated chunked HTTP admission, origin/CSRF rejection,
original-response replay after status changes, changed-content/filename conflicts,
concurrent same-key publication, corrupt receipts, post-rename retry and a real server
restart with a fresh authenticated session.

This is progress on #162, not its completion. Process-kill staging recovery is now
qualified, and the SPA upload journey is complete under #169. Total retained-storage
quotas remain outstanding.
The existing legacy transport contract is preserved.

The distribution build and [packaged session smoke](evidence/web-upload-receipt-session-20260905.json)
passed with pinned Node 24.20.0, JDK 21 and the isolated test browser run with
`--no-sandbox`. This smoke checks session/dashboard/Runtime behavior and the advertised
upload ceiling; upload/replay itself is verified by the HTTP and storage tests above.


Retained-storage upload admission now uses [bounded accounting and reservations](web-retained-storage-accounting.md). This supersedes the initial free-space-only admission described above; workflow report-growth enforcement is still outstanding.
