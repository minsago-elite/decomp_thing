# Streaming upload and atomic publication checkpoint

The legacy HTTP upload route now streams its one `binary` multipart part into
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
`.upload-*` directory. The publisher independently bounds and hashes the payload,
validates the ELF header through the existing metadata reader, writes final-path
job metadata, syncs both files and the staging directory, then atomically renames
the complete directory to a fresh job ID and syncs the parent. The uploaded binary
retains the existing owner-executable permission; upload itself never executes it.
Identical deliberate legacy uploads create distinct job IDs.

Before-rename errors remove the known staging files and directory. After-rename
errors retain the complete job and report uncertain publication. The service blocks
new work until it is closed and storage is reopened; callers must inspect storage
rather than blindly retry an uncertain upload. This is not idempotent replay.
A process crash may leave an unpublished `.upload-*` directory; those directories
are excluded from job identity enumeration. Crash-orphan maintenance is still
outstanding and is not handled by deleting arbitrary hidden directories at startup.

At most two streaming uploads run per service. Each requires at least 64 MiB of
reported free space at admission. This is a staging headroom check, not a reservation
against unrelated writers or a total retained-data quota. Streaming does not hold the
service monitor, so existing status reads can proceed. Shutdown interrupts upload
threads and retains storage ownership until all of them actually exit, including
when the bounded shutdown wait expires. HTTP request deadlines close stalled bodies.

## Evidence and remaining scope

121 web/jobs tests pass, including multipart split/byte-preservation tests, a 4 MiB
incremental source, actual request ceilings, invalid/multiple parts, UTF-8 display
names, cancellation and sink failure. Publication tests cover visibility only after
rename, invalid ELF, faults before and after rename, complete retained uncertain
results and duplicate-content identity. Service tests cover two concurrent blocked
uploads, responsive status reads, capacity rejection and retained ownership during
an unresponsive upload's shutdown.

This is progress on #162, not its completion. `POST /api/v1/jobs` remains disabled:
durable idempotency receipts/replay, complete request-level authorization and crash
qualification, crash-orphan maintenance, total storage quotas and SPA upload controls
are still required. The existing legacy transport contract is preserved; it is not
substituted for the authenticated v1 mutation boundary.
