# Retained-storage accounting

Issue: [#162](https://github.com/minsago-elite/decomp_thing/issues/162).

`RetainedStorageUsage.measure` supplies a bounded, read-only snapshot for future
storage admission. Streaming HTTP uploads use it through `WebUploadStorage`;
workflow report-growth enforcement remains outstanding under the quota criterion.

The caller must hold exclusive root ownership and coordinate writers so the tree
is quiescent. The scan uses pinned Linux directory and entry descriptors, rejects
symlinks, special files, foreign owners and mount crossings, and checks directory
names and selected identities again after traversal. Detected changes fail the
whole measurement; no partial total is returned. These checks do not turn a live
tree into an atomic filesystem snapshot.

Every descendant is included, irrespective of its name: binaries, reports,
receipts, metadata, staging, hidden entries and abandoned temporary files. Charges
are logical lengths, including directory lengths, with hard links charged once per
name and sparse files charged by their full logical extent. The root directory
itself is excluded. This is not physical allocation accounting: filesystem
metadata, extended attributes, compression, copy-on-write sharing and deleted but
open files require separate filesystem capacity controls.

The caller supplies the byte ceiling. Default scan limits are 100,000 descendants,
32 directory levels and a two-second monotonic deadline. Cancellation and the
deadline are checked between filesystem operations; they cannot interrupt a
blocked kernel filesystem call. Arithmetic checks remaining capacity before
adding each charge. Invalid arguments fail immediately; an incomplete scan fails
with `STORAGE_ACCOUNTING_UNAVAILABLE` and preserves all retained data.

Verification: `RetainedStorageUsageTest` covers complete mixed-tree accounting,
exact byte and entry boundaries, sparse files, hard links, dangling symlink
rejection, depth and deadline limits, preserved interrupt status, and unchanged
file contents. This checkpoint does not qualify concurrent writer reservations,
upload admission, report-growth enforcement or status-request responsiveness.

## Upload admission reservations

Streaming upload admission has an 8 GiB logical retained-data ceiling. Embedders
can set `maximumRetainedStorageBytes` on `WebJobService`; the packaged server uses
the default. Each admitted transfer reserves 33 MiB: its 32 MiB maximum request
plus one MiB for the fixed publication metadata and directory entries. A new
reservation must fit both the logical ceiling and current free filesystem space,
with 64 MiB of additional recovery headroom. Denials return `UPLOAD_STORAGE` (HTTP
503) before the service reads multipart bytes. Data is never deleted to make room.

The first upload in an overlapping group measures the whole retained tree.
Subsequent uploads share that snapshot and charge separate reservations. Completed
reservations remain charged until every upload in the group has exited; the next
group measures actual retained bytes again. This deliberately conservative policy
can deny a request even if a completed transfer used less than its reservation.
Failed and replayed uploads release reservations through the same path.

The service registers upload ownership before measuring and releases it after
reservation cleanup. Accounting and streaming run outside the service monitor.
During this interval, new legacy/durable workflows and the compatibility byte-array
upload helper are refused; active workflows also prevent new streamed uploads.
This prevents service-owned report writers from changing the scan. Read-only status
and collection requests remain available. The existing two-transfer ceiling and
bounded HTTP executor still apply. Direct external changes to an owned job root
are unsupported. The byte-array helper is not an HTTP route and has not acquired
the streaming quota contract.

This admission ceiling includes existing reports, but does not yet constrain new
report growth while workflows run. It is therefore not a complete hard quota for
all application writes; #162 remains open for that integration and qualification.

Verification adds reservation overlap/release, exact free-space boundaries,
accounting-error recovery, retained-report refusal before body reads, status reads
during blocked transfers, and mutual exclusion between uploads and workflows.

The packaged upload browser qualification passed against `51ff358`, using the
pinned Chrome driver with test-only `--no-sandbox`. It covered session restoration,
lost-response reload/retry, invalid and oversized request rejection, and a real
throttled transfer cancelled after server-observed bytes followed by same-key retry.
No fixture execution occurred. [Retained report](evidence/web-upload-storage-reservations-20260905.json).
