# Retained-storage accounting

Issue: [#162](https://github.com/minsago-elite/decomp_thing/issues/162).

`RetainedStorageUsage.measure` supplies a bounded, read-only snapshot for future
storage admission. It is not yet called by HTTP admission and does not establish
the outstanding quota acceptance criterion.

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
