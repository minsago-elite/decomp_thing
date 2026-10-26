# Job collection pagination

`GET /api/v1/jobs` is an authenticated, no-store read. It returns the shared `jobs`
envelope and never starts a workflow. Root and nested deployments use the same
versioned route. It accepts these query parameters exactly once:

| Parameter | Meaning |
| --- | --- |
| `search` | Case-insensitive display-filename substring, at most 256 characters |
| `status` | One exact public job status |
| `createdAfter` | Inclusive RFC3339 creation instant |
| `createdBefore` | Exclusive RFC3339 creation instant |
| `sort` | `newest` (default) or `oldest`, by creation instant then job identity |
| `limit` | 1–200 records, default 50 |
| `cursor` | Opaque continuation from this collection |

Unknown/duplicate filters, malformed encodings, invalid date ranges and invalid
limits return `422 VALIDATION_FAILED`. Clients repeat the same filters, sort and limit
when following a cursor. Search case and equivalent date offsets normalize to the
same query. Jobs sort by creation instant and then job identity, both descending for `newest`
and ascending for `oldest`. Sort is part of the cursor-bound query.

The first read captures existing job identities and copies each job's presentation
using short service-state checks around the metadata reads. Rows reflect their
individual read time; this is not a transaction across all job files. Continuations use those retained immutable rows.
New uploads and subsequent status changes therefore cannot insert, reorder or
replace rows midway through pagination. Deleting a job does not erase its retained
historical row; follow-up detail reads still check current storage authority.
A malformed/unavailable record fails collection admission with its safe diagnostic,
rather than disappearing silently. The legacy dashboard retains isolated diagnostic
rows; extending the collection schema to present partial results is not claimed.

Cursors use a process-keyed signature and bind the retained snapshot to the
browser session and normalized query, including page size. Tampered or mismatched
cursors return `400 INVALID_CURSOR`. Snapshots expire after two minutes or earlier
under capacity pressure; valid expired cursors return `410 CURSOR_EXPIRED` and
require a fresh collection read. A process restart invalidates the signing key,
so old cursors return `400 INVALID_CURSOR`. No cursor grants authentication.

One new snapshot is admitted at a time. A competing admission returns
`503 LISTING_BUSY`; retained continuations and single-job reads do not share that
admission lock. Admission first counts every root entry, including names that are
not job identities: at most 10,512 entries and 10,000 matching job identities are
accepted before metadata reads begin. Workflow inspection and the later legacy
presentation read share one 64 MiB actual metadata-read budget. The first incomplete
physical read latches refusal before another read; an exhausted allowance cannot
start another read. Existing descriptor checks and per-file bounds remain, with
at most one physical overflow byte before refusal.

The same five-second deadline reaches root enumeration and bounded metadata-read
units. It is checked after collection, including empty or fully filtered results,
after sorting, and before snapshot publication. These cooperative checks cannot
preempt blocked kernel I/O. They do not hold the service monitor across it either:
the v1 collection and the legacy HTML dashboard capture the monitor-guarded service
state for one record (publication failure, store owner, legacy task) in a short
section, then read that record's metadata under the attempt store's per-job stripe
lock only; the job store's listing read takes no store monitor, and its descriptor
checks refuse a record replaced during the read. This removes the listing's direct
service-monitor hold, but does **not** establish unrelated-request responsiveness
under blocked I/O (#162). Distinct jobs can share one of the 64 attempt-store stripes.
A detail or command request can acquire the service monitor and then wait behind a
listing-held stripe, blocking otherwise unrelated status reads and upload admission.
Scheduler sampling remains monitor-free. The existing concurrency test covers only
another job on a distinct stripe with no same-stripe detail/command contender; it
does not qualify this remaining convoy or same-record-only blocking.

Before publishing a row, the service rechecks shutdown, storage ownership,
publication failures and task identity. A legacy admission changes an identity token,
so even a start and finish wholly within a row read invalidate that observation.
This token conservatively invalidates in-flight rows on any legacy admission without
retaining per-job history. Changed observations are refused with
`JOB_RECORD_UNAVAILABLE` (a diagnostic row on the dashboard; collection admission
fails), rather than combining a new queued record with a pre-admission task flag or
retrying reads outside the original budget. A fresh read may observe the new state.
`WebJobServiceTest` covers both projections with a deferred legacy task and with a
task that finishes before the paused presentation read resumes.
Each snapshot retains at most 16 MiB of
serialized row data, with at most 4 KiB per row so a 200-row response fits the
1 MiB transport ceiling; the cache retains at most eight snapshots and 32 MiB of row
data, evicting oldest snapshots first. JVM object overhead is additional. An
excessive scan time/snapshot returns `503 LISTING_LIMIT`; root-entry, identity or
metadata-byte exhaustion returns `503 STORE_LIMIT`. An incomplete physical read
returns a fixed unavailable diagnostic. Narrow filters can reduce
retained bytes, but do not remove the scan limit. All resources remain bounded by
the existing API response and per-file read limits. SPA startup selects the same
10,512-entry/10,000-job library capacity, while retaining its separate 64 MiB read
and 64 MiB encoded recovery-plan limits. The legacy startup profile remains 4096
root entries. This preserves libraries seeded before SPA startup as well as those
uploaded after initialization; the profile is retained for lazy storage creation.

Streaming upload admission and the retained-storage quota are described in the
upload documents; uploads refuse before consuming a body when the quota cannot hold
a reservation, while listings stay readable. A persistent query index beyond the
bounded scan profile is not provided.
