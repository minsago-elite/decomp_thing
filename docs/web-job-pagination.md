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
under a short service lock. Rows reflect their individual read time; this is not a
transaction across all job files. Continuations use those retained immutable rows.
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
admission lock. Admission scans at most 10,000 identities with a five-second budget
checked between bounded record reads. Each snapshot retains at most 16 MiB of
serialized row data, with at most 4 KiB per row so a 200-row response fits the
1 MiB transport ceiling; the cache retains at most eight snapshots and 32 MiB of row
data, evicting oldest snapshots first. JVM object overhead is additional. An
excessive library/snapshot returns `503 LISTING_LIMIT`; narrow filters can reduce
retained bytes, but do not remove the scan limit. All resources remain bounded by
the existing API response and per-file read limits.

This is the collection portion of #162. Streaming upload, upload/storage quotas,
a persistent query index beyond the bounded scan profile, and full dashboard
integration remain separate unfinished work within the original D-series scope.
