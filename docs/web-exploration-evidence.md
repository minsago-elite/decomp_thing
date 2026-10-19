# Attempt-bound exploration evidence

Issues: #165 and #170. GET
`/api/v1/jobs/{jobId}/runs/{runId}/reports/exploration` reads only the fixed
`reports/runs/{runId}/exploration.json` namespace after checking the exact durable
job/run association. The shared descriptor-backed reader bounds input to 1 MiB and
checks retained file identity. The endpoint checks the attempt version again after
reading and refuses a changed attempt. It applies session authorization, GET-only
policy, strict no-query/JSON Accept checks and private no-store headers. It never
falls back to legacy shared reports or another attempt's latest output.

Adapter version 1 recognizes the existing unversioned exploration producer and
the versioned observation-failure and preparation-failure records described below. Strict
JSON parsing rejects duplicate fields, excessive structure and invalid values.
Required top-level fields, unsigned counts, candidate-list count, confidence score
range and boolean isolation fields are checked. This is a summary projection, not
complete validation of nested candidate/observation payloads or producer claims.
It does not execute inputs or attest independent containment.

The typed report distinguishes:

- `available`: the known summary can be projected, with `observations` authority.
- `partial`: required producer fields are absent or a known failure
  record reports incomplete work; summary remains null.
- `unsupported`: the declared producer schema or version is not recognized.
- `invalid`: malformed bytes, invalid summary values or parser limits prevent projection.
- `unknown`: the storage reader could not return stable bounded bytes. That reader
  deliberately combines missing/inaccessible/path-change failures; the adapter
  does not infer proven absence from that combined error.

All counts remain decimal strings. The report identity includes a digest of the
observed bytes and is interpreted with its job/run binding. Revision binding is
null because this producer does not attest a source revision. Acceptance is always
`not-evaluated`; confidence and observation breadth never imply equivalence or an
accepted reconstruction. Observed report bytes now have a [digest-bound artifact descriptor and download](web-exploration-artifacts.md). Unreadable bytes retain a null sourceArtifact.

The pinned attempt page offers an explicit Read exploration evidence action.
Opening the attempt does not fetch the report automatically. Each response must
match the requested job, run and report type. Reads abort on navigation/unmount;
missing summaries show limitations instead of zero metrics. Producer-reported
sandboxing/network isolation are labelled as reports, not verified controls.

Verification: 192 frontend tests and 179 web/jobs tests passed, including exact
unsigned counts, malformed/partial/future/duplicate JSON, invalid score/counts,
missing-byte projection, HTTP identity binding and no read-triggered workflow
writes. Component tests verify deliberate reads, response identity rejection,
limitations and abort behavior. The production bundle and distZip passed. Canonical
validation reports, general artifact resolution, proven missing-vs-inaccessible states
and complete evidence navigation remain outstanding.


The actual packaged history-mode journey passed an on-demand exploration read on
an earlier synthetic attempt, using the real authenticated API. It verified the
available observation summary, equivalence limitation and unchanged report bytes,
plus the existing populated-history, session and recovery checks.
[Retained report](evidence/web-exploration-evidence-20260905.json). Pinned Chrome
used test-only --no-sandbox; no fixture execution or acceptance attestation occurred.

## Observation failures

When candidate observation throws an exception, automatic exploration can retain
`schema: "decomp-exploration-failure"`, `schemaVersion: 1` at its existing
`exploration.json` path. The original exception is rethrown immediately: no later
candidate is executed and no confidence score or coverage population is computed.
If retaining the record also throws, that exception is suppressed on the original
failure instead of replacing it or triggering a retry. Successful exploration
keeps the existing unversioned representation.

The bounded metadata-retention callback temporarily consumes an already-set thread
interrupt flag and restores it in a finally block. It does not clear interruptions
around generation, candidate observation or later work. A new interrupt arriving
during retention remains set; a failed write is suppressed without retrying.

The record identifies the baseline or expanded sample and the zero-based failed
input position. Planned and completed sample counts remain separate. Fixed reason
codes distinguish a typed deadline, unavailable sandbox, output limit, unverified
completion, interruption, I/O failure and an unclassified exception. Exit codes
and arbitrary exception messages are never used to infer these categories.
The record does not claim whether an ambiguous I/O error occurred before launch,
inside the program or during cleanup.

When they fit, separate baseline/expanded arrays retain the proposed inputs and
completed observations. Array position joins each observation to its input; a
repeated candidate ID does not merge different sample positions. Detail is bounded
to 1000 inputs per sample, 256 arguments per input, a conservative 1,000,000-byte
JSON estimate and 90,000 detail nodes. These are retention limits, not new proposal
or execution limits. Oversized detail is wholly omitted before JSON allocation;
`details: null` and `detailsOmitted: "detail-budget"` preserve the reason, failed
position and exact counts without inventing missing input/output bytes. Raw
exception messages and stack traces are not included.

The existing read-only endpoint validates this known format and projects `partial`
with producer schema version 1, null numeric summary and the original digest-bound
artifact/attempt links. Coverage and confidence are always null in this record.
Malformed counts, positions, signatures or reason pairs are invalid; future
versions are unsupported. The record remains producer-reported observation data,
without independent containment, source-revision or acceptance authority.

Isolation and coverage flags must be JSON boolean literals; quoted booleans are
invalid rather than coerced. An unknown declared schema remains unsupported even
when it omits a version and otherwise resembles a complete legacy summary.

The structured viewer reads this partial format only when the selected report
declares producer version 1 and partial state. Its existing explicit artifact read
checks attempt/URL binding and observed length/SHA-256 before parsing. Baseline and
expanded sample positions form distinct identities, including repeated candidate
IDs within either sample. Completed observations, the typed failed position and
unobserved positions remain distinct; an observed exit code 124 is not relabelled
as a timeout. Exact planned/completed counts appear separately. The producer's
reason code and the same retained artifact identify the reported failure without
inferring launch, cleanup or containment facts.

The viewer preserves its 1 MiB, depth and preview limits, 1000-input
per-sample limit and 256-argument limit. Filters, 20-row pages and selection only
change the local view. Omitted detail shows exact sample counts and an explicit
unavailable-bytes message rather than an empty or successful sample. Unsupported
or inconsistent formats are refused. Format/artifact/session changes discard
private detail; refresh failures clear previous observations.

Case artifacts use a bounded 100,000-node parser ceiling matching the backend,
so valid details admitted by the producer's conservative 90,000-node budget remain
inspectable. General API JSON retains its 50,000-node default. Both ceilings remain
subject to the same byte/depth limits, duplicate-key refusal and strict values.

## Failures before candidate observation

The existing Angr, static-hint and mutation callbacks can retain a separate
`decomp-exploration-preparation-failure` version-1 partial record when they throw.
Their order and multiplicity are unchanged. The original exception is rethrown
immediately; retention errors are suppressed once and later stages do not run.
Completed proposals still use the original deduplication, candidate cap, observation
calls and successful report writer.

The record names the failed generation stage and reports available provided-seed,
Angr and static-hint counts. An unreturned group is null, distinct from a returned
empty group. The final expanded proposal and sample counts remain unknown.
`observationState: "not-started"` is the producer's pipeline claim, not independent
execution or containment evidence. Fixed generic, I/O and interruption codes use
exception types only; an exit124 or message mentioning timeout supplies no timeout,
tool-availability, launch or cleanup classification. Messages/stacks are omitted.

Optional inputs retain exact reported IDs/sources/argv/stdin bytes under the same
1000-per-group,256-argument,1,000,000-byte/90,000-node conservative retention budget;
oversized detail is wholly omitted before JSON allocation. The existing read-only
adapter and version-one partial viewer validate the separate known namespace,
stage/availability consistency and unknown counts. Stable group/position identities
preserve repeated IDs. The viewer keeps its existing byte/node/preview/page limits,
artifact/attempt/length/digest checks and deliberate read/abort/refresh policy.
Input inspection never presents an exit code, output or observation that this
preparation record does not contain.

Independently established regression origins and broader integration qualification
remain outstanding. The historical verification above covers its recorded source
only; new pure callback/metadata and in-memory fetch/decoder/DOM controls require
their own current Actions evidence.
