# Attempt-bound exploration evidence

Issues: #165 and #170. GET
`/api/v1/jobs/{jobId}/runs/{runId}/reports/exploration` reads only the fixed
`reports/runs/{runId}/exploration.json` namespace after checking the exact durable
job/run association. The shared descriptor-backed reader bounds input to 1 MiB and
checks retained file identity. The endpoint checks the attempt version again after
reading and refuses a changed attempt. It applies session authorization, GET-only
policy, strict no-query/JSON Accept checks and private no-store headers. It never
falls back to legacy shared reports or another attempt's latest output.

Adapter version 1 recognizes the existing unversioned exploration producer. Strict
JSON parsing rejects duplicate fields, excessive structure and invalid values.
Required top-level fields, unsigned counts, candidate-list count, confidence score
range and boolean isolation fields are checked. This is a summary projection, not
complete validation of nested candidate/observation payloads or producer claims.
It does not execute inputs or attest independent containment.

The typed report distinguishes:

- `available`: the known summary can be projected, with `observations` authority.
- `partial`: required producer fields are absent; summary remains null.
- `unsupported`: an explicit producer schema version is present.
- `invalid`: malformed bytes, invalid summary values or parser limits prevent projection.
- `unknown`: the storage reader could not return stable bounded bytes. That reader
  deliberately combines missing/inaccessible/path-change failures; the adapter
  does not infer proven absence from that combined error.

All counts remain decimal strings. The report identity includes a digest of the
observed bytes and is interpreted with its job/run binding. Revision binding is
null because this producer does not attest a source revision. Acceptance is always
`not-evaluated`; confidence and observation breadth never imply equivalence or an
accepted reconstruction. Raw artifact download and its separate identity resolver
remain unconnected, so sourceArtifact is null and the limitation is visible.

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
validation reports, raw artifact resolution, proven missing-vs-inaccessible states
and complete evidence navigation remain outstanding.


The actual packaged history-mode journey passed an on-demand exploration read on
an earlier synthetic attempt, using the real authenticated API. It verified the
available observation summary, equivalence limitation and unchanged report bytes,
plus the existing populated-history, session and recovery checks.
[Retained report](evidence/web-exploration-evidence-20260905.json). Pinned Chrome
used test-only --no-sandbox; no fixture execution or acceptance attestation occurred.
