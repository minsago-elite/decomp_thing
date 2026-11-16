# #1056 local packaged source-tree evidence

This is fixture-level local evidence for the source-tree browser path. It does not
qualify hosted CI, production workloads, or completion of #1056, #625, or #220.

## Source and package binding

- Base: PR #1937 checkpoint `b97f96712caa3afcb712f5f97b8303bcb4205d39`.
- Tested implementation commit: `20302fee2110dc7e6505dee6ef28663ce0b7405f`.
- Tested implementation tree: `32965cc72571c95cc70ecac8adfff0681bc34bd3`.
- `git archive` SHA-256 for that commit: `ede73a568fff61040633f593fd255dc8fafb080bb1f4a316df2348dbffb47c4a`.
- Distribution ZIP SHA-256: `f4b738fc6f9835505c6070190e93c92c13edd3d7c5f3482fe2c946d143900c3d`.
- Application JAR SHA-256 inside the ZIP:
  `45292f034ba8191109fa5f0a8538294bbec333eab84e4c024e3da1f93620c803`.
- Frontend build ID: `f12f2619b0a8b37890e024453573f10b51aa7ddb800079232c3e328f71b4fcb4`.
- Chrome SHA-256: `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`.
- Node/npm: 24.20.0 / 11.19.0; Java: Temurin 21.0.12.1+1.

Both browser runs used the same freshly built ZIP and exact implementation commit.
The driver reports `driverCommit: null` because the package was built from a
Git archive; `workflowSha` was also null because these were local runs. The
commit and driver hashes below bind the source independently.

| Driver | SHA-256 |
|---|---|
| `scripts/check-packaged-web-browser.mjs` | `1315e83139706fcd34104af1a25ab973751207e19666c4c4013b8e3e4121152d` |
| `scripts/packaged-browser-source-tree.mjs` | `aaeb82a9f5ed8c8b7c5f19e5a0a57483cf75a69b8a91b6d9fc7f19078e3cc196` |
| `scripts/packaged-source-tree-fixture.mjs` | `d4f01b9d64496bf1cac93330d3f33cf487c5238beec1c5e642a464c6931468e8` |

## Run results

The final candidate passed all 13 gates in both profiles. Reports:

- Loopback report SHA-256: `89c2c308734aa67e8f9d1dc29cda8dca6bdfe5b84464c07272d1b4cad1b1ad5e`.
- Constrained report SHA-256: `f09d1154bee10c032f8fda74dc06e3c9d0d21e0233237d59289c4e4df34f003e`.

| Measurement | Loopback | Constrained | Limit |
|---|---:|---:|---:|
| First directory page p95 (10 samples) | 411.75 ms | 901.47 ms | 500 ms / 1,000 ms |
| First preview chunk | 109.43 ms | 203.85 ms | 500 ms |
| Local feedback p95 (50 interactions) | 11.8 ms | 23 ms | 100 ms |
| Slowest common/rare/missing search first page | 1,980.95 ms | 1,606.52 ms | 2,000 ms |
| Browser heap after browsing | 1,978,336 B | 1,977,912 B | 134,217,728 B |
| Server process-tree RSS growth | 197,386,240 B | 200,007,680 B | 268,435,456 B |
| Maximum mounted rows | 50 | 50 | 500 |
| Maximum directory rows | 50 | 50 | 50 |
| Maximum API response | 15,163 B | 15,163 B | 1,000,000 B |
| Maximum search response | 20,690 B | 1,911 B | 1,000,000 B |
| Maximum request head estimate | 665 B | 665 B | 8,192 B |
| Maximum URL length | 466 chars | 466 chars | 4,096 chars |
| Rare query elapsed through completion (including continuations) | 1,741.23 ms | 1,612.43 ms | 10,000 ms |

The constrained profile applies fourfold browser CPU throttling, 100 ms round-trip
latency, 10 Mbit/s download and 2 Mbit/s upload. Each run traversed all 500
directory pages / 25,000 files with stable ordering and keyboard navigation,
opened a file and its first bounded preview chunk, and ran common, rare and
missing searches. The search first-page gate now uses the maximum of the first
response durations for all three queries. Local feedback is measured from
keyboard activation until the source view visibly announces “Loading recorded
inputs”; page data readiness is separately measured by the first-page metric.
The cancellation probe submits a pending search and leaves its view through the
application's in-app Runtime route, exercising the route unmount and transport
abort. It does not assert that server-side work stopped after disconnect.

The fixture contains inert files and invoked no compiler or credentials. The
packaged `web` launcher used `-Xmx256m` and `-XX:ActiveProcessorCount=4`; those
options apply to all work performed in the web process and are part of the
candidate.

## JVM checks

Against parent implementation commit `da1a3342abd2a3692962ab276ff2b61cef1ddc4f`,
the selected JVM suite completed with 243 tests, 1 skipped, 0 failures, and 0
errors. `distZip` passed for the tested commit `20302fee`; its build ran the pinned
frontend toolchain verification and completed the frontend contracts, typecheck,
lint, frontend build, Kotlin compilation and distribution packaging. The small
source-tree Node suite passed 4/4 on the final driver.

## Limits

These are local fixture results, not a hosted Actions run. The browser journey
uses a warmed packaged JVM; it is not a fresh-process cold-load measurement.
The 256 MiB web heap cap was exercised for this fixture, not qualified for every
web workflow or production workload. No production ACP-provider, long-session,
power-loss, or real-project qualification is claimed. Attempt-scoped child-JVM
workers remain unimplemented because descendant termination and parent-death
cleanup have not been proved on supported hosts.

## Exact-head hosted packaged evidence (2026-11-09)

GitHub Actions run [42625438851](https://github.com/minsago-elite/decomp_thing/actions/runs/42625438851)
completed successfully for PR #1937 head
`f4895018a8d48b9f225c06c9a9434e014aece815`. The packaged browser reports identify
checkout commit `0ff82c9a00db556b38aebd9363d7388fd23e9d38`; its parents are base
`2b1121999c806d5b3f89d3723fca8a39879c49b1` and that PR head. I independently
matched the three source-tree driver SHA-256 values in both reports to the files
at that merge commit.

The `packaged-web-verification` artifact (artifact ID `13680136585`) contains
reports `packaged-browser-7DlSRV/report.json` and
`packaged-browser-BripZ5/report.json`. Both report `status: passed` and all 13
source-tree budget checks passed:

| Measurement | Loopback | Constrained | Limit |
|---|---:|---:|---:|
| First data page p95 (10 samples) | 300.99 ms | 848.08 ms | 500 ms / 1,000 ms |
| First preview chunk | 91.34 ms | 224.67 ms | 500 ms |
| Local feedback p95 | 4.3 ms | 16.3 ms | 100 ms |
| Slowest search first page | 1,639.58 ms | 1,628.54 ms | 2,000 ms |
| Browser heap peak | 28,360,104 B | 25,447,288 B | 134,217,728 B |
| Application process-tree RSS growth | 212,467,712 B | 221,741,056 B | 268,435,456 B |
| Maximum mounted / directory rows | 50 / 50 | 50 / 50 | 500 / 50 |
| Maximum API / search response | 15,163 / 20,679 B | 15,163 / 20,690 B | 1,000,000 B each |
| Maximum request head / URL | 668 B / 466 chars | 668 B / 466 chars | 8,192 B / 4,096 chars |
| Search continuation elapsed | 3,601.50 ms | 4,139.71 ms | 10,000 ms |

Both journeys traversed all 500 pages and 25,000 files in stable order. The
reports record zero RSS sampling errors. The distribution ZIP SHA-256 is
`25e5cdc9c1d4ba160a2af5f6ed8eca265a2877824e68bed3794f30f35b14dbc6`; the
application JAR SHA-256 is
`4c6016f0aea5e4463d19d2229eea2ae4a97c48c4aa3597ee64f6c8c57c7cd815`. Both
used Chrome 149.0.7827.55 (SHA-256
`2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`) and the
same frontend build ID recorded above.

Report SHA-256 values:

- Loopback: `f4d3b6151c22064bee72b703d810b7297da5b6ba208aec7a406fa0eede5e4635`.
- Constrained: `7f0f849de264f3dcd64dca298a7eb9fb40e9e491f93850bb5ccb8fb6ffd0fa3d`.

This is exact-merge-candidate hosted evidence for the packaged 25,000-file
journey. It is one journey per profile, not the documented 20 fresh-process
cold-load protocol. It does not qualify production trees, all web workflows
under the web JVM heap cap, or long-session behavior. The reports also record
browser-observed request cancellations; the passing resource gates do not prove
that server work stopped after client disconnect. Keep #1056, #625 and #220 open
until their full acceptance scope is independently satisfied.
