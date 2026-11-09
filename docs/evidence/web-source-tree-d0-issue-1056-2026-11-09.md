# #1056 local packaged source-tree evidence

This is fixture-level local evidence for the source-tree browser path. It does not
qualify hosted CI, production workloads, or completion of #1056, #625, or #220.

## Source and package binding

- Base: PR #1937 checkpoint `b97f96712caa3afcb712f5f97b8303bcb4205d39`.
- Implementation commit: `da1a3342abd2a3692962ab276ff2b61cef1ddc4f`.
- Implementation tree: `c2503c30ae04dc9916228736bc8e74bc35bb08e6`.
- `git archive` SHA-256 for that commit: `723abc8b39b5378408914614327c8afe4bdf1ed41929c6742f054d6b01bc88ca`.
- Distribution ZIP SHA-256: `24de58b7e542e7d9dd7972a519818e96229f64ad813641a215be132fa81f3dc8`.
- Application JAR SHA-256 inside the ZIP:
  `ee4334ca0bdc9f578888904555642fd388f906f2a6b985a607daee7623944568`.
- Frontend build ID: `f12f2619b0a8b37890e024453573f10b51aa7ddb800079232c3e328f71b4fcb4`.
- Chrome SHA-256: `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`.
- Node/npm: 24.20.0 / 11.19.0; Java: Temurin 21.0.12.1+1.

The two passing browser report SHA-256 values are:

- `0ca0f1b894849bf35674bd4a3d5334915aa83584cc07c9af27d25b31da328767`
- `5cd7efee405dfebb2c63574b8a286a8b8d4ca400378c6c9d6bb2969c986e6817`

The source-tree driver hashes recorded by both reports are:

- `check-packaged-web-browser.mjs`: `3b579720e3997dff20c87bca856e667fb615d94dd1cf58eed283cc78e954a0db`
- `packaged-browser-source-tree.mjs`: `5e361ee3d1c9b33cbcaf2d38573473dafe7dcf414ecd6558707ba324aadd765e`
- `packaged-source-tree-fixture.mjs`: `d4f01b9d64496bf1cac93330d3f33cf487c5238beec1c5e642a464c6931468e8`

## Run results

Two consecutive source-tree browser runs against the same freshly built ZIP
passed all twelve budgets. Selected measurements:

| Measurement | Run 1 | Run 2 | Limit |
|---|---:|---:|---:|
| First data page p95 | 321.38 ms | 427.78 ms | 500 ms |
| First preview chunk | 200.36 ms | 205.41 ms | 500 ms |
| Common-query first page | 286.56 ms | 322.98 ms | 2,000 ms |
| Browser heap | 1,972,296 B | 1,972,828 B | 134,217,728 B |
| Server process-tree RSS growth | 188,317,696 B | 231,985,152 B | 268,435,456 B |
| Rare search to final file | 1,716.97 ms | 1,655.99 ms | 10,000 ms |

The other six checks also passed in both reports: 50 mounted rows (limit 500),
50 directory rows (limit 50), 15,163 B maximum API response (1,000,000 B),
20,690 B maximum search response (1,000,000 B), 665 B request-head estimate
(8,192 B), and a 466-character maximum URL (4,096).

Both journeys traversed all 500 pages and 25,000 files, checked stable ordering
and keyboard focus, opened a file and its first bounded preview chunk, ran
common/rare/missing searches, and exercised browser navigation cancellation.
The fixture contains inert files and invoked no compiler or credentials. The
packaged `web` launcher used `-Xmx256m` and `-XX:ActiveProcessorCount=4`; this is
part of the candidate and affects all work performed in the web process.

These reports predate the follow-up search/interaction gate: their two-second
search check covered only the common query, and they did not record local
feedback for 50 interactions. The follow-up adds those checks and runs the
constrained profile as well; these older reports should not be used as evidence
for those requirements.

An earlier invocation of the same ZIP traversed all 500 directory pages but
failed the driver's 10-second wait for a completed preview-chunk network event.
The UI had displayed the preview, but the browser event was recorded as aborted
during cleanup. That report is retained with SHA-256
`c5bd7345b33089aad01c4bbecc072b3e429b498f2ed183b7a9eff7b1195b29c0`; two
immediate unchanged reruns passed the complete gate. This intermittent
observation is disclosed rather than counted as a passing run.

## JVM checks

Against the same implementation commit, the selected JVM suite completed with
243 tests, 1 skipped, 0 failures, and 0 errors. The run covered filesystem
syscalls, job storage, JSON parsing, source-tree/catalog capture, search,
pagination, output encoding, and packaged CLI launcher behavior. `distZip` also
completed successfully.

## Limits

These are local fixture results, not a hosted Actions run. The browser journey
uses a warmed packaged JVM; it is not a fresh-process cold-load measurement.
The client navigation test proves stale browser work is discarded, not that
server processing stopped. The 256 MiB web heap cap was exercised for this
fixture, not qualified for every web workflow or production workload. No
production ACP-provider, long-session, power-loss, or real-project qualification
is claimed. Attempt-scoped child-JVM workers remain unimplemented because
descendant termination and parent-death cleanup have not been proved on
supported hosts.
