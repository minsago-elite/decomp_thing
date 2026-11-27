# D-series #630 cross-tab preference recovery evidence

## Source identity

- Base: `2b1121999c806d5b3f89d3723fca8a39879c49b1` (master at implementation start)
- Implementation: `5bf13187f1a498706961d5788e0c5e5462153724`
- Audit-control follow-up: `7cb077910aff5e9b4c508693e175fa2215d60446` (test-only)
- Scope: cross-tab display-preference convergence in the browser shell
- Related contract: [#630](https://github.com/minsago-elite/decomp_thing/issues/630), child of [#221](https://github.com/minsago-elite/decomp_thing/issues/221)

The component listens for local-storage events for its versioned preference key and clear
events. It re-reads the bounded schema, updates the in-memory controls and document theme, and
does not write in response. A later local field edit merges with the latest valid stored record,
which also recovers if a tab missed an event. Malformed or cleared records converge to defaults.
Events from `sessionStorage` and unrelated keys are ignored.

## Verification

The hosted `Frontend contracts and bundle` job passed on the PR source tree. Its retained JUnit
artifact contains 1,199 tests, 0 failures and 0 errors; the generated asset manifest and pinned
toolchain identity are retained with it (details below).

### Packaged two-tab control

- Follow-up source: `19326581a7135e77694f57299569573dfb0b4f3c`.
- The audit opens two targets in the packaged profile, checks both begin at defaults, dispatches
  one rendered-select change in each tab, and retains trusted storage-event, target, rendered
  state, write-count and persisted-record evidence. The verdict fails on missing or divergent
  evidence.
- The exact PR source was exercised by hosted Chromium through CDP. Two same-origin tabs began at
  `system/system`; a change in tab 1 propagated `dark` to tab 2 through a trusted `localStorage`
  event without a receiver write, and a change in tab 2 propagated `reduce` to tab 1. Both tabs
  rendered `dark/reduce`. Cleanup restored the original preference record and peer state, closed
  both targets, and reported no cleanup failures.
- This verifies browser storage-event delivery in Chrome for the packaged audit. The select changes
  are DOM-dispatched rather than trusted keyboard or mouse gestures. Firefox and WebKit run the
  broader engine journey, but explicitly opt out of this DevTools-only cross-tab evidence.

The focused tests cover valid cross-tab updates, malformed values, clear events, unrelated
keys, `localStorage` versus `sessionStorage`, no write-back, a local edit after a missed event, and
preservation of tab-only choices across failed updates and resets, missed or delivered storage
events, and a later recovered write. The audit-driver tests execute the actual cleanup expression
against a modeled `localStorage` for both an initially absent key and a pre-existing record; they
do not assign the expected value unconditionally in the mock. The packaged audit includes a two-target browser exchange
using DOM-dispatched changes on rendered selects, trusted `localStorage` events, rendered state,
and preference-key mutation assertions. The scenario runs after the pre-existing audit
measurements, restores the exact preference record found before the scenario, verifies peer
restoration, and closes both targets. Existing tests cover reload-once version recovery and
concurrent session expiry.

The audit-control follow-up ran `node --check scripts/test-packaged-browser-audit.mjs` and
`node --test scripts/test-packaged-browser-audit.mjs` locally: 32 passed, 0 failed. It changes
only the test model; it does not alter the packaged browser implementation. Hosted browser evidence
below remains bound to the preceding production/driver tree, and CI for the follow-up source is
required before treating the new test as hosted-qualified.

## Hosted evidence and source binding

- PR: [#1945](https://github.com/minsago-elite/decomp_thing/pull/1945), source head
  `39a5b02db2e22816745dd7ac4b6c30935b8d974e`.
- CI run: [43062382861](https://github.com/minsago-elite/decomp_thing/actions/runs/43062382861).
  Its executed merge candidate is `ed03f018b974f71c7f2d47bd5d05b9e313166441`, with parents
  `2b1121999c806d5b3f89d3723fca8a39879c49b1` and the PR head above. Both have tree
  `1806cd89b568e9834273281fcc07569fd6b4241e`, binding the hosted evidence to the PR source.
- Packaged Chrome artifact: [13875211461](https://github.com/minsago-elite/decomp_thing/actions/runs/43062382861/artifacts/13875211461).
  The audit report SHA-256 is
  `edf9108fd74d37999595c0cacbfe8cab9c23d0faf621bff0af3ad2829166aad4`. It records
  `status=passed`, no audit failures, Chrome `149.0.7827.55`, base path `/nested/`, build ID
  `1ef08163318bde904d7942af41964d04920de56be55149b7e832fecc85c7f4f8`, archive SHA-256
  `05dc5e29557f4f0cf4c57b71b33dd49822c32816a2e7033be73c96e6a87a9690`, and application JAR
  SHA-256 `c39448b9e26683e502a642d5199c5219ff64285eb505b00f80d508e9da486bfe`. The report confirms
  installation integrity, work-directory cleanup and browser shutdown.
- Frontend artifact: [13872939481](https://github.com/minsago-elite/decomp_thing/actions/runs/43062382861/artifacts/13872939481).
  `component-tests.xml` SHA-256 is
  `3ebf7c82533dc82bd0ba66f74ddef86deca8f9511c0755d9c3a0e62c0936f0f4`; the suite records
  1,199 tests with 0 failures/errors. The artifact also retains the generated asset manifest and
  toolchain identity.
- Packaged expiry artifact:
  [13873903905](https://github.com/minsago-elite/decomp_thing/actions/runs/43062382861/artifacts/13873903905).
  Its JSON evidence SHA-256 is
  `1ae98518ee449ae88326cdad8da02dcb0b771bdf8e51807b5dd8d66cf8725f86`; the packaged browser
  expiry selection reports 3 passed and 0 skipped. It uses a test-controlled clock and a real
  browser/server path; it is not a natural eight-hour wait or independent idle-versus-absolute
  expiry qualification.
- Cross-engine artifact:
  [13874891670](https://github.com/minsago-elite/decomp_thing/actions/runs/43062382804/artifacts/13874891670).
  Firefox report SHA-256 is `2293f43f876bcfb9953f82b4365e98aa5897b0b362ef0c9533a1d1b52a14d0d7`;
  WebKit report SHA-256 is `3c89bae611060b44b957e90ba7eda82e433bf4986fb114c3863920c7beb12ddc`.
  Both passed against the same build ID, but explicitly omit cross-tab preference evidence.
- The exact-head workflow was still in progress when this evidence was recorded. Frontend,
  packaged-browser, cross-engine, Kotlin-oracle and other listed lanes had passed; `kotlin-core`
  and `kotlin-live` failed before their intended qualification completed. The core lane timed out
  installing sandbox-host packages and produced no test execution. The live ACP preflight exceeded
  its 25-second sandbox-launch deadline while preparing a large snapshot. `clang` remained in
  progress at the time of capture. These results do not constitute an all-green workflow.

### Exact-head follow-up: repeated stale-shell recovery

- PR source head: `01f5e330b01773bb954994d376dd459905517af7`; CI run
  [43069616345](https://github.com/minsago-elite/decomp_thing/actions/runs/43069616345).
  The executed merge candidate `9b26d693b1ffbbec3bbb706a49c9ac716eeeef05` has the PR base
  `2b1121999c806d5b3f89d3723fca8a39879c49b1` and this head as parents. Both commits have tree
  `f922781811fee5b95bb7633bc3398f6086cfb78e`.
- In this run, the `Frontend contracts and bundle` and `Packaged web contracts and browser` jobs
  passed, as did `Packaged cross-engine journeys`, `kotlin-live`, `kotlin-live-fulltree`,
  `kotlin-oracle`, `clang`, `archival-ghidra`, and `bundled-ghidra`. The overall workflow concluded
  with failure because `kotlin-core` failed the unrelated test
  `OwnedExplorationProcessTest > a descendant its parent never reaps cannot hang cancellation()`
  at `OwnedExplorationProcessTest.kt:103`; the shard reports 3,002 tests, one failure and 15
  skipped. The PR diff contains no Kotlin source or test changes. Aggregate `kotlin` consequently
  failed. These failures do not negate the passing frontend and packaged browser jobs, but the
  overall PR check is not green.
- The packaged artifact is
  [13877408374](https://github.com/minsago-elite/decomp_thing/actions/runs/43069616345/artifacts/13877408374).
  Its audit report SHA-256 is
  `3b410efa287b21530b3c7661772b9fe85d63d49572c88c4eae0f2772443d288a`. It reports `passed`,
  Chrome `149.0.7827.55`, build ID
  `1ef08163318bde904d7942af41964d04920de56be55149b7e832fecc85c7f4f8`, archive SHA-256
  `e516b35ef0005fd8040e87e51cc265cff7a083dff2ec100dfb96b44a8509b52b`, and application JAR
  SHA-256 `37e9d27236f212ec83fb0295483455b4f49c8440866c4ab29767cf3683559a59`. The report contains
  the two-tab preference exchange, trusted same-origin storage events, exact-record restoration,
  peer restoration, target closure, and no cleanup failures.
- The same artifact records the `session` journey: the stale-shell fixture rewrote exactly two
  packaged HTML document responses to use the stale UI-build metadata. The first mismatch offered
  one explicit reload without automatic reload; the repeated mismatch showed manual guidance and
  no reload button. There were zero mutation and external requests. This is a metadata-only shell
  control, not a complete historical bundle or CDN/proxy cache test. Its report SHA-256 is
  `d2ed3235ace5707f96de9ac209469728ea0c8c792a14939cacc543092032e78d`.
- The current-run frontend artifact is
  [13877571562](https://github.com/minsago-elite/decomp_thing/actions/runs/43069616345/artifacts/13877571562).
  Its component-test XML SHA-256 is
  `cbb6e2a9673b7ff592d767621c103b5b9e92175257ce679ad2455638ff090296`; it records 1,199 tests,
  zero failures and zero errors, including 26 display-preference tests. The packaged expiry
  artifact is [13877343049](https://github.com/minsago-elite/decomp_thing/actions/runs/43069616345/artifacts/13877343049);
  its JSON SHA-256 is `270b9d972341a92912c0811a232ffa6314952c01cbdea0971e73c39a12db6c1b`.
  Natural session expiry and independent idle-versus-absolute expiry remain unqualified.
- The exact-current-head Firefox/WebKit run is
  [43075068111](https://github.com/minsago-elite/decomp_thing/actions/runs/43075068111), artifact
  [13882456969](https://github.com/minsago-elite/decomp_thing/actions/runs/43075068111/artifacts/13882456969).
  It ran PR head `bf235fc424e03456804882a109205d12d99065ba`.
  The Firefox 146.0.1 report SHA-256 is
  `cba8bb1cabcef520c56d882ee649542dd26808d9bc887eabe55339c538d7dae7`; the WebKit 26.0 report
  SHA-256 is `e69d8b686be3560f3fd8bac8315f3dfca89b0f459391a8bb6e9b11574622e826`. Both reports
  use build ID `1ef08163318bde904d7942af41964d04920de56be55149b7e832fecc85c7f4f8`, show no audit
  failures, and confirm work cleanup. The engine runner explicitly omits the Chrome-only
  cross-tab preference audit.

## Limits and remaining acceptance

The two-tab preference control, repeated stale-shell retry, and test-clock packaged session-expiry
path have exact-source hosted Chrome evidence. The retained cross-tab test double still models
browser storage delivery; the hosted Chrome report supplies real-browser evidence for that
behavior. The stale-shell fixture rewrites only the UI-build metadata in two actual packaged HTML
responses and checks the one-reload/manual-guidance transition. It does not serve a complete
historical bundle or qualify a real CDN/proxy cache. This slice does not independently qualify
Firefox/WebKit storage-event behavior, natural session expiry, or all version/session combinations.
Dependencies #159 is closed; #167 and #179 remain open and retain their respective shell/version
and multi-tab/session ownership. Keep #630 and #221 open until their original criteria and required
integrated packaged evidence are satisfied. No production-provider, workflow-mutation or release
qualification is implied.
