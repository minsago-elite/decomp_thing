# D-series #630 cross-tab preference recovery evidence

## Source identity

- Base: `2b1121999c806d5b3f89d3723fca8a39879c49b1` (master at implementation start)
- Implementation: `5bf13187f1a498706961d5788e0c5e5462153724`
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
events, and a later recovered write. The packaged audit includes a two-target browser exchange
using DOM-dispatched changes on rendered selects, trusted `localStorage` events, rendered state,
and preference-key mutation assertions. The scenario runs after the pre-existing audit
measurements, restores the exact preference record found before the scenario, verifies peer
restoration, and closes both targets. Existing tests cover reload-once version recovery and
concurrent session expiry.

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

## Limits and remaining acceptance

The two-tab preference control now has exact-source hosted Chrome evidence, and a test-clock
packaged session-expiry path passed. The retained cross-tab test double still models browser
storage delivery; the hosted Chrome report supplies real-browser evidence for that behavior. This
slice does not add exact-source packaged evidence for the second stale-build reload. It does not
independently qualify Firefox/WebKit storage-event behavior, natural session expiry, or all
version/session combinations. Dependencies #159 is closed; #167 and #179 remain open and retain
their respective shell/version and multi-tab/session ownership. Keep #630 and #221 open until
their original criteria and required integrated packaged evidence are satisfied. No
production-provider, workflow-mutation or release qualification is implied.
