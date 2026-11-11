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

Using the repository-pinned Node 24.20.0/npm 11.19.0 toolchain:

- Focused post-commit recovery set: `npm test -- --run tests/display-preferences.test.tsx tests/resilience.test.tsx tests/asset-recovery.test.tsx tests/session-tabs.test.ts tests/session-status.test.tsx` — 5 files, 58 tests passed.
- Full frontend suite — 84 files, 1,194 tests passed.
- `npm run typecheck` — passed; generated web API contracts verified.
- `npm run lint` — passed with zero warnings.
- `npm run build` — passed; bundle limits and module ownership checks passed.

### Packaged two-tab control

- Follow-up source: `19326581a7135e77694f57299569573dfb0b4f3c`.
- The audit opens two targets in the packaged profile, checks both begin at defaults, dispatches
  one rendered-select change in each tab, and retains trusted storage-event, target, rendered
  state, write-count and persisted-record evidence. The verdict fails on missing or divergent
  evidence.
- Focused local control: `node --test scripts/test-packaged-browser-audit.mjs` — 29 tests passed;
  all three changed JavaScript files passed `node --check`; `git diff --check` passed.
- A local packaged Chrome run was not available in this checkout because no Chrome executable
  or packaged runtime archive was present. Exact-head hosted packaged-browser qualification is
  pending; the local control validates report rejection behavior, not real browser event delivery.

The focused tests cover valid cross-tab updates, malformed values, clear events, unrelated
keys, `localStorage` versus `sessionStorage`, no write-back, and a local edit after a missed
event. The packaged audit now includes a two-target browser exchange using DOM-dispatched changes
on rendered selects, trusted `localStorage` events, rendered state, and preference-key mutation
assertions. The scenario runs after the pre-existing audit measurements, then clears its test
record and closes its targets. The select activation is not a trusted keyboard or mouse gesture;
exact-head browser execution is pending. Existing tests cover reload-once version recovery and
concurrent session expiry.

## Limits and remaining acceptance

The current retained test results qualify synthetic `StorageEvent`s in jsdom only; the new
two-tab packaged-browser control has not yet produced hosted evidence. This source slice
does not add new packaged-browser evidence for the second stale-build reload or production
session-expiry paths. Dependencies #159 is closed; #167 and #179 remain open and retain their
respective shell/version and multi-tab/session ownership. Keep #630 and #221 open until their
original criteria and required packaged evidence are satisfied. No production-provider,
workflow-mutation or release qualification is implied.
