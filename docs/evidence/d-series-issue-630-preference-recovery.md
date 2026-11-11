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

The focused tests cover valid cross-tab updates, malformed values, clear events, unrelated
keys, `localStorage` versus `sessionStorage`, no write-back, and a local edit after a missed
event. Existing tests cover reload-once version recovery and concurrent session expiry.

## Limits and remaining acceptance

Cross-tab coverage uses synthetic `StorageEvent`s in jsdom. No two-tab packaged-browser run was
performed, so browser delivery of real storage events is not qualified here. This source slice
does not add new packaged-browser evidence for the second stale-build reload or production
session-expiry paths. Dependencies #159 is closed; #167 and #179 remain open and retain their
respective shell/version and multi-tab/session ownership. Keep #630 and #221 open until their
original criteria and required packaged evidence are satisfied. No production-provider,
workflow-mutation or release qualification is implied.
