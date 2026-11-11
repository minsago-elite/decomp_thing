# #628 route failure-state extension — 2026-11-12

Source checkpoint: `48da5630de3394c176a9714781647093dab75d25` on PR #1946.

This checkpoint extends the focused #628 work in four areas:

- Dashboard listing errors use the shared failure classifier, fixed messages, validated correlation references, and explicit empty/partial-result behavior; the route's forms and navigation remain available after failure.
- `RunHistory` is now the fifth route in the shared failure-class matrix. The matrix exercises session, denied, missing, unsupported, corrupt/unverified, and server failures; checks fixed copy and correlation-reference behavior; rejects protocol diagnostics; and verifies route headings and main navigation remain available.
- Runtime storage and maintenance reads use the shared failure classifier. Their six failure classes have distinct fixed messages, validated reference IDs are retained, and errors use an alert. A `PanelBoundary` isolates storage-panel render faults while preserving the runtime identity and capability sections.
- The dashboard refresh regression binds its URL cursor through a non-retainable read failure, then proves an explicit refresh can publish a new first-page cursor.

## Verification at the source tree for this checkpoint

- `frontend`: `npm test -- --run` — 84 test files passed; 1,201 tests passed.
- `frontend`: `npm run build` — generated API drift check, TypeScript, ESLint, production bundle, and bundle budgets passed.
- Focused coverage: `resilience.test.tsx`, `panel-isolation.test.tsx`, `storage-summary-format.test.tsx`, `job-dashboard.test.tsx`, and `dashboard-live.test.tsx` passed.

These are local source-tree results. Hosted checks for the pushed head and packaged-browser evidence are separate gates. This checkpoint does not complete #628 or #221: other routes and panels, complete route-by-state coverage, packaged-browser qualification, manual assistive-technology evidence, and parent-level integration remain open.

## Saved activity-window failure states and live-region follow-up — 2026-11-12

Source checkpoint: `98603e61bfb8c8d1de3ebffef0a6b7a1b13869e6` on PR #1946.

The saved activity-window route now uses the shared metadata failure classifier for session expiry, denied access, missing history, unsupported response contracts, unverified/corrupt responses, and other read failures. Its existing expired-window and invalid-cursor cases remain separate. Fixed messages retain only a validated request reference, do not substitute another window, and preserve rows only for a safe transient read failure on the same binding. The route matrix now exercises the saved-window snapshot path; focused component coverage also checks event-page failure, transient retention, unsupported-contract clearing, and that the read-only saved view never starts a live stream.

This checkpoint also keeps Runtime's storage loading status element mounted before and during the read, so the changing message is delivered through an existing live region. The dashboard's generic listing failure copy no longer claims every fallback was caused by an unavailable server.

Verification at this source checkpoint:

- Focused Vitest: `resilience.test.tsx`, `activity-navigation.test.tsx`, `storage-summary-format.test.tsx`, and `job-dashboard.test.tsx` — 4 files, 80 tests passed.
- Full frontend Vitest suite — 84 files, 1,203 tests passed.
- `npm run build` — generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.

These are local frontend results. The source does not establish packaged-browser or screen-reader evidence. Dashboard continuation after every cursor-failure permutation, remaining evidence/validation/Git panels, full panel failure matrices, and complete #628/#221 acceptance remain open. Shared `docs/web-failure-states.md` was not changed because other open D11 PRs edit it.

## Retained exploration artifact failure states — 2026-11-12

Source checkpoint: `c21aac825798f53ad9fca3ea4cd86b5e2983cf41` on PR #1946.

Explicit retained-case reads now distinguish session, denied, missing artifact, unsupported contract, unverified content, and other read failures using fixed copy and only a validated request reference. Parser/format failures are classified as unverified rather than as a generic transport failure. The new component matrix checks message distinctness, reference-ID behavior and exclusion of server codes/exception details. The existing malformed legacy artifact case now expects the unverified state. This remains an explicitly activated, read-only artifact view; it does not execute cases or start a workflow.

Verification at this source checkpoint:

- Focused Vitest: `exploration-cases.test.tsx`, `exploration-failure-cases.test.tsx`, and `resilience.test.tsx` — 3 files, 49 tests passed.
- Full frontend Vitest suite — 84 files, 1,204 tests passed.
- `npm run build` — generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.

These local results do not qualify all exploration/report failures or the remaining validation, Git, activity and other job panels. Packaged-browser and assistive-technology evidence, full #628/#221 acceptance, and hosted exact-head checks remain separate.
