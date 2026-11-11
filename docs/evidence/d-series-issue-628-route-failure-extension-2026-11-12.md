# #628 route failure-state extension — 2026-11-12

Source checkpoint: `48da5630de3394c176a9714781647093dab75d25` on PR #1946.

This checkpoint extends the focused #628 work in two areas:

- `RunHistory` is now the fifth route in the shared failure-class matrix. The matrix exercises session, denied, missing, unsupported, corrupt/unverified, and server failures; checks fixed copy and correlation-reference behavior; rejects protocol diagnostics; and verifies route headings and main navigation remain available.
- Runtime storage and maintenance reads use the shared failure classifier. Their six failure classes have distinct fixed messages, validated reference IDs are retained, and errors use an alert. A `PanelBoundary` isolates storage-panel render faults while preserving the runtime identity and capability sections.
- The dashboard refresh regression binds its URL cursor through a non-retainable read failure, then proves an explicit refresh can publish a new first-page cursor.

## Verification at the source tree for this checkpoint

- `frontend`: `npm test -- --run` — 84 test files passed; 1,201 tests passed.
- `frontend`: `npm run build` — generated API drift check, TypeScript, ESLint, production bundle, and bundle budgets passed.
- Focused coverage: `resilience.test.tsx`, `panel-isolation.test.tsx`, `storage-summary-format.test.tsx`, `job-dashboard.test.tsx`, and `dashboard-live.test.tsx` passed.

These are local source-tree results. Hosted checks for the pushed head and packaged-browser evidence are separate gates. This checkpoint does not complete #628 or #221: other routes and panels, complete route-by-state coverage, packaged-browser qualification, manual assistive-technology evidence, and parent-level integration remain open.
