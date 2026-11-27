# D11 #615 attempt-control focus handoff

**Source checkpoint:** `4c86e62f1da21557891ea3ed8fac0f6c676a92ea` on `codex/issue-615-attempt-control-focus`, based on current `master` `2b1121999c806d5b3f89d3723fca8a39879c49b1`.

When a user explicitly starts cancel or retry, the action buttons are replaced while the request is in flight. Resume has the same transition. An explicit discard removes the unconfirmed-command controls. The component now moves focus to its stable, programmatically focusable `Attempt controls` heading only when focus is inside that panel. The heading uses `tabIndex=-1`; focus is moved without scrolling. Existing command identity, request, retry and recovery behavior is unchanged.

The regression cases focus each action before activation, check the heading owns focus immediately and after the response/readback, cover explicit discard, and confirm an outside focus owner is not moved by a passive stale-version update. These are component-level DOM assertions. They do not establish physical keyboard behavior or screen-reader announcements.

## Verification

- Focused Vitest: `attempt-controls.test.tsx`, `run.test.tsx`, and `panel-isolation.test.tsx` — 3 files, 75 tests passed.
- Full frontend Vitest suite — 84 files, 1,193 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

No packaged-browser or manual assistive-technology run was performed. This completes one focus-handoff slice only; the broader keyboard journeys, evidence inspection/download paths, dialogs, and D11 #615/#217 acceptance remain open.
