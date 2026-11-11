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

## Attempt-evidence failure matrix extension — 2026-11-12

Source checkpoint: `b072992d4fe1526db8e8a623dc568a107180a51c`, directly based on PR #1946 head `9556839c1e2c82d6c7186dd50eac73eaca9edd20`.

The app-level resilience matrix now covers the explicit exploration-report read on the attempt-evidence route for session expiry, denied access, missing evidence, unsupported contract, corrupt/unverified response, and server failure. It checks distinct fixed messages, safe request-reference behavior, absence of raw codes/exception diagnostics, and that the attempt route, Activity navigation, validation evidence panel, and main navigation remain available. The shared route-state matrix now documents eight routes. This is mock/JSDOM route evidence, not packaged-browser or screen-reader qualification.

On Node.js `v24.20.0`, the exact source tree passed the focused `resilience.test.tsx` suite (18 tests), the full frontend suite (85 files, 1,238 tests, no failures), and `npm run build` (generated API check, TypeScript, ESLint, production Vite bundle, and all bundle-size budgets). The change does not establish every failure class on every panel or close #628/#221; exact-head hosted and packaged-browser evidence plus manual assistive-technology qualification remain outstanding.

Verification at this source checkpoint:

- Focused Vitest: `exploration-cases.test.tsx`, `exploration-failure-cases.test.tsx`, and `resilience.test.tsx` — 3 files, 49 tests passed.
- Full frontend Vitest suite — 84 files, 1,204 tests passed.
- `npm run build` — generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.

These local results do not qualify all exploration/report failures or the remaining validation, Git, activity and other job panels. Packaged-browser and assistive-technology evidence, full #628/#221 acceptance, and hosted exact-head checks remain separate.

## Exploration report read failure states — 2026-11-12

Source checkpoint: `8762fc5b225572f47bae757a22c4594fe6e154ae` on PR #1946.

Explicit reads of the exploration report now distinguish session, denied access, missing route, unsupported response, unverified content, and general read failure. The component matrix verifies six distinct fixed alerts, reference-ID filtering, suppression of server codes and exception diagnostics, and preservation of the report panel controls after failure.

Verification at this source checkpoint:

- Focused Vitest: `run.test.tsx`, `exploration-cases.test.tsx`, `exploration-failure-cases.test.tsx`, and `exploration-breadth.test.tsx` — 4 files, 109 tests passed.
- Full frontend Vitest suite — 84 files, 1,205 tests passed.
- `npm run build` — generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.

These are local frontend results. Remaining job panels, full route/panel-state acceptance, packaged-browser evidence, screen-reader evidence, and parent #221 qualification remain open.

## Dashboard recovery-inspection failure states — 2026-11-12

Source checkpoint: `bed9cb0cb892808fe21058e98d29905c48ce6c9c` on PR #1946.

The independent recovery inventory now distinguishes session expiry, denied access, missing recovery data, unsupported response formats, unverified inventory, and other read failures. An active upload's `RECOVERY_INSPECTION_BUSY` remains a separate paused state. Read failures are announced as alerts and preserve the explicit warning to retain stored files; no cleanup action or recovery authority is exposed. The component tests verify distinct fixed messages, safe correlation references, diagnostic redaction, and clearing an earlier observation on denied refresh.

Verification at this source checkpoint:

- Focused Vitest: `dashboard-recovery.test.tsx` and `resilience.test.tsx` — 2 files, 25 tests passed.
- Full frontend Vitest suite — 84 files, 1,206 tests passed.
- `npm run build` — generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.

These local results leave other job panels, complete route-by-state coverage, packaged-browser and assistive-technology evidence, and parent #221 acceptance open.

## Queue-position read failure states — 2026-11-12

Source checkpoint: `d8b5ff6703838f43887d87c7c1666080f2428eef` on PR #1946.

The explicitly requested queue-position read now uses the shared failure classifier for session expiry, denied access, missing attempts, unsupported response contracts, unverified responses, and other read failures. Each category has fixed local guidance; only a validated request reference may be displayed. A failed refresh continues to discard the previous queue sample because an older position would be misleading. The read remains user-triggered and does not poll or retry automatically.

Verification at this source checkpoint:

- Focused Vitest: `queue-usage.test.tsx` — 1 file, 14 tests passed.
- `npm run build` with the repository-pinned Node 24.20.0/npm 11.19.0 toolchain — generated API drift check, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local component and build evidence only. It does not qualify packaged-browser or assistive-technology behavior, all queued-attempt route states, the remaining job panels, or full #628/#221 acceptance.

## Validation source lookup failure states — 2026-11-12

Source checkpoint: `2e28e8a10a8c37727bddf6c968b70df3c69f86c7` on PR #1946.

The validation source resolver now distinguishes session expiry, denied access, missing retained source, unsupported response format, unverified source commitment, and other read failure. Fixed messages retain only validated request references. The resolver still withholds the link on every failure and only publishes it after both run and source-directory identity/commitment checks succeed.

Verification at this source checkpoint:

- Focused Vitest: `recorded-validation.test.tsx` — 1 file, 45 tests passed.
- `npm run build` with the repository-pinned Node 24.20.0/npm 11.19.0 toolchain — generated API drift check, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local component and build evidence only. It does not qualify packaged-browser or assistive-technology behavior, every validation route state, all remaining job panels, or full #628/#221 acceptance.

## Retained validation history and selection failure states — 2026-11-12

Source checkpoint: `60c372ef3e25f0540d463d6bc3258a1eeb191dfe` on PR #1946.

The retained validation panel now distinguishes session expiry, denied access, unavailable history, unsupported response formats, unverified evidence, and other read failures. Restoring a saved selection keeps its exact-identity warning in each category and never substitutes another observation. Failures remain bounded alerts with only validated request references; the panel keeps its explicit history-read control available.

Verification at this source checkpoint:

- Focused Vitest: `recorded-validation.test.tsx` — 1 file, 51 tests passed.
- `npm run build` with the repository-pinned Node 24.20.0/npm 11.19.0 toolchain — generated API drift check, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

These are local component/build results. The full route-state matrix, packaged-browser and assistive-technology behavior, and complete #628/#221 acceptance remain outstanding.

## Retained dashboard page navigation after transient failure — 2026-11-12

Implementation checkpoint: `6fa21635ede9678315867749be16f5eafb0a88be`; exact test checkpoint: `5812f54c6a5ae36b82e9d246c14727ef60c14432` on PR #1946.

When a network, timeout, or retryable server failure leaves previously verified dashboard data visible, its available page cursors remain enabled after the failure alert is shown. Cursor-expiry, listing-busy, listing-limit, and unverified/non-retainable failures continue to require refresh or clear the old page. The check is explicit and does not add background reads or retries.

Verification at this source checkpoint:

- Focused Vitest at test checkpoint `5812f54c6`: `job-dashboard.test.tsx` — 1 file, 51 tests passed. The test retains a signed first-page cursor after timeout, follows its next cursor, and also preserves disabled-navigation controls for cursor-expiry and listing capacity/busy outcomes.
- `npm run build` with the repository-pinned Node 24.20.0/npm 11.19.0 toolchain — generated API drift check, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local component/build evidence only. Packaged-browser behavior, all signed-cursor failure permutations, and full #628/#221 acceptance remain open.

## Job-library route matrix coverage — 2026-11-12

Implementation checkpoint: `d8b5ff6703838f43887d87c7c1666080f2428eef`; exact matrix test checkpoint: `840c9893eb0319e12badc82cf367c6ad0b98b34f` on PR #1946.

The shared route failure matrix now includes the authenticated job library alongside job overview, attempt history, attempt overview, saved activity window, source directory and source file. Every route is exercised with session, denied, missing, unsupported, corrupt/unverified, and server failure responses. The test checks category-distinct fixed messages, request-reference filtering, diagnostic redaction, and that the route heading and main navigation remain available.

Verification at test checkpoint `840c9893e`:

- Focused Vitest: `resilience.test.tsx` — 1 file, 17 tests passed; the matrix covers seven routes across six failure categories.
- `npm run build` with the repository-pinned Node 24.20.0/npm 11.19.0 toolchain — generated API drift check, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local component/build evidence only. It does not qualify packaged-browser or assistive-technology behavior, the complete panel matrix, or full #628/#221 acceptance.

## Combined frontend verification after route and panel extensions — 2026-11-12

Exact source checkpoint: `b4d62334f8872b4a0b1d5f266993e8528ff99038` on PR #1946.

The combined changes were verified together after correcting internal validation binding errors to use the unverified-evidence message while preserving the saved-selection no-substitution wording.

- Full frontend Vitest suite: **84 files, 1,226 tests passed**.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0: generated API drift, TypeScript, ESLint, production bundle and all bundle-size budgets passed.
- Focused validation regression suites: `validation-navigation.test.tsx` and `recorded-validation.test.tsx` — 2 files, 56 tests passed.

This remains local frontend/JSDOM evidence. Hosted checks on the pushed head, packaged-browser qualification, manual assistive-technology evidence, remaining panel states and complete #628/#221 acceptance are separate and outstanding.

## Runtime storage partial-read preservation — 2026-11-12

Exact source checkpoint: `df3c37d8ae3f5de62346e258c52ef00ff9b5ae36` on PR #1946.

The Runtime storage panel reads storage totals and the maintenance preview independently. If one endpoint fails, its data is omitted while the successful endpoint remains visible. The fixed categorized alert identifies which read failed, includes only a validated request reference, and states when the displayed information is partial. Tests cover both directions: storage totals succeed while the preview is denied, and the preview succeeds while storage totals fail.

Verification at this source checkpoint:

- Focused Vitest: `storage-summary-format.test.tsx` — 1 file, 8 tests passed.
- Full frontend Vitest suite — 84 files, 1,228 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify packaged-browser behavior, screen-reader announcements, or full #628/#221 route and panel acceptance.

## Attempt action read failure states — 2026-11-12

Exact source checkpoint: `b703043d77184b57f3337a1387c613f12258177d` on PR #1946.

The explicit read of available attempt actions now distinguishes expired session, denied access, missing route, unsupported response, unverified response, and general read failure. The control remains available for an explicit retry; no command is sent on mount or after a failed read. The six-case component test checks distinct fixed status copy, validated request-reference handling, diagnostic redaction, and that no mutation request is sent.

Verification at this source checkpoint:

- Focused Vitest: `attempt-controls.test.tsx` — 1 file, 11 tests passed.
- Full frontend Vitest suite — 84 files, 1,229 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify packaged-browser or assistive-technology behavior, command failure categories, or full #628/#221 acceptance.

## Progress-retention policy read failure states — 2026-11-12

Exact source checkpoint: `5bbc13e5df4298ce845f8499801d450d256266af` on PR #1946.

The explicit progress-retention policy read now distinguishes expired session, denied access, missing route, unsupported response, unverified response, and general read failure. Unverified job/run binding is typed as an invalid response. The policy remains unavailable for changes after any failed read; pin/unpin mutation handling and conflict semantics are unchanged. The six-case test verifies category-distinct fixed status copy, safe request references, diagnostic redaction, and no mutation request.

Verification at this source checkpoint:

- Focused Vitest: `progress-pin.test.tsx` — 1 file, 10 tests passed.
- Full frontend Vitest suite — 84 files, 1,230 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify packaged-browser or assistive-technology behavior, pin/unpin failure permutations, or full #628/#221 acceptance.

## Runtime summary panel isolation — 2026-11-12

Exact source checkpoint: `48eba88c0d4b806ab8b8f79d7ee0dc8760272dcf` on PR #1946.

The scheduler and progress-retention summaries now have independent `PanelBoundary` instances. If either summary fails during rendering, its fixed notice replaces only that panel; the other summary, Runtime capabilities and route heading remain available. Retry rerenders only the failed panel and performs no action. Tests cover both failure directions and the retry behavior.

Verification at this source checkpoint:

- Focused Vitest: `panel-isolation.test.tsx` — 1 file, 4 tests passed.
- Full frontend Vitest suite — 84 files, 1,232 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify packaged-browser or assistive-technology behavior, API read failures within these summaries, or full #628/#221 acceptance.

## Deleted-job attempt-history refusal — 2026-11-12

Exact test checkpoint: `c412169882e476f95a7a94055491b4cb2da46cd0` on PR #1946. The production source is unchanged from the previously verified `48eba88c0d4b806ab8b8f79d7ee0dc8760272dcf` checkpoint.

The attempt-history failure matrix now distinguishes a deleted job (`410/RESOURCE_GONE`) from an expired signed cursor. A deleted job clears retained rows, does not offer a retry for the removed history, and displays the fixed deletion explanation.

Verification:

- Focused Vitest: the `deleted-job` case in `run.test.tsx` — 1 test passed.
- Full frontend Vitest suite at this test checkpoint — 84 files, 1,233 tests passed.
- The production build passed at the unchanged source checkpoint `48eba88c0d4b806ab8b8f79d7ee0dc8760272dcf` (recorded above).

This is local JSDOM evidence only. Packaged-browser, assistive-technology, and full #628/#221 acceptance remain open.

## Dashboard recovery inventory panel isolation — 2026-11-12

Exact source checkpoint: `8da24324f32cc01356a4841eb6069367a8dd5d53` on PR #1946.

The recovery-file inventory now has an independent panel boundary inside the job dashboard. A render failure replaces only that inventory; the upload form, filters, loaded jobs, dashboard heading, and page controls remain available. The fixed panel notice suppresses exception details, and retry rerenders only that read-only panel without sending a command.

Verification at this source checkpoint:

- Focused Vitest: `panel-isolation.test.tsx` — 1 file, 5 tests passed.
- Full frontend Vitest suite — 84 files, 1,234 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify packaged-browser or assistive-technology behavior, recovery endpoint failures beyond the existing component matrix, or full #628/#221 acceptance.

## Exploration evidence read failure classes — 2026-11-12

Exact test source checkpoint: `85d20fd8c5d3f813fc975462801fca8199ed4457` on PR #1946. The production categorization was already present in the reviewed source; this change adds focused evidence for its six read-failure classes.

The component test covers expired session, denied access, missing route, unsupported response, unverified response, and general server failure. It requires distinct fixed guidance, includes only validated request IDs, rejects private server diagnostics, and confirms one explicit report read per attempt without automatic retry.

Verification at this source checkpoint:

- Focused Vitest: `exploration-evidence-failures.test.tsx`, `exploration-failure-cases.test.tsx`, `dashboard-recovery.test.tsx`, and `resilience.test.tsx` — 4 files, 46 tests passed.
- Full frontend Vitest suite — 85 files, 1,235 tests passed.
- `npm run build` with pinned Node 24.20.0/npm 11.19.0 — generated API drift, TypeScript, ESLint, production bundle, and all bundle-size budgets passed.

This is local frontend/JSDOM evidence only. It does not qualify browser or assistive-technology behavior, every route/panel failure combination, or full #628/#221 acceptance.

## Retained legacy-page navigation after a failed continuation — 2026-11-12

Implementation/source checkpoint: `5dae1feeada937f2ece293ba4b184b3eb81dbd1a` on PR #1946.

For peers without signed `currentCursor` metadata, the dashboard now anchors Previous/Next to the page whose rows are actually displayed after a transient continuation failure. An explicit navigation-attempt identity allows a user to retry the same failed destination without changing the requested page index or automatically retrying. The packaged scale journey now verifies the transient failure retains Page 1, leaves only Next enabled, and a keyboard retry loads exactly Page 2 before the explicit Refresh recovery.

Verification on a repository-local archive snapshot reconstructed from the exact PR parent plus the three source/test/script files in this checkpoint:

- Focused Vitest: `job-dashboard.test.tsx` — 53 tests passed.
- `npm run typecheck` with Node 24.20.0/npm 11.19.0 — generated API drift and TypeScript checks passed.
- `npm run lint` with Node 24.20.0/npm 11.19.0 — passed with zero warnings.
- `node --check scripts/packaged-browser-scale.mjs` — passed.

The source-level tests cover legacy peers without cursor metadata; the packaged retry journey exercises the signed-cursor browser fixture. Hosted checks for this checkpoint remain authoritative. This evidence does not establish all dashboard failure classes, every route or panel, packaged accessibility beyond the existing gates, assistive-technology behavior, or full #628/#221 acceptance. #628 remains OPEN.


## Exact-head review reconciliation — 2026-11-12

The review of earlier checkpoint `f92769613` identified a conditionally mounted Runtime storage
status paragraph and dashboard wording that implied every unclassified failure came from server
unavailability. These findings do not apply to the current PR source checkpoint `8af0f15e9`:

- `StorageSummary` keeps one `<p role="status">` mounted while its text changes from empty to
  “Reading storage…”. The `storage-summary-format.test.tsx` loading case asserts the same DOM
  node is still present after the update. This is component evidence for the live-region structure;
  it is not screen-reader announcement evidence.
- The dashboard's fallback is the fixed, generic “Jobs could not be loaded. Refresh the job
  library to try again.” message. The route tests include a non-transient 422 refusal and assert
  that copy, without attributing the failure to a server outage.
- The shared route matrix and wrapped-panel inventory in `docs/web-failure-states.md` now match
  the current seven-route matrix and Runtime panel boundaries.

The conditionally mounted status paragraph was corrected in source checkpoint
`df3c37d8ae3f5de62346e258c52ef00ff9b5ae36`. This remains local component evidence; packaged
browser and assistive-technology qualification, remaining panels, and full #628/#221 acceptance
remain outstanding.
