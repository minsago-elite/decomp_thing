# Workbench browser support, capability fallbacks and offline policy

This page is the qualification record for
[#631](https://github.com/minsago-elite/decomp_thing/issues/631) and the offline/old-tab policy
for [#632](https://github.com/minsago-elite/decomp_thing/issues/632), both under tracker #222.
GitHub issues own live status.

## Qualification record

| Engine | Build | How it is exercised | Status |
| --- | --- | --- | --- |
| Chromium | Chrome for Testing 149.0.7827.55, linux64, pinned with its SHA-256 in `scripts/web-test-browser.json` | Every CI `web-packaged` run drives the packaged JVM in this build through DevTools: session, metadata, live dashboard, 10,000-job scale and Vite proxy. The route audit (reflow, contrast, focus, keyboard commands/download, assets under CSP and timing) is pending unmerged #1782, not evidence at this head. `upgrade` and `legacy` modes exist for explicit runs. Each run records `Browser.getVersion` and the binary SHA-256 in `report.json`. | Qualified only for the existing journeys, per successful CI run; route audit/download pending #1782 |
| Firefox | none pinned | Not run. | **Not qualified.** Tracked in #1791 |
| WebKit / Safari | none pinned | Not run. | **Not qualified.** Tracked in #1791 |

The delivery budgets name Playwright Chromium, Firefox and WebKit for CI plus current
stable browsers at release (`docs/web-delivery.md`). Until #1791 lands, nothing on this page
claims Firefox or WebKit support. A passing Chromium run is not evidence for other engines.
Engine-specific defects found later each get their own issue linked here, along with the
fallback used in the meantime.

## Capability detection and fallbacks

The client detects features (`frontend/src/shared/browserCapabilities.ts`) and never reads the
user-agent string. A missing capability selects one of these documented paths instead of
producing a failure state for streaming or clipboard. The download limitation below remains
unfixed at this head; documenting its intended fallback does not qualify that capability.

| Capability | Detection | Fallback | Evidence |
| --- | --- | --- | --- |
| Streamed event delivery (readable `fetch` body) | `ReadableStream`, `TextDecoder` and `Response.prototype.body` present | Activity polls `events?transport=poll` every 2.5 s from the start and says it is using periodic refresh. A server that answers the stream with 406/415/501, a stream limit, or repeated transient failures switches to the same polling at runtime. API responses still enforce the byte limit while reading a stream even without `TextDecoder`, using a strict UTF-8 decoder after the bounded read. Only engines without readable bodies use `arrayBuffer()`: the declared length is checked before reading and the actual byte limit afterwards, but the browser must buffer that response whole (`api/body.ts`). | `capability-fallbacks.test.tsx`, `activity-stream.test.tsx` |
| Clipboard write | `navigator.clipboard.writeText` in a secure context | The copy action is replaced by guidance to select the displayed text or download the complete input. A write that fails at runtime reports its failure. Selection is available, but the complete-source download mentioned in that guidance is **pending #1782** as described below. | `capability-fallbacks.test.tsx` verifies the guidance and clipboard behavior, not a completed download |
| File download | Intended: native `<a download>` with a non-empty name | **Not qualified at this head.** `routes/Sources.tsx` still uses `download=""`; the shipped router intercepts that click as SPA navigation, so `Content-Disposition: attachment` cannot rescue it. Unmerged #1782 supplies the non-empty filename and packaged keyboard-download regression. Once native navigation is preserved, source and evidence attachment responses use `Content-Disposition: attachment` for browsers ignoring the attribute. The validation page's in-memory `data:` export relies on `download`; no further fallback is implemented. | Existing accessibility/component checks do not establish complete-source download. Integrated #1782 component and packaged keyboard-download evidence is still required; the #631 download slice remains open. |
| Module worker (source highlighting) | Worker construction inside the explicit highlight action | Highlighting reports "unavailable" and the complete text stays plain; nothing else depends on the worker. | `source-highlight-operation.test.ts` |
| Broadcast session invalidation | `BroadcastChannel` | Without it, other tabs learn about sign-out at their next authenticated read (401) instead of immediately. | `session-tabs.test.ts` |
| Local preference storage | `localStorage` access | Display preferences apply to the tab only and say they could not be saved. | `display-preferences.test.tsx` |

## Retention evidence boundary (#624)

`frontend/tests/retention-leaks.test.tsx` exercises repeated navigation and 60 stream
subscriptions on a still-live signal. It checks listener/timer/channel baselines, response-body
cancellation and released reader locks. This is structural jsdom evidence, not a measurement of
retained JavaScript heap or detached buffers. The production-bundle heap traces on the agreed
browser/machine profile required by #219 have not been collected here. #624 remains open pending
that qualification and coverage of the dependent graph/source features; this harness alone does
not establish its full acceptance criterion.

## Offline and sensitive-data policy (#632)

- **No service worker, Cache Storage, IndexedDB or app manifest.** The client never registers a
  worker that could cache job data or queue requests. `capability-fallbacks.test.tsx` scans the
  application source and `index.html` and fails if one appears.
- **API reads bypass the HTTP cache.** Every API and event request uses `cache: 'no-store'`,
  `credentials: 'same-origin'`, `mode: 'same-origin'` and `redirect: 'error'`, and the server
  sends `Cache-Control: no-store` on API responses. Only hashed static assets are cacheable.
- **Browser storage holds only inventoried, non-sensitive records.** The test fails on any
  storage use outside this list:

  | Storage | Record | Contents |
  | --- | --- | --- |
  | `localStorage` | `decomp.display-preferences.v1` | Theme and reduced-motion choice |
  | `sessionStorage` | `decomp.upload.v1:<base>` | One bounded upload intent identity; no file bytes |
  | `sessionStorage` | `decomp.attempt-command.v1:<base>` | One unconfirmed attempt command: identities, version and request key, never credentials |
  | `sessionStorage` (reserved, not implemented here) | `decomp.reload-attempt.v1:<base>` | Planned public UI build ID a reload left (#630), pending #1784 |

  The policy test allowlists `app/reloadGuard.ts` for #1784, but that module and record do not
  exist at this head. An allowed future path is not evidence that the recovery guard is present.

- **Offline viewing is limited to what the page already shows.** When the browser reports
  offline, the shell marks previously loaded information as possibly out of date and says server
  work may continue. Nothing is fetched from a cache instead, and after reconnect it still asks for
  an explicit refresh.
- **No queued execution commands.** Attempt commands and progress-pin changes are disabled while
  the tab is offline or hidden. Activating them sends nothing, and going back online sends nothing
  automatically. An unconfirmed command sent before the connection dropped is only replayed after
  an explicit request, with its original key and version.

## Old tabs and a new server (#632)

- A lazy route whose hashed chunk no longer exists produces one application notice and one
  explicit reload per page lifetime, not a guard persisted across reloads. There is no automatic
  chunk retry or reload, and no mutation is sent. The
  packaged `--mode upgrade` journey checks this with a real previous/current pair of packages
  when run explicitly; normal CI does not build the second package.
- **Pending unmerged #1784:** compare an authenticated tab's UI build with the server's build,
  offer one explicit reload and then only manual guidance if that reload kept the same build.
  This head only reports server-instance changes; it does not implement that UI-build comparison
  or the persisted one-reload guard. #1784 also supplies `docs/web-failure-states.md`, which is not
  present here, and shares the persisted guard with asset recovery.
- A response in a contract version this client cannot read moves the session to "incompatible",
  shows the reload guidance and stops private reads. Nothing is replayed.

Still open in #632: integrate and verify #1784's UI-build mismatch recovery and persisted guard,
and run `--mode upgrade` with the HTTP cache enabled against two complete distinct packages in CI.
The cache-observation helper and its controls exist, but no CI job builds a second package. The
missing implementation and the unexecuted two-package qualification are separate gaps; existing
asset/API recovery checks do not close either one.
