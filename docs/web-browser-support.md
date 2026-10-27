# Workbench browser support, capability fallbacks and offline policy

This page is the qualification record for
[#631](https://github.com/minsago-elite/decomp_thing/issues/631) and the offline/old-tab policy
for [#632](https://github.com/minsago-elite/decomp_thing/issues/632), both under tracker #222.
GitHub issues own live status.

## Qualification record

| Engine | Build | How it is exercised | Status |
| --- | --- | --- | --- |
| Chromium | Chrome for Testing 149.0.7827.55, linux64, pinned with its SHA-256 in `scripts/web-test-browser.json` | Every CI `web-packaged` run drives the packaged JVM in this build through DevTools: session, metadata, live dashboard, 10,000-job scale, Vite proxy and (with #1782) the route audit, which covers reflow, contrast, focus, keyboard commands/download, assets under CSP and timing. `upgrade` and `legacy` modes exist for explicit runs. Each run records `Browser.getVersion` and the binary SHA-256 in `report.json`. | Qualified for the journeys listed, per CI run |
| Firefox | Playwright 1.58.2 Firefox 146.0.1 (browser revision 1509) | `scripts/packaged-browser-engines.mjs --engine firefox` against the packaged JVM at `/nested/` with its enforced CSP. The smoke journey uses the real server: bootstrap link sign-in with fragment removal, cookie restore across reload, runtime build identity, heading focus on route change, sign-out, and no browser storage left behind. It then runs the same route audit as Chromium: reflow at all five sizes in light and dark, text and focus contrast, Tab and Shift+Tab stops, 24 px targets, reduced motion, attempt retry/cancel and the source download by keyboard, every packaged asset plus the highlight worker under CSP, and timing budgets. | **Qualified locally** on 2026-10-26 (Linux x86-64): every check passed. Cold dashboard p95 219 ms, route feedback p95 16 ms, first data p95 49 ms. CI re-runs it for engine-driver changes or by dispatching *Browser engine qualification* |
| WebKit | Playwright 1.58.2 WebKit (browser revision 2248) | The same runner with `--engine webkit`. | **Not yet qualified.** The local host lacks WebKit's system libraries. It needs a passing *Browser engine qualification* run, which installs WebKit and its host dependencies on ubuntu-24.04. Engine-driver pull requests run it before merge; it can also be dispatched. Tracked in #1791 |
| Safari (macOS) | — | Not run; release-time manual check per `docs/web-delivery.md`. | Not qualified |

The delivery budgets name Playwright Chromium, Firefox and WebKit for CI plus current
stable browsers at release (`docs/web-delivery.md`). The Chromium DevTools checks run on every
pull request. The Playwright engine runner (`.github/workflows/browser-engines.yml`) runs Firefox
and WebKit before merge on pull requests touching its workflow, driver/input controls, shared
audit/installation helpers or the API-origin regression. Other changes avoid its additional
distribution build and browser host-dependency installation. Explicit dispatch can select a
nonempty, duplicate-free list of `firefox`, `webkit` and `chromium`; invalid or empty selections
fail before installation. Each run uploads `build/packaged-engines-*/report.json` with the engine
and Playwright versions, plus screenshots. A passing Chromium run is not evidence for other engines.

The engine smoke/audit is not yet the full #1791 qualification: upload, history and scale
journeys in both engines, retained browser archive SHA-256 pins and network-isolated test-time
execution still need evidence. #1791 and #631 stay open; a successful smoke/audit alone must not
be reported as satisfying their full acceptance criteria.

### Engine-specific findings

- **Mutations from Firefox (and per the Fetch standard, WebKit) were refused.** The document's
  `Referrer-Policy: no-referrer` makes these engines send `Origin: null` on a same-origin POST, and
  the server requires the exact origin, so sign-in, uploads and commands failed with
  "The browser address and application configuration do not match". Chromium still sends the real
  origin, so the Chromium-only checks never saw it. API requests now set
  `referrerPolicy: 'origin'`, which restores the exact `Origin` and sends only scheme, host and
  port as `Referer`, never the page path. The Firefox smoke journey and
  `capability-fallbacks.test.tsx` cover it.
- **Firefox does not wrap Tab back into the page** after the last stop (focus moves to browser
  chrome). This is browser behaviour, not an application defect; keyboard walks start from the
  route heading.

## Capability detection and fallbacks

The client detects features (`frontend/src/shared/browserCapabilities.ts`) and never reads the
user-agent string. A missing capability selects one of these documented paths instead of
producing a failure state.

| Capability | Detection | Fallback | Evidence |
| --- | --- | --- | --- |
| Streamed event delivery (readable `fetch` body) | `ReadableStream`, `TextDecoder` and `Response.prototype.body` present | Activity polls `events?transport=poll` every 2.5 s from the start and says it is using periodic refresh. A server that answers the stream with 406/415/501, a stream limit, or repeated transient failures switches to the same polling at runtime. API responses still enforce the byte limit while reading a stream even without `TextDecoder`, using a strict UTF-8 decoder after the bounded read. Only engines without readable bodies use `arrayBuffer()`: the declared length is checked before reading and the actual byte limit afterwards, but the browser must buffer that response whole (`api/body.ts`). | `capability-fallbacks.test.tsx`, `activity-stream.test.tsx` |
| Clipboard write | `navigator.clipboard.writeText` in a secure context | The copy action is replaced by guidance to select the displayed text or download the complete input. A write that fails at runtime reports its failure, and the download remains. | `capability-fallbacks.test.tsx` |
| File download | Native `<a download>` with a non-empty name (`download=""` would be taken over by the router) | Source and evidence attachments are served with `Content-Disposition: attachment`, so a browser that ignores the attribute still saves the file. The validation page export is an in-memory `data:` link and relies on `download`, which all three engines support; no further fallback is implemented. | `accessibility.test.tsx`, packaged audit keyboard download |
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
  | `sessionStorage` | `decomp.reload-attempt.v1:<base>` | The public UI build ID a reload left (#630) |

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
  explicit reload. There is no automatic chunk retry or reload, and no mutation is sent. The
  packaged `--mode upgrade` journey checks this with a real previous/current pair of packages
  when run explicitly; normal CI does not build the second package.
- An authenticated tab whose server reports a different UI build gets one explicit reload, then
  only manual guidance if the reload kept the same build (`docs/web-failure-states.md`).
- A response in a contract version this client cannot read moves the session to "incompatible",
  shows the reload guidance and stops private reads. Nothing is replayed.

Still open in #632: running `--mode upgrade` with the HTTP cache enabled against two complete
distinct packages in CI. The cache-observation helper and its controls exist, but no CI job
builds a second package.
