# Workbench failure states and recovery convergence

This page covers [#628](https://github.com/minsago-elite/decomp_thing/issues/628),
[#629](https://github.com/minsago-elite/decomp_thing/issues/629) and
[#630](https://github.com/minsago-elite/decomp_thing/issues/630) under the D11 resilience
tracker #221. GitHub issues own live status.

## One vocabulary for read failures

Every private read classifies its failure with `metadataFailureKind`
(`frontend/src/shared/retainMetadata.ts`) and shows a fixed catalog sentence for that class,
never server text. Source reads use the same classes after their source-specific outcomes
(invalid address, busy, invalid range, expired continuation).

| State | Trigger | What the view shows |
| --- | --- | --- |
| Loading | Read in flight | A local `role="status"` line; previous verified data stays and is labelled as being refreshed. |
| No data | Successful empty page | An explicit empty-state sentence (for example "No uploaded jobs yet"), never an alert. |
| Stale data | Transient failure (network, timeout, 408, 429, 5xx) after a verified read | The retained data with a "may be outdated" line beside the failure. Other classes clear retained data. |
| Session | 401 | Reconnect guidance; the shared session notice takes over. |
| Denied | 403 | Access-denied guidance for the local session or declaration. |
| Missing | 404/410 | The record is unavailable or was not retained. |
| Unsupported | The response is a contract this client cannot read | Reload-to-match guidance; nothing is rendered from it. |
| Corrupt | Malformed, oversized or unverifiable response, or a server code naming damaged storage | Unverified-record guidance; nothing from it is shown. |
| Server failure | Any other failure | Check-the-server guidance. |

A failure that came from an HTTP 400–599 response with a canonical server UUID appends
`Reference ID: <uuid>.` (`withApiFailureReference`); no server code, message, stack, URL or
token is displayed. `frontend/tests/resilience.test.tsx` drives every class through the job,
attempt, source directory and source file routes, requires six distinct messages per route,
the reference only where one exists, no leaked diagnostics, and a still-navigable route
(route heading and main navigation present).

## Partial results and panel isolation

Each independent panel owns its read and its failure, so a failed exploration report does not
hide validation evidence or activity. Panels are also wrapped in `PanelBoundary`
(`frontend/src/shared/PanelBoundary.tsx`): a render failure replaces only that panel with
"<panel> could not be displayed", keeps the route heading, identity facts, navigation and
sibling panels, shows no exception text, and offers "Show this section again", which only
re-renders the panel (repeating its own reads). Wrapped panels: upload, the job list, workflow
availability, attempt actions, progress pin, activity, exploration and validation evidence,
the source preview and the download digest check. `frontend/tests/panel-isolation.test.tsx`
forces a panel to throw and checks the notice, the absence of private detail, the surviving
siblings, axe, and that retry sends no command.

## Retry safety and form context (#629)

| Control | What it repeats | Evidence |
| --- | --- | --- |
| Refresh job/attempt/history/file/range, Retry this page, First page | One GET for the same identity (and cursor) | `resilience.test.tsx` activates every retry/refresh/try-again control on eight routes and requires zero POST/PUT/upload/delete calls; `history-context.test.tsx` |
| Show this section again / Try again (view and panel boundaries) | A re-render, hence the view's own reads | `panel-isolation.test.tsx`, `app.test.tsx` |
| Replay unconfirmed request (attempt retry/resume/cancel) | The retained command with the same idempotency key, If-Match version and body; never a refreshed guard | `attempt-controls.test.tsx` (lost acknowledgement, reload, duplicate clicks send once) |
| Upload retry | The same retained file and intent under the server's upload identity | `mutation-reconnect.test.tsx`, `upload-recovery.test.ts` |

Validation errors stay attached to their field (`aria-invalid`, `aria-describedby`, focus) and
keep the typed value (`dashboard-*.test.tsx`, `upload.test.tsx`). An unsubmitted dashboard
filter draft now survives the dashboard remounting for a new session generation, for example
after expiry and reconnect (`jobs/filterDraft.ts`). It is held in page memory only, bound to
the browser-session object and the applied filters it was typed against, and dropped when the
session identity is invalidated (sign-out, another tab, a new server instance, an incompatible
server), including while another route is open: the first retained draft subscribes to the
session's invalidation for the session's lifetime. It is never written to storage or the URL.

## Converging session and version recovery (#630)

Nothing in the client reloads, re-authenticates or retries on a timer.

- **Session expiry:** a session generation transitions to "required" once, however many
  in-flight reads report 401; later stale failures are ignored, one notice is shown, and only
  the explicit "Check session" control reads again. No sign-in link is replayed.
- **Server version change:** when the authenticated bootstrap reports a UI build different from
  the page's build, the shell shows one status notice with both builds and a single
  "Reload application" control. Before reloading, the page records the build it is leaving in
  `sessionStorage` (`app/reloadGuard.ts`: one public build ID per tab and deployment). If the
  reloaded page is still that build, for example because a cache or proxy served the old
  document, the notice replaces the control with manual hard-reload guidance. A page that loads a
  different build clears the record.
- **Missing application files:** the asset-recovery notice uses the same guard, so a reload that
  returns the same stale build cannot be offered again in a loop.
- **Display preferences:** an invalid or unreadable stored preference falls back to the defaults
  without being rewritten at startup (`display-preferences.test.tsx`).

`resilience.test.tsx` covers the reload-once-then-guidance sequence, convergence after a
successful reload, the asset-recovery guard, and six concurrent expiry rejections producing a
single transition and notice with no automatic bootstrap or exchange request.
