# Workbench accessibility audit

This is the audit record for [#217](https://github.com/minsago-elite/decomp_thing/issues/217)
and its children #615–#618. The target and machine/browser profiles are the ones in
[delivery budgets](web-delivery.md#measurement-profiles-and-budgets): WCAG 2.2 AA, desktop
1440×900 at 1×, narrow 390×844, a 320 CSS-pixel reflow check and 200%/400% zoom. GitHub issues
own live status; this page records what is checked, how, and what still needs a person.

## Automated coverage

| Gate | Command / CI step | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Component axe gate | `npm test` → `frontend/tests/accessibility.test.tsx` | Zero axe-core WCAG 2.0/2.1/2.2 A/AA violations (contrast disabled; jsdom has no layout) on every routed view with contract fixtures, the public shell, the open display-preference panel and a failed read. Downloads stay native links the router does not intercept. Each route change focuses its `h1` once, updates the title and clears the shared loading status. | Rendered colour, layout, zoom, real keyboard input or assistive-technology output. |
| Token contrast | `npm test` → `frontend/tests/contrast-tokens.test.ts` | Every documented foreground/background token pairing meets 4.5:1 (text) or 3:1 (control boundaries, focus) in light and dark, and the explicit and system dark themes are identical. | Pairings a component invents outside the documented set; those are caught by the packaged audit. |
| Copy catalog | `npm test` → `frontend/tests/copy-catalog.test.ts` | Accessible names, titles and placeholders come from catalogs, so names stay consistent across views. | Name quality; that is a manual check below. |
| Shell keyboard and navigation | `npm test` → `frontend/tests/app.test.tsx` | Skip link, route heading focus (including history traversal without scrolling), the narrow Navigation disclosure (Escape, focus return, breakpoint changes), offline notices without focus theft. | Physical keyboard behaviour in each engine. |
| Form error relationships | `dashboard-*.test.tsx`, `upload.test.tsx` | Invalid fields are focused, `aria-invalid`, and described by their message; upload errors persist through retry. | Screen-reader phrasing. |
| Packaged audit | CI `web-packaged` → `check-packaged-web-browser.mjs --mode audit` (`scripts/packaged-browser-audit.mjs`) | In pinned Chrome against the packaged JVM at `/nested/` with its enforced CSP: every SPA route at all five sizes in light and dark (system preference) has no page-wide horizontal scroll; only `.source-rows` and `.retained-case-table` scroll, and each such region fits, is focusable and named; no action is pushed off-screen; buttons, fields, navigation and breadcrumb targets are at least 24×24 CSS px; the Navigation disclosure replaces the sidebar below 48rem; reduced motion leaves zero running animations. Every rendered text node is measured against its effective opaque background (4.5:1, or 3:1 for large text), failing on any colour it cannot measure. Every Tab stop on every route, forward from the heading and backward to the skip link, is `:focus-visible` with a ≥2 px outline at ≥3:1 and is neither off-screen nor covered. Attempt retry and cancellation and the source download are completed with Tab plus Enter/Space only, and each command carries its If-Match, idempotency key and CSRF token. Screenshots of every route at 400% zoom, and of the dashboard, job detail and source views at every size, are retained. | Other engines: `scripts/packaged-browser-engines.mjs` runs the same checks in Firefox (qualified locally) and WebKit (dispatch workflow) — see [browser support](web-browser-support.md). Manual screen-reader output, Git views (not implemented), the router's not-found view (unknown paths are a server 404 document). API reads are contract fixtures fulfilled in DevTools, because inert seeding cannot persist source revisions; the document, CSP, assets and worker are the real packaged responses. |
| Dashboard contrast/reflow | CI `--mode scale` | Dashboard controls' border and focus contrast at their measured colours and 320/390 px reflow with 10,000 persisted jobs. | Other routes (covered by the audit). |

## Findings from this audit and their fixes

| Finding | Measured by | Fix |
| --- | --- | --- |
| The reduced-motion rule set `transition-duration: 0.01ms` on every element, so any property change (for example switching to the dark theme) started hundreds of real transitions; in a throttled tab the old colours stayed on screen and measured 1.004:1. | Packaged audit: `document.getAnimations()` and text contrast after a theme switch. | Reduced motion now sets `animation: none` and `transition: none`. The app declares no animations, so nothing that was meant to run is removed. |
| Breadcrumb links ("All jobs") rendered below 24×24 CSS px. | Packaged audit target-size check. | Breadcrumb links are inline-flex with a 1.5rem minimum height and width. |
| "Download complete recorded input" used `download=""`. preact-iso only skips truthy `link.download`, so Enter or a click turned the attachment into an in-app route and no download began. | Packaged audit keyboard download, then a component regression test. | The link carries the file's display name; the server's `Content-Disposition` still names the saved file. |
| Populated validation history/case tables widened narrow and zoomed attempt views and pushed inspection actions off-screen. The comparison table had the same missing styling. | Hosted populated-content audit (PR #1782, run `40266450563`); component regressions cover all three table wrappers. | All validation tables now use the existing bounded `.retained-case-table` styling on their named, keyboard-focusable regions; the surrounding evidence section uses the retained-evidence wrapping rules. Hosted qualification of the fix is required. |

### Audit coverage corrections

The initial audit accepted the shared “Attempt identity” shell without activating the explicit
activity/evidence reads. Its passing result did **not** qualify the activity rows, exploration
chart/table or validation history/case tables. The corrected audit follows then pauses activity,
reads exploration evidence and validation history, and inspects a populated validation receipt
on every fresh overview/activity/evidence navigation before layout, contrast or focus measurement.
It requires successful identity-bound API reads and visible distinctive rows, the chart and its
table alternative; an unused fixture or empty shell fails preparation. Explicit-read interaction
timings are retained separately from initial-route metadata timings.

The initial verdict also ignored non-exempt overflow that did not widen the root. The corrected
measurement and verdict reject both out-of-viewport content and local horizontal scrolling or
clipping outside the named source/table exemptions. Dependency-free regression controls cover
missing content/reads and bounded `auto`/`hidden`/`clip` overflow; these models are not browser
rendering evidence. The expanded populated-content coverage requires its own hosted packaged
qualification; earlier shell-only results must not be used as that evidence.

The populated-content run also exposed an audit false positive: descendants of closed
`<details>` can retain client rects even though they are not rendered. Layout and contrast now
use `checkVisibility()` to exclude those boxes. Opening the disclosure restores the checks;
regression controls require visible overflow and insufficient contrast to fail. This does not
exempt visible previews or add any new horizontal-scroll exception.

An independent review found two further coverage gaps. The verdict previously accepted empty
layout/contrast/focus arrays and `null` timing percentiles. It now requires the exact 10-route ×
5-viewport × 2-theme layout matrix (100 records), contrast at desktop and 320 CSS pixels in
both themes (40 records), and both-theme focus walks for every route (20 records), rejecting
missing, duplicate or unexpected cells. Timing evidence must contain 20 target-load and 50/50
route-feedback/data finite nonnegative samples, with matching finite median/p95 summaries;
only then are the existing budgets evaluated. These target-load measurements still do not
establish the fresh-browser-process cold-load requirement in #623.

Previously, source highlighting was activated only in the later worker/CSP journey, after
contrast and layout measurements. Each fresh source navigation for layout/contrast/focus now
explicitly highlights and requires distinctive rendered plain/keyword/string/comment/number
tokens before measurement. Each source contrast record must include measured text of all five
token kinds in both themes at both contrast profiles. The dedicated worker-target/CSP checks
remain separate and mandatory. Negative controls inject low-contrast rendered tokens and absent
token measurements, as well as empty/partial matrices and missing/null/nonfinite timing evidence.
These controls validate the audit, not browser rendering; the expanded highlighted-state coverage
requires new-head hosted qualification and does not establish a pre-existing token colour defect.

Contrast, reflow, focus, target-size and reduced-motion results are retained in the CI
`packaged-web-verification` artifact
(`build/packaged-browser-*/report.json`, every route's 400% zoom screenshot and the dashboard, job
detail and source views at every supported size).

## Dialogs, disclosures and announcements

The workbench has no modal dialogs. The Navigation disclosure (below 48rem) and Display
preferences are non-modal disclosures in the document flow, following the WAI-ARIA disclosure
pattern: a button with `aria-expanded`/`aria-controls`, Escape closes the panel and returns focus
to its button, and Tab is not trapped because the rest of the page remains usable. A future
modal must use `<dialog>` with `showModal()` so the browser traps focus and makes the page inert,
return focus to its opener on close, and add a case to the component gate and the packaged audit.

Route changes announce context by moving focus to the new view's `h1` (which carries
`tabindex="-1"`) and updating `document.title`. The only shared live region is the visually
hidden "Opening view" status, which is cleared when the view is ready; views announce their own
loading and result states in local `role="status"` regions, so navigation does not repeat them.

## Graphs, charts and long lists

The output-signature breadth chart is `role="img"` with a caption and a description that cite
the exact counters, and the same values are in a captioned table with row headers. There are no
virtualized lists: jobs, attempts, activity rows, source directories and validation cases are
paged (at most 200 rows per page) and every row is in the DOM and the accessibility tree. No call
or dependency graph view exists in the SPA yet (#184); when one lands it needs an equivalent
table/list alternative and its own audit case.

## Manual screen-reader qualification (#617)

Automated results above are recorded; manual results are still required and are not claimed.
Run each journey on the packaged app served from Linux, with the browser and screen reader on
the host named in [delivery budgets](web-delivery.md#measurement-profiles-and-budgets):

- NVDA (current) with Firefox (current) on Windows 11.
- VoiceOver with Safari (current) on macOS.
- Orca with Firefox on Linux (optional smoke).

For every journey record the application commit, browser and screen-reader builds, pass/fail per
step, the exact announcement when it is wrong, and the fix or a scoped exception with an issue.

1. **Start and navigate.** Load the workspace. The skip link is announced first and moves to the
   main landmark. Landmarks list one banner, one main navigation, one main and one contentinfo.
   Moving between Workspace, Upload and Runtime status announces each new heading once, and the
   title changes. Below 48rem, "Navigation" is announced as a collapsed button and its state
   changes when toggled; Escape returns to it.
2. **Upload.** The file field is announced with its label and guidance. A rejected file announces
   the error once, and the field reports invalid with the message as its description. Progress
   and the created job are announced as status, not as alerts.
3. **Dashboard.** Filter fields have names; an invalid date moves focus to the field and the error
   is read as its description. Page changes and live-update pauses are announced once.
4. **Attempt commands.** "Read available actions", then Retry or Request cancellation, each
   announce their verified/sent/result status. An unconfirmed command offers replay and discard
   with their scope.
5. **Evidence and activity.** Activity rows, the output-signature chart description and its table,
   and validation case tables are navigable with table commands; each table announces its caption.
6. **Source views.** Directory listings, file facts, the source preview region (named, focusable,
   scrollable), line links, highlighting status and the copy/download actions are announced with
   their names; the download starts a file save.
7. **Recovery.** Session expiry, a server version change and an offline notice are each announced
   once with their next step.

## Git workflows (#618)

The SPA has no Git views yet: the runtime reports managed Git as unsupported, and the staging,
commit review, branch selection, remote-write preview and conflict resolution UIs are owned by
#206 and #211. No automated or manual Git accessibility result exists. When those views land,
add each one to the component gate and the packaged audit, then run this keyboard and
screen-reader checklist with the same recording rules as above:

- **Staging:** every changed path is reachable by keyboard; its staged state is a named checkbox
  or toggle button; bulk actions report their count as status.
- **Commit review:** the diff is a named, focusable region with line positions; the summary and
  message fields are labelled; validation errors are attached to their field.
- **Branch selection:** the current branch is announced; the chooser is a labelled select or
  listbox with no focus trap; switching announces the result once.
- **Remote-write preview:** the remote, refs and objects to be written are readable as a list or
  table before confirmation; confirmation is a distinct button, and cancelling returns focus.
- **Conflict resolution:** each conflict and its side is named; choosing a resolution is
  keyboard-operable; remaining-conflict counts are announced as status.
