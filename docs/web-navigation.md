# Embedded workbench navigation and interaction design

This is the design contract for [D0.3 / #147](https://github.com/minsago-elite/decomp_thing/issues/147).
It specifies the D3–D9 views and D11 accessibility work; the wireframes are synthetic design
examples, not implemented screens or evidence that a workflow passed. GitHub issues remain the
source of implementation and acceptance status. The inspected legacy baseline is `27feba3`,
particularly [UploadServer](../src/main/kotlin/decompengine/web/UploadServer.kt) and
[WebViews](../src/main/kotlin/decompengine/web/WebViews.kt).

Use the [parity inventory](web-parity.md) for existing behavior, the
[architecture](web-architecture.md) for module/state ownership, the [API contract](web-api.md)
and [schema](../contracts/web/v1/contract.schema.json) for identity and response semantics,
the [trust contract](web-trust.md) for authorization, and the [delivery budgets](web-delivery.md)
for qualification. This document changes none of the server's acceptance authorities.

## Navigation and identity

The global navigation contains **Jobs**, **Upload**, and **Runtime**. A job workspace adds
**Overview**, **Activity**, **Structure**, **Evidence**, **Sources**, **Revisions**, **Artifacts**,
and **Git**. The workspace header always identifies the job, selected attempt/revision when
applicable, current action status, and the last successful refresh. Git has its own subnavigation:
**Overview**, **Changes**, **History**, **Branches**, **Worktrees**, **Remotes**, **Conflicts**.
Unavailable capabilities remain explainable without obstructing source or evidence browsing.

All paths below are relative to the configured application `basePath`. `J` abbreviates
`/jobs/{jobId}`, `R` abbreviates `J/runs/{runId}`, `V` abbreviates
`J/revisions/{revisionId}`, and `G` abbreviates `J/repositories/{repositoryId}`.
These are browser routes; downloads and JSON use separate `/api/v1` endpoints.

- Treat job, run, revision, file, artifact, repository, worktree, operation and ref IDs as opaque,
  case-sensitive server identifiers. Encode each value once. A display filename, relative source
  path, branch name or abbreviated Git object ID is never a substitute for its identifier.
- Source links always pin `revisionId` and `fileId`. Their server response supplies the originating
  run and acceptance relationship. Evidence and activity links pin `runId`; evidence detail also
  records a revision when the report establishes one. Validate all supplied associations together.
  Legacy evidence with unknown run/revision provenance is labelled accordingly, without invented IDs.
- The overview may show a changing latest-attempt pointer. Opening that pointer resolves an exact
  run URL; an already open source/evidence view never silently advances to a newer attempt or revision.
  Switching attempt or revision is explicit and creates a history entry.
- User navigation, selected files, submitted filters, pagination and comparisons use history push.
  Initial canonicalization and invalid/expired cursor cleanup use replace with a visible explanation.
  Typing an unsubmitted search, expanding a tree or receiving events does not create history entries.
  Back/forward restores the selected resource, filters, scroll and focus where the item still exists.
- Search and filter queries are URL state; do not put credentials, private prompts, file contents,
  host paths or mutation bodies in URLs. Source searches are transient by default; sharing a search
  query is an explicit action because a URL can be retained in browser history.
- A deleted job shows a tombstone when authorized, with **All jobs**. Missing run/revision/file/artifact
  views retain the requested identity and offer their containing list. A missing repository returns
  to job overview. Never redirect a missing immutable item to unrelated current bytes.
- A stale response from the previous route must not overwrite the current route. Cache keys include
  every identity and filter; cancel obsolete requests. Opening, refreshing or restoring any route
  is read-only and never starts execution, resumes work, initializes Git or publishes changes.

## Route and state matrix

Every route uses the following common states in addition to its specific recovery below.
**Loading** preserves the shell, page heading and any previously loaded data, marks the relevant
region busy, and labels retained data stale. **Denied** shows session recovery for `401`; for `403`
it explains that access is unavailable and offers an authorized parent/global destination without
revealing resource existence. Reauthentication returns to the read-only route, never resubmits a
mutation. **Failure** includes a safe message and request ID, preserves inputs, and provides a
bounded explicit retry for reads. Retryable mutations first reconcile the recorded operation.

The table's loading column names the bounded region to load. Its denied column names the safe
destination after the common denied treatment; it does not bypass access controls.

| Route / primary task and context | URL state | Empty state | Loading region | Denied destination | Recoverable failure |
| --- | --- | --- | --- | --- | --- |
| `/` — find persistent jobs; global Jobs | `q`, `status`, `createdAfter`, `createdBefore`, `cursor` | No jobs: Upload; no matches: Clear filters | Current job page | Session recovery | Retry list; expired cursor returns to first page with filters preserved |
| `/upload` — create a job; global Upload | None; file selection stays transient | Choose file, accepted format and server limit | Upload progress; prevent duplicate submit | Jobs | Field-specific invalid/oversized file message; retry retained file while page is open; reconcile ambiguous creation |
| `J` — inspect binary metadata and choose explicit next action; job Overview | None | No attempts: workflow action; no reports: explain expected output | Job metadata/capabilities | Jobs | Retry snapshot; unavailable capabilities link Runtime |
| `J/workflows/new` — review and start a supported workflow; job Overview | `kind`, optional `baseRevision` | No available workflow: explain capability reason | Capabilities/preflight; retain form | Job overview | Show field/preflight errors; refresh changed base/version and require renewed review |
| `J/runs` — select a historical attempt; job Activity | `cursor` | No attempts: return to overview action | Attempt page | Job overview | Retry page or refresh expired cursor |
| `R/activity` — inspect durable status, plan, events and logs; job Activity | `event`, optional `log`, `after` for explicit historical inspection | No events yet, with authoritative attempt state | Snapshot then bounded event/log window | Job overview | Disconnected/stale notice; reconnect, reconcile retention gap, offer polling |
| `R/structure` — inspect functions/modules/types/globals and bounded graph; job Structure | `kind`, `entity`, `module`, `q`, `cursor`, optional `revision` | Report absent or zero results are distinct; clear filters or visit Activity | Inventory page or selected graph neighborhood | Attempt activity | Retry report; unsupported schema shows adapter limitation and available artifact |
| `R/evidence` — inspect inputs, observed outputs, scores and validation; job Evidence | `report`, `case`, `compareCase`, optional `revision`, `cursor` | Evidence missing: explain which stage has not produced it | Report summary/current cases | Attempt activity | Partial/unreadable evidence remains labelled; retry or inspect raw artifact as text/download |
| `J/revisions` — inspect lineage and choose candidate/accepted revision; job Revisions | `status`, `cursor` | No registered source revisions | Revision page | Job overview | Retry registry; never infer acceptance from current files |
| `V` — inspect provenance, validation and review relationship; job Revisions | Optional `compare` revision ID | No validation: Unknown/not run; no deltas: say so | Revision and selected comparison | Revision list | Comparison missing/incompatible: preserve primary revision and select another comparison |
| `V/sources` — browse/search immutable source and inspect provenance; job Sources | `file`, `line`, optional `endLine`, `compare`; search explicit opt-in `q` | No files or no search matches; unresolved ownership is separate | Lazy directory page and bounded file/line window | Revision detail | Missing file returns to same revision tree; oversized/binary/invalid UTF-8 offers byte view or download |
| `J/artifacts` — locate reports, logs and archives; job Artifacts | `run`, `revision`, `kind`, `cursor` | No artifacts for scope; clear filter or visit Activity | Catalog page | Job overview | Retry catalog; partial availability does not remove readable entries |
| `J/artifacts/{artifactId}` — inspect identity/digest and download or review archive verification; job Artifacts | Optional `operation` verification ID | Verification not run: say so and offer explicit Verify when supported | Metadata and existing verification result | Artifact catalog | Failed integrity verification shows expected/observed findings and available diagnostics; never label archive verified |
| `/runtime` — inspect readiness, versions, limits and capabilities; global Runtime | Optional `capability` | Capability unknown: explain unavailable diagnostic | Sanitized readiness/capabilities | Jobs | Unreachable/stale details with last check; explicit Retry |
| `J/repositories` — choose or explicitly attach a managed repository; job Git | None | No repository: explain optional Git and supported attach/init action | Registered repository list | Job overview | Git unavailable leaves non-Git navigation intact |
| `G/overview` — inspect Git identity and source mapping; Git Overview | Optional `worktree` | Unborn repository: no commits yet; accepted revision remains independently visible | Repository/worktree status | Repository list | Busy/unavailable/recovery notice with last known status |
| `G/changes` — inspect selected changes, stage and review commit; Git Changes | Required `worktree`; optional `file` | Clean worktree: no changes | Status and bounded selected diff | Git overview | Dirty/version changed: refresh and renew selection/review; preserve drafts |
| `G/history` — inspect immutable commits and linked source revisions; Git History | `commit` full opaque object ID, `compare`, `ref`, `cursor` | No commits | History page or bounded comparison | Git overview | Missing/pruned object: keep requested identity and return to history; no fallback to HEAD |
| `G/branches` — review branch targets and guarded changes; Git Branches | `ref`, optional `worktree`, `cursor` | No named branches; detached/unborn explanation | Ref page and worktree locks | Git overview | Ref changed or active lock: refresh targets; no silent discard |
| `G/worktrees` — inspect/manage registered worktrees; Git Worktrees | `worktree`, `cursor` | None attached: explicit supported add action | Registered worktree page | Git overview | Busy/dirty restrictions identify affected worktree and safe next action |
| `G/remotes` — review remotes, fetch/divergence and deliberate publication; Git Remotes | `remote`, `ref`, `operation` | No remotes: explicit Configure when supported | Sanitized remote/status/operation | Git overview | Offline/auth/transfer failure shows safe classification and reconciliation/retry; credentials never appear |
| `G/conflicts` — inspect and review integration conflicts as candidates; Git Conflicts | `worktree`, `operation`, optional `file` | No conflicts; link operation outcome | Conflict list and selected bounded three-way view | Git overview | Stale target/incomplete recovery blocks apply; keep conflict context and offer operation recovery |

Unsupported route capabilities show an explanatory view with a Runtime link, rather than fabricated
empty data or an execution button that cannot work. Unknown routes show **Page not found** and Jobs;
unknown `/api/**`, asset or download routes never receive the SPA shell. Legacy route migration and
old source/artifact links follow the parity contract and [#230](https://github.com/minsago-elite/decomp_thing/issues/230).

## Desktop and narrow-screen wireframes

All names, IDs and numbers below are synthetic. Bracketed text represents a labelled control;
status words remain visible regardless of color. Desktop uses a persistent job sidebar, a flexible
main pane and optional contextual details. At widths below 48rem the sidebar becomes an explicit
**Navigation** disclosure; breadcrumbs, heading and action status remain above content. At 320 CSS
pixels and 400% zoom, the page reflows to one column. Only source/diff/table regions that need
two-dimensional reading may scroll horizontally. Status and action buttons are never hidden to fit.

```text
Desktop — Jobs and upload                         Desktop — Job overview
+------------------------------------------+     +-------------------------------------------------------+
| Workbench   Jobs   Upload   Runtime       |     | Workbench   Jobs   Upload   Runtime                    |
| Jobs                         [Upload]    |     | Jobs / demo.elf   Job j-demo                           |
| [Search jobs____] [Status v] [Clear]      |     | demo.elf   [Interrupted]  Last updated 10:42            |
| Name          State          Updated    |     +-------------+-----------------------------------------+
| demo.elf      Interrupted    10:42       |     | Overview *  | Binary: ELF64 / x86-64 / 48 KiB          |
| sample.elf    Ready          09:30       |     | Activity    | Attempt r-02: interrupted                |
| [Previous]                     [Next]   |     | Structure   | [Inspect attempt] [Review recovery]      |
+------------------------------------------+     | Evidence    | Source v-01: Candidate                   |
| Upload — choose an ELF [Choose file]     |     | Sources     | Validation: not run                      |
| demo.elf 48 KiB    server limit: 32 MiB   |     | Revisions   | Acceptance: no accepted revision         |
| [Create job]  Creates job; no run starts |     | Artifacts   | [Review workflow] [View source]          |
+------------------------------------------+     | Git         | Repository: none attached                |
                                                 +-------------+-----------------------------------------+

Desktop — Activity after interruption
+----------------------------------------------------------------------------------+
| demo.elf / Attempt r-02      [Interrupted]       [Review recovery]                  |
| Connection restored. Snapshot checked at 10:43; attempt did not resume.             |
| Plan: Analyze [done] -> Reconstruct [interrupted] -> Validate [not run]             |
| Timeline                                | Details                                 |
| 10:40 Stage started                     | Selected event e-17 / source v-01       |
| 10:42 Worker interrupted                | [View available evidence]               |
| Earlier events expired [Load snapshot]  | [Open log] [Download log]               |
| Log window: lines 201–400 [Previous][Next]    [Follow new output: off]              |
+----------------------------------------------------------------------------------+

Desktop — immutable source with unresolved ownership
+----------------------------------------------------------------------------------+
| demo.elf / Candidate v-01 / sources/parser.c       [View revision] [Download]       |
| Origin: attempt r-01 | Inferred recovery | Validation: unknown | Acceptance: none  |
+--------------------------+---------------------------------------+---------------+
| [Search this revision]   | parser.c    [Wrap: off] [Go to line]  | File details  |
| Source tree              |  1  /* synthetic generated source */  | Ownership:    |
| > include/               |  2  ...                               | unresolved    |
| v sources/               |  3  ...                               | [See evidence]|
|   parser.c *             | Bounded text; [Previous] [Next]       | Generator:    |
|   main.c                 | [Compare revision...]                 | recorded ID   |
+--------------------------+---------------------------------------+---------------+

Narrow — overview                 Narrow — sources              Narrow — artifacts
+----------------------------+    +--------------------------+   +----------------------------+
| Workbench [Navigation]     |    | Workbench [Navigation]   |   | Workbench [Navigation]     |
| Jobs / demo.elf            |    | demo.elf / v-01          |   | demo.elf / Artifacts       |
| Overview   [Interrupted]   |    | parser.c                 |   | source-tree.zip            |
| Attempt r-02               |    | Candidate; inferred      |   | v-01 / attempt r-01        |
| [Inspect attempt]          |    | Ownership unresolved     |   | [Verification failed]      |
| [Review recovery]          |    | [Tree] [File details]    |   | Digest mismatch in entry   |
| ELF64 x86-64 / 48 KiB      |    | [Wrap on] [Go to line]   |   | [View findings]            |
| Candidate v-01             |    | 1  /* synthetic source */|   | [Retry verification]       |
| Validation not run         |    | 2  ...                   |   | Last checked 10:44         |
| No accepted revision       |    | [Previous] [Next]        |   | No verified export exists  |
| [View source]              |    | [View revision]          |   | [Back to catalog]          |
+----------------------------+    +--------------------------+   +----------------------------+

Desktop — Git changes/conflicts                    Narrow — Git operation
+----------------------------------------------------------------------------------+
| demo.elf / Repo repo-1 / Worktree wt-1         [Dirty] [Git operation busy]         |
| Overview | Changes * | History | Branches | Worktrees | Remotes | Conflicts        |
| Git branch: review / commit: <full object ID on demand>                            |
| Accepted source: v-00   Candidate: v-01   Mapping: not yet validated                |
+----------------------------+-----------------------------------------------------+
| Changes [selected 1 of 2]  | sources/parser.c: bounded diff                      |
| [x] sources/parser.c       | Before / After; textual additions/deletions          |
| [ ] sources/main.c         | [Review staging] [Review commit]                    |
| Conflicts [1]              | When conflicting: Base / Ours / Theirs / Candidate   |
| sources/parser.c           | [Review resolution] [View validation]               |
+----------------------------+-----------------------------------------------------+
                                               +-----------------------------------+
                                               | Git / wt-1 [Detached] [Dirty]      |
                                               | [Git navigation]                  |
                                               | Operation op-1: fetching [Busy]    |
                                               | Transfer: reported progress       |
                                               | [Review cancellation]             |
                                               | [Source] [Evidence] remain usable |
                                               +-----------------------------------+
```

On narrow screens, Tree and File details open separately labelled drawers/dialogs; closing restores
focus to their trigger and the same source line. Source lines use their own scroller and optional
wrap. Diffs offer stacked before/after or unified text; a wide side-by-side comparison is optional.
Conflict panes stack with persistent Base/Ours/Theirs/Candidate labels. Global/job navigation uses
links, not ARIA tabs; tabs are reserved for local alternate panes that do not navigate routes.

## Visual tokens and shared controls

Use local CSS and the system UI/monospace font stacks. The initial palette below is a light theme;
a future dark theme must pass the same state/contrast checks before becoming selectable. Text sizes
are rem-based: body 1rem/1.5 line height, metadata 0.875rem/1.5, source 0.875rem/1.6, headings
1.25–2rem. Spacing tokens are 4, 8, 12, 16, 24 and 32 CSS pixels; border radius 6px, border 1px.
Controls target at least 44px height. Density preferences may reduce table padding without shrinking
interactive targets or losing status text.

| Token | Value | Use |
| --- | --- | --- |
| `canvas`, `surface` | `#f6f8fa`, `#ffffff` | Page and content surfaces |
| `text`, `muted` | `#1f2937`, `#526071` | Body and secondary text |
| `primary`, `on-primary` | `#1745a0`, `#ffffff` | Primary action, links and button text |
| `success`, `warning`, `danger` | `#17633a`, `#7a4e00`, `#9b1c1c` | Status text/icon on surface; always accompanied by words |
| `neutral`, `border`, `focus` | `#465569`, `#7d8795`, `#6444cc` | Neutral state, meaningful boundaries, focus outline |

Calculated sRGB contrast against white is 14.68:1 for body text, 6.42:1 for muted text, 8.77:1 for
primary, at least 7.20:1 for the three status colors, 3.64:1 for borders and 6.48:1 for focus.
Against canvas these pairs still exceed 4.5:1 for text and 3:1 for meaningful boundaries/focus.
This calculation is design evidence only; actual rendered combinations need the D11 audit.

| Shared control | Required behavior |
| --- | --- |
| Forms/buttons | Native labels, descriptions and field errors; summary links to invalid fields; preserve non-secret drafts on recoverable failure. Distinguish navigation links from submit buttons. Show why an action is unavailable; disabled styling alone is insufficient. |
| Tables/lists | Semantic headers/captions, labelled row links and selection checkboxes; announce sort/order and selected count. Bound/virtualize data without making offscreen rows the only accessible path; offer paginated access. |
| Badges | Visible state word plus optional decorative icon. Keep workflow outcome, validation and acceptance separate. No green badge inferred from absent data. |
| Progress | Show stage and reported completed/total units; unknown total is indeterminate text. Queue position and estimates are explicitly reported/estimated. Cancellation requested is distinct from cancelled. |
| Notices/errors | Inline safe summary, retained last-good timestamp, recovery action and request ID. Transient toasts supplement persistent failures; they never carry the only recovery control. |
| Dialogs | Labelled title and description; focus enters a suitable heading/first field, stays within a modal, Escape cancels when safe, close is visible, and focus returns to trigger or surviving parent heading. Destructive review initially focuses the least destructive choice. |
| Tabs/disclosures | Local tabs have roving focus, arrow/Home/End navigation and Enter/Space activation when loading would be slow. Disclosures use buttons with expanded state. Route navigation remains ordinary links with current-page indication. |
| Pagination | Previous/Next with disabled boundary explanations and current range; do not invent a total. Expired cursor refreshes with notice. Focus remains on the activated control or the results heading when the control disappears. |
| Log/source panes | Labelled bounded region, selectable escaped text, line/byte range and truncation reason, keyboard scroll and full allowed download. Follow-tail is explicit and pauses when reading older output; new lines never steal focus. |
| Confirmation/review | Show exact job/run/revision or Git worktree/ref/object targets, action effects and current guard. Stale targets require a new review; closing or reloading does not confirm. |

Accessibility target is WCAG 2.2 AA, including keyboard access, visible unobscured focus, reflow,
text contrast and status messages. The additional 44px control target is this project's design
choice. Use a visible skip link, one main landmark, meaningful page titles/headings and a two-pixel
focus outline with offset. On route change, focus the main heading; background refresh preserves
focus. Announce operation/state transitions in a polite live region, coalescing repetitive events;
field validation can use an assertive error summary after submit. Never announce every log line.
Honor reduced motion by removing animated transitions/shimmer and retaining static progress text.
[W3C WCAG 2.2 reference](https://www.w3.org/WAI/WCAG22/quickref/).
Dialog and local-tab keyboard/focus behavior follows the
[W3C modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/) and
[tabs pattern](https://www.w3.org/WAI/ARIA/apg/patterns/tabs/).

## Evidence language and Git states

| Label | Meaning presented to the user |
| --- | --- |
| Evidence-only output | Binary-derived evidence/scaffolding; no claim of inferred functional implementation or equivalence |
| Inferred recovery | Generated reconstruction with explicit provenance and limitations; not itself validated or accepted |
| Validation: passed/failed/not run/unknown/partial | Outcome of the named validator on the exact source/input scope, with evidence link; a passed case is not universal equivalence |
| Candidate revision | Immutable source proposed for review/validation, including Git imports and conflict resolutions |
| Accepted revision | Separate canonical acceptance relationship backed by validation/publication evidence; never inferred from agent completion, Git commit, branch/tag, archive existence or a score |
| Confidence/structural score | Reported metric with denominator, method and scope; missing score is unknown, not zero or 100% |
| Agent/workflow completed | Execution lifecycle outcome; any missing downstream validation and acceptance remain explicit |
| Archive verified/failed/not checked | Result bound to exact archive bytes/revision and verification operation; an existing ZIP alone is not verified |

Git **busy** names the operation/lock and limits conflicting actions while browsing remains usable.
**Dirty** shows tracked/untracked/staged counts and selected scope; no implicit discard/stash.
**Detached** shows the pinned commit and explains the absence of an active branch. **Unavailable**
shows the server capability reason and Runtime link. **Diverged** shows local/remote targets and
requires deliberate integration review; **conflicted** routes to conflict candidates and validation.
**Recovery required** preserves the operation identity and blocks dependent writes until reconciled.
Never equate Git cleanliness, commit success, branch membership or push success with accepted source.
Remote publication review names destination, exact source/target refs and object IDs; credentials
remain server-side. Optional GitHub actions are capability-labelled and separate from core Git.

## Recorded design walkthroughs and implementation acceptance cases

The following desk walkthroughs check the synthetic wireframes against the inspected legacy flow
and the prospective API contract. They record expected behavior, not browser-test results.

| Journey | Route/control walkthrough | Design outcome and required later evidence |
| --- | --- | --- |
| Upload | Jobs → Upload → choose `demo.elf` → Create job → job overview; review workflow separately | Job creation ends at metadata with no running attempt. Invalid upload remains on the labelled form; an ambiguous response reconciles before retry. #169/#171 packaged test must prove no automatic execution and keyboard error recovery. |
| Interrupted run | Open `r-02/activity` → reconnect → consistent snapshot says interrupted → Review recovery → inspect exact base and capability → explicit supported retry/resume | Old evidence remains at `r-02`; recovery produces a new attempt link. A disconnected stream alone never changes durable outcome to interrupted. Back returns to `r-02`; reopening cannot resume. #179/#180 must test restart, stale state and operation reconciliation. |
| Unresolved source | Evidence entity → `v-01/sources?file=f-parser&line=2` → inspect unresolved provenance → open details on narrow screen → close → Back | Identity and line remain pinned; unresolved ownership is visible without hiding readable text or manufacturing confidence. Drawer returns focus; Back restores evidence selection. #188/#189/#191 must test lazy loading, long lines and accessible navigation. |
| Failed archive verification | Artifact catalog filtered to `v-01` → archive detail → explicit Verify → failure result → inspect findings → optionally retry verification | Failure is persistent and bound to exact bytes; no verified-export wording/action. Available diagnostics remain accessible, and source review returns to `v-01`. #193 must test corrupt/missing entries and retain failure evidence. |

Accessibility acceptance cases for [#217](https://github.com/minsago-elite/decomp_thing/issues/217),
[#223](https://github.com/minsago-elite/decomp_thing/issues/223) and
[#226](https://github.com/minsago-elite/decomp_thing/issues/226):

1. Complete the upload journey using only keyboard; verify skip link, labels, first invalid field,
   upload announcement and focus on the newly created job heading.
2. Navigate nested source links and browser Back/Forward; verify resource/line identity, current
   navigation indication and restored focus even when the containing list uses pagination.
3. Open and cancel a workflow/Git review dialog by keyboard; verify focus containment, visible close,
   Escape behavior and return focus. Removing the trigger during refresh falls back to the heading.
4. Stream repeated progress and disconnect/reconnect events while reading older logs; verify one
   understandable state announcement, no focus/scroll theft and a visible stale/retention-gap notice.
5. At 320 CSS pixels, 400% zoom, enlarged text, reduced motion and forced colors, inspect overview,
   source, failed verification and Git conflict views; ensure statuses/actions remain perceivable
   and all required content is reachable without page-wide horizontal scrolling.
6. Exercise loading, empty, denied, partial, unsupported, unknown, failed and stale fixtures for each
   route family. Confirm missing evidence never renders as success, and authentication recovery never
   replays a workflow, staging, commit or remote-write request.
7. Read Git busy/dirty/detached/unavailable states with a screen reader; verify that repository/commit
   and accepted revision have distinct labels and source/evidence navigation remains available.

The route/state inventory, wireframes, token calculations and desk walkthroughs are the D0 design
deliverable. Runtime accessibility, packaged parity and actual workflow behavior require their owning
implementation gates; publication of this specification does not satisfy those later gates.
