# Embedded workbench parity contract

This is the implementation contract for [#145](https://github.com/minsago-elite/decomp_thing/issues/145),
within [the D-series program](https://github.com/minsago-elite/decomp_thing/issues/144).
Issue and milestone status lives in GitHub. This document defines behavior and test
identities; it is not a progress checklist. Baseline inspected: `27feba3`, including
`UploadServer.kt`, `WebViews.kt`, `Jobs.kt`, `UploadServerTest`, `JobStoreTest`, the
README, and the delivered #24/#33 scope.

## Product boundary

The workbench is a persistent, single-user, local-first Linux x86-64 ELF
reconstruction application. Uploading, viewing, refreshing, importing historical
metadata, opening a deep link, or inspecting a Git view never starts binary or model
execution. Execution requires an explicit workflow request accepted by Kotlin's
capability, policy, and scheduling services. Repeated navigation never resubmits it.

The initial supported application host is Linux x86-64 with JDK 21. Existing
distribution/native helper, Ghidra, agent, Git and sandbox prerequisites continue
to apply to their individual workflows. A browser can inspect stored jobs without
those execution prerequisites. The browser compatibility and measurement profiles
are defined in [web delivery](web-delivery.md); no plugin, Node installation, CDN,
provider credential or agent configuration is needed in the browser.

Multi-tenant SaaS, simultaneous collaborative source editing, arbitrary filesystem
browsing, a browser terminal/shell, Windows/macOS execution-host qualification and
an executable fat JAR are deferred product features. Optional authenticated remote
access has its own D10 gate; binding to a public address is not that gate.

Git is first-class scope, including managed source repositories, local changes and
history, selected commits, branches/worktrees, explicit remote synchronization,
conflict review, controlled publication and optional GitHub pull requests. GitHub
project planning continues in issues/milestones. Source-workspace Git operations
do not mutate this project's planning repository implicitly.

## Route and journey inventory

`J` is a persisted job ID, `R` an attempt ID, `V` an immutable source revision,
`F` an opaque file ID and `A` an artifact ID. Route identity and query rules are in
[navigation](web-navigation.md); request schemas and service ownership are in
[the API contract](web-api.md). Every case below belongs in the real packaged
browser suite under #225 and the migration suite under #230. IDs remain stable
when a case is split into finer tests.

| Case | Current route/behavior and baseline evidence | Future route and API | Implementation owner and required browser assertion |
| --- | --- | --- | --- |
| PAR-01 | `GET /`: ELF form and recent jobs; tests `upload page has ELF form`, `dashboard lists uploaded jobs` | `/`, `/upload`; `GET /api/v1/jobs` | #167 #168 #169: empty dashboard, upload navigation, bounded recent jobs, keyboard/back navigation |
| PAR-02 | `POST /jobs` multipart `binary`; HTML 303 to job, JSON Accept gets 201; `web UI uploads ELF and returns job JSON` | `/upload` to `/jobs/J`; `POST /api/v1/jobs` | #162 #169: valid synthetic ELF persists across restart; upload progress/retry never invokes analyzer/reconstructor |
| PAR-03 | Non-ELF rejected at 400; `upload rejects non-ELF content`; declared/actual multipart body limited to 32 MiB | `/upload`; typed upload error | #162 #169 #208: invalid/oversized/truncated uploads keep form recoverable and leave no visible partial job |
| PAR-04 | `GET /jobs/J`: filename, size, timestamps, status/message and ELF metadata; `job state page shows status metadata and repair iteration history` | `/jobs/J`; `GET /api/v1/jobs/J` | #158 #159 #170: metadata is lossless, host path absent, missing/deleted job links back to jobs |
| PAR-05 | `POST /jobs/J/explore`; queued/analyzing/complete or failed; concurrent operation gives 409; `GUI launches analysis renders evidence and downloads artifacts` | job workflow form then activity; `POST /api/v1/jobs/J/runs` | #160 #165 #171 #180: explicit summary and submit, one attempt for a repeated request key, unavailable capability explained; no implicit fallback |
| PAR-06 | `POST /jobs/J/reconstruct`; same scheduling; `GUI launches reconstruction browses escaped source and downloads archive` and `SourceTreeJobReconstructorTest` | job workflow form then activity; same run API with reconstruction kind | #165 #171 #194 #195: explicit agent/evidence-only selection; missing ACP configuration is visible; output mode never inferred from missing credentials |
| PAR-07 | Inline script polls `GET /api/jobs/J` after 900 ms and every 1500 ms while active; page reloads on status change | `/jobs/J/activity?run=R`; run snapshot and resumable events | #174 #175 #179 #181: refresh/reconnect reconciles persisted state; no duplicated start; retained gap and unavailable usage are explicit |
| PAR-08 | Restart converts queued/analyzing to failed with interruption message; `backend marks interrupted analysis jobs failed on recovery` | overview/activity and run detail | #159 #160 #180: interrupted attempt is retained; retry creates a new linked attempt only after submit; viewing old metadata starts nothing |
| PAR-09 | Exploration report from `reports/exploration.json`: candidates, args/stdin, exit/stdout, symbolic counts, signatures, coverage/confidence; first 50 candidates displayed | `/jobs/J/evidence?run=R`; typed report/evidence pages and artifact download | #163 #182 #186: page across candidates, distinguish missing observations, preserve measured denominators and limitations, link raw evidence |
| PAR-10 | Source-tree progress from `reconstruction_progress.json`; module counts and current phase | activity and overview; persisted run snapshot/events | #174 #175 #181: progress has report/run identity; missing total is unknown; reaching total does not confer acceptance |
| PAR-11 | Source tree enumerates generated text paths; unresolved/confidence summaries; `GET /jobs/J/source/{path}` renders escaped text and manifest provenance | `/jobs/J/sources?run=R&revision=V&file=F`; revision tree/file/provenance API | #164 #188 #189 #191: lazy tree, bounded text, same immutable revision in title/content/provenance; unresolved source stays visible |
| PAR-12 | Source metadata includes generator, entity IDs and module confidence; escaped source assertion and traversal rejection in reconstruction GUI test | same source view, structure and evidence detail | #185 #186 #189 #191: benign markup remains text; unknown provenance is explicit; no inferred entity binding from file basename |
| PAR-13 | Repair history from `repair_history.json`: iteration, failure kind, summary, before/after evidence and retained regressions; history test | `/jobs/J/revisions?run=R` and evidence comparisons | #187 #197 #199: historical records remain inspectable; attempted repair, validator result and accepted revision are separate labels |
| PAR-14 | `GET /jobs/J/artifacts/{path}` attachment, report links and source file download | artifacts catalog plus source actions; ID-based artifact/download API | #164 #166 #192: streamed bytes, safe filename, cancellation, missing artifact and immutable identity; never arbitrary host paths |
| PAR-15 | Existing `reports/source-tree.zip` produces a “verified source archive” link; GUI fixture actually writes text `archive` | artifacts/archive detail for `V`; backend verification receipt and archive download | #166 #193: valid bundle hashes/revision match; invalid bytes show failed verification and cannot be labeled verified; raw download remains explicitly unverified if supported |
| PAR-16 | `GET /assets/app.css` serves embedded Kotlin string with one-hour cache; unknown routes 404, invalid requests 400, exceptions 500 HTML | `/assets/ui/*`, recognized SPA routes, structured API errors | #153 #154 #176 #222: packaged styles/chunks, correct MIME/cache/HEAD, unknown APIs/assets never get index HTML, failed chunk offers safe reload |
| PAR-17 | Legacy JSON job API includes `binary_path` and numeric `entry_point`; error responses can be HTML | legacy `/api/jobs/J` compatibility adapter and separate `/api/v1` DTO | #158 #177 #230: documented legacy shape/status compatibility, sanitized messages, lossless v1 values; no new UI dependency on legacy path fields |

The baseline source viewer permits Makefile and `.c`, `.h`, `.json`, `.md`, `.log`.
It reads complete files; tree/report/artifact listing is not yet bounded. The
baseline artifact resolver normalizes paths but does not establish immutable
snapshots or reject every link boundary. These are gaps owned by #164/#166/#188/
#189, not behavior to preserve. Baseline inline scripts/styles and exception
messages also need replacement under #161/#176/#177. Baseline tests establish
specific routes and rendering only; they do not qualify archive integrity,
containment, keyboard access, live models or compiler-scale datasets.

## State vocabulary and authority

| Concept | Meaning and authoritative source | Presentation rule |
| --- | --- | --- |
| Uploaded | Job and validated ELF metadata persisted; no attempt requested | Ready for an explicit action; never “analyzed” |
| Queued | A persisted attempt is admitted to a bounded queue | Show its attempt ID and backend queue position if known |
| Running | Worker has begun that attempt | Display backend stage, progress, cancellation state and evidence links |
| Interrupted | Durable attempt lacks a terminal result after process recovery | Explain interruption; no automatic replay of binary/model calls |
| Failed | Attempt has a terminal error | Retain available evidence and sanitized cause; retry is a new action |
| Partial | Output/report exists but required work or evidence is incomplete | Preserve omissions/reason codes; not synonymous with failure or success |
| Completed | Worker stopped normally | Completion alone says nothing about validation or acceptance |
| Validated | A named validator produced a result for exact input/revision identities | Show pass/fail/unknown and covered scope; never generalize a build pass to behavioral equivalence |
| Accepted | Existing backend revision authority recorded acceptance after required checks | Immutable revision and acceptance evidence must be linked; neither a Git commit nor an agent stop event qualifies |
| Evidence-only | Intentional output contains recovery evidence/placeholders | Label mode and unresolved entities; buildability does not imply recovered implementation |
| Inferred recovery | Recovered source or structure includes inferences | Preserve source/provenance/confidence limitations separately from validation |

Lifecycle, output completeness, validation and acceptance are independent fields.
Legacy `complete` maps to completed with unknown acceptance; legacy `failed` plus
an interruption message may be presented as historical interruption only with
its original metadata retained. Migration cannot manufacture an authenticated run,
revision or validation receipt from historical text.

## Two distinct archive contracts

The application JAR contains trusted compiled JVM code and the frontend asset
closure. Its thin-JAR launch still needs distribution dependencies and configured
native/runtime prerequisites. D1 verifies every shipped UI entry and preserves
the final-JAR hashes used by existing BOOT/hosted worker checks. UI reproducibility
does not imply whole-distribution or native-helper reproducibility.

`source-tree.zip` is an untrusted generated project artifact until the Kotlin
archive verifier checks its manifest, payload and source revision. Its claim is
about that project's files, provenance and independent rebuildability. Downloading
an archive does not execute it; viewing its build result does not validate the
application JAR. See #193 and the existing archival reconstruction contract.

## Release scope and feature dependencies

Legacy parity is PAR-01 through PAR-17, including correcting misleading integrity
and state labels. The richer D-series adds durable attempts, bounded APIs/events,
source search and immutable views, workflow/revision review, local Git and remote
synchronization, accessibility, deployment controls and packaged release gates.

ACP reconstruction/repair (#64/#65), normalized events (#69), ACP qualification
(#72), built-in reconstruction/repair (#76/#77), harness parity (#79) and built-in
qualification (#83) retain their original ownership. Their absence may disable
individual actions with an explanation; it cannot prevent browsing existing
jobs or silently select another harness. Scripted fixtures exercise the UI while
live capabilities remain unavailable. A-series report producers and validators
remain the only authority for the facts the UI presents.

D13 closure requires the milestone-linked acceptance report in #233, with actual
packaged browser results for every parity case and separate evidence for added
features. Passing the legacy Kotlin tests is baseline evidence, not SPA release
qualification.
