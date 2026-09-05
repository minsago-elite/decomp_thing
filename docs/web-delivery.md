# Workbench delivery and measurement contract

This document specifies [#150](https://github.com/minsago-elite/decomp_thing/issues/150).
The [program issue](https://github.com/minsago-elite/decomp_thing/issues/144) and its
linked milestones/issues own live status. Numbers below are initial acceptance
budgets, not measured performance claims. The fixtures are synthetic and provide
no evidence about reconstruction quality, vulnerability behavior or model output.

## Independently deliverable slices

The embedded shell comprises D0, D1 and fixture/testing foundations from D12.
It must start from an archived distribution and expose a build identity without
requiring an analysis runtime. Local session, origin and content controls from D10
must precede private data or mutation API exposure. A preview shell does not
replace the legacy workbench before parity qualification.

Legacy parity comprises D2–D6 and the [PAR-01–PAR-17 cases](web-parity.md), with
required D10 controls and D11/D12 checks applied as each feature lands. The richer
workbench adds bounded structure/evidence exploration and D7 capability-aware
revision controls. Local Git parity is D8, qualified independently from remote
access. Remote synchronization is D9 with explicit credential/network boundaries;
optional GitHub integration has a provider-specific gate. Release hardening
integrates D10–D13 evidence without deferring earlier security or scale work.

| Milestone | Entry and primary D prerequisites | Concrete exit / gate owners | A/B/C dependencies |
| --- | --- | --- | --- |
| D0 | Delivered #24/#33 and current service/report contracts | Reviewed parity, architecture, route/state, schema/fixture, trust and budget specifications; #145–#150 | Read existing contracts, no unfinished phase gate |
| D1 | #146 architecture; #148/#149 for serving/proxy behavior | Locked build embeds complete assets in JAR and all distributions; clean/incremental/deterministic builds and relocated packaged serving; #151–#157 | Preserve existing native/BOOT/hosted-worker checks; no model/runtime capability needed to serve shell |
| D2 | #148/#149, local access #161 and containment #164 before private/mutating routes | Durable jobs/attempts, bounded APIs, concurrency/restart/upload/cancel/error contracts; #158–#166 #224 | Existing JobStore/workflow services; A/B/C action capabilities are feature-level |
| D3 | Embedded routes, jobs/upload/capability APIs | Packaged upload-to-job and deliberate workflow request, durable dashboard/lifecycle links; #167–#173 #225 | Live start only for provisioned supported workflow; upload/view have none |
| D4 | Durable attempts, #174 event retention contract, #177 redaction | Reconnect, gap reconciliation, bounded logs, truthful cancel/retry/usage across restart and tabs; #174–#181 #225 | #69 normalized agent events is feature-level; scheduler events work independently |
| D5 | Revision/evidence APIs and synthetic scale fixtures | Report/source authority links, bounded inventory/graphs, explicit unknown/excluded/mismatch states; #182–#187 #220 | Existing A-series producer/validator reports; missing report kinds remain unavailable |
| D6 | Immutable snapshot/artifact services, #164 containment | Lazy safe source/search/diff, streamed artifact download and exact verified archive identity; #188–#193 #225 | Existing #33 archival contract; no unfinished reconstruction phase required to inspect prior evidence |
| D7 | D2 capability/action APIs, D4 events, D6 revision evidence | Capability-based workflow/preflight, candidate review, authorized decisions and backend-validated lineage/rollback; #194–#199 #225 | #64/#65/#72 ACP and #76/#77/#79/#83 built-in are feature-level; unavailable operations disabled with reason |
| D8 | D2 identities, D6 snapshots, applicable D7 revision authority | Contained repositories, bounded status/history/diffs, deliberate staging/commits/worktrees and immutable provenance across restart/conflict; #200–#206 | Backend acceptance authority remains required for acceptance, but Git history itself requires no agent |
| D9 | Qualified D8 repository operations, #207 credential boundary | Explicit bounded clone/fetch/integrate/conflict/push/tag journeys and interruption recovery; #209–#212 #215 | Core Git has no A/B/C gate; optional GitHub #213 requires its own configured provider capability |
| D10 | #149; begin alongside D1/D2 | Verified sessions/origins/text/containment/redaction/quotas/retention; optional authenticated proxy separately qualified; #161 #164 #172 #176 #177 #208 #216 | Existing execution containment stays mandatory for live workflows; web tests use inert data |
| D11 | #147/#150 budgets applied from first UI, actual packaged fixtures | Keyboard/screen-reader/responsive/browser checks and recorded load/heap/list/log/graph budgets; #217–#222 #226 | None; use synthetic persisted datasets |
| D12 | D0 schemas, D1 build; expand as services/views land | Deterministic fixtures, component/API/browser/packaging/adverse-condition tests in required CI with artifacts; #214 #223–#227 | Preserve existing Kotlin/oracle/ACP gates; UI tests do not require live models/native analysis |
| D13 | Proven parity, D10/D11 acceptance, D12 required checks | Migration/rollback evidence, docs/notices/artifact provenance, legacy retirement and requirement-linked release report; #228–#233 | Resolve or explicitly document feature-level A/B/C deferrals; never present unsupported functionality as live |

This table summarizes dependencies; each issue's prerequisite links govern actual
sequencing. A milestone closes only after each criterion has linked current
evidence. Fixture success, a green unrelated gate, prose or dependency installation
cannot qualify a live feature. Deferring an A/B/C capability does not defer a
required D-series view or its truthful unavailable state.

## Reproducible workload

Run `node scripts/generate-web-scale-fixtures.mjs build/web-scale-a` from the
checkout with the pinned Node version in [architecture](web-architecture.md).
The output directory must be absent. Repeat into `build/web-scale-b` and compare
the two `fixture-manifest.json` files and declared payload SHA-256 values. Inputs
are an explicit profile in `contracts/web/scale-profile-v1.json`, fixed timestamps
and deterministic IDs; no random clock, external download, native analyzer,
provider or uploaded executable is used.

The generator emits 10,000 job records, 100,000 functions with addresses above the
JavaScript safe-integer boundary, 25,000 source-tree file records with deterministic
text content, an 8 MiB source file, a 256 KiB single line, 64 MiB of logs, 120,000
ordered events, and 10,000 history/2,000 changed-file/200 ref records. Source-tree
records carry complete virtual file contents; the #214 fixture adapter materializes
owned files only when testing JVM filesystem services. The large source/log files
are real byte payloads. #214 owns conversion into actual persisted jobs, API
schema-bound pages and managed Git repositories; the synthetic workload format
itself is not a production API or a claim that those adapters already exist.

Load profiles name the manifest hash, dataset shape, pagination settings,
retention settings and injected delays. Sustained streams replay event records at
100 events/s for 20 minutes, with a 1,000 events/s ten-second burst, periodic
disconnects and retention gaps. For Git transfer, #215 generates fixed object
payloads at 64/256/512 MiB plus a just-over-limit case in isolated temporary
repositories; no public remote is needed. Git history tests materialize 10,000
commits and 200 refs with fixed author/time/object format and compare logical
history/provenance, not incidental packfile bytes.

## Measurement profiles and budgets

Reference server/client: Linux x86-64, four logical CPU cores, 8 GiB RAM, local SSD,
JDK 21 and a dedicated browser process. CI records actual CPU model, core/memory
limits, kernel, browser build, Node/npm, JDK, commit, asset manifest and fixture
hash. Use the pinned Playwright Chromium, Firefox and WebKit revisions for CI;
qualify current stable Chrome/Edge and Firefox on Linux, and current Safari on
macOS with VoiceOver at release. Native execution remains Linux-only. Safari
qualification is a separate browser-host check, not proof of a macOS JVM workflow.
Manual NVDA/Firefox accessibility checks use a Windows 11 browser host accessing
the qualified packaged Linux server; record Windows, NVDA and Firefox builds in
#217's evidence. This does not qualify Windows as a native execution host.

Desktop viewport is 1440×900 at 1× scale; narrow is 390×844, with a 320 CSS-pixel
reflow check and 200%/400% zoom. Baseline uses same-host loopback. A constrained
profile uses 4× browser CPU slowdown, 10 Mbit/s download, 2 Mbit/s upload and 100 ms
round-trip latency. Record 20 cold loads and 50 interactions per workload; report
median/p95 and failures. Empty browser cache/storage and a fresh process define
cold load; warm data is measured separately. Do not hide failing runs as outliers.

| Metric | Initial acceptance budget and measurement | Fixture / owner |
| --- | --- | --- |
| Entry payload | ≤150 KiB gzip-9 combined HTML + initial JS/CSS; ≤500 KiB gzip-9 all UI resources excluding private maps; sum exact shipped bytes and identify lazy chunks | Asset manifest; #151 #157 #219 |
| Cold shell / ready dashboard | p95 ≤1.5 s loopback, ≤3 s constrained to interactive main landmark / first usable job page; browser performance marks and trace | 10,000 jobs; #219 #225 |
| Interaction | p95 ≤100 ms local feedback for tabs/filter submit/dialog/open file; first data page ≤500 ms loopback or ≤1 s constrained | Jobs/functions/tree/history; #219 #220 |
| Browser heap | ≤128 MiB after initial large-project browsing; ≤192 MiB after 20 min stream/source navigation; ≤16 MiB retained growth between post-GC five-minute checkpoints | Functions/tree/log/event records; Chromium heap trace, other engines process trend; #220 #226 |
| DOM/list work | ≤500 mounted result rows, ≤200 graph nodes/400 edges; append/scroll p95 task ≤50 ms | 100,000 functions, 25,000 files, 10,000 commits; #183 #184 #188 #202 #220 |
| Event latency | p95 ≤1 s from persisted event timestamp to rendered event on loopback; ≤2 s constrained; reconcile gap before rendering acceptance | 100/s stream, 1,000/s burst; #174 #175 #179 #226 |
| Concurrent clients | Eight sessions, up to sixteen SSE streams; normal paged GET p95 ≤500 ms loopback during two scripted workflows; reject over-quota clients predictably | Jobs/events and contained inert workflow fixtures; #208 #220 #224 |
| JVM memory | Incremental web workload RSS ≤256 MiB above warmed idle JVM; bounded request/snapshot state under long session; native workflow memory separately recorded | Full scale profile; #208 #220 #226 |
| Source/log viewing | First bounded chunk ≤500 ms loopback; no full 8 MiB file/64 MiB log load into a view; 256 KiB long line remains responsive | Actual payload files; #178 #189 #220 |
| Search | First ≤200 results within 2 s loopback, cancellable with deadline ≤10 s and explicit truncated/incomplete state | 25,000 files with rare/common/missing terms; #190 #220 |
| Local Git | First status/history page ≤1 s; first diff page ≤2 s; 50 default/200 max rows, 1 MiB response ceiling and 256 KiB diff hunk read | 10,000 commits, 2,000 changed paths, 200 refs; #202 #206 |
| Git transfer | Reserved growth ≤512 MiB; over-limit/timeout/cancel produces terminal bounded operation evidence, ≤5 s process-tree cleanup after cancel | Isolated 64/256/512 MiB remote with delay/disconnect injection; #209 #215 |
| Accessible use | WCAG 2.2 AA target, zero serious/critical automated violations, all documented keyboard/dialog/status cases pass; manual NVDA/Firefox and VoiceOver/Safari smoke | Four navigation walkthroughs plus conflict/push review; #147 #217 #226 |

Performance tools may themselves consume memory; record measurement overhead and
use the same method for control/candidate comparisons. Use server counters and
heap snapshots alongside process RSS; GC-sensitive numbers cannot be compared
across different browser builds without a fresh baseline. Accessibility budgets
require manual evidence as well as automation.

## Reproducibility, evidence and changes

Frontend determinism means two clean locked builds produce identical asset bytes,
names, content digests and canonical manifest; no wall-clock time, host paths or
untracked environment variables enter the bundle. Application JAR reproducibility
means sorted resource entries, fixed timestamps and identical UI entries; #157
also verifies omitted/duplicate/stale/digest-mismatched assets are rejected.
Whole-JAR identity remains an input to existing runtime references after final
JAR bytes exist. Native helper bytes/modes, dependency order, platform closures and
entire distribution reproducibility are separate existing gates under #156;
frontend determinism cannot stand in for them.

Every acceptance result records commit, command, input/fixture/asset hashes,
machine/browser profile, samples, failures/skips, traces/screenshots/logs and
criterion IDs in a retained artifact. Documentation gates include user workflows,
unavailable capabilities, development/build commands, migration/rollback and
deployment/retention operations (#228–#232). Required CI links and independent
packaged checks feed #233's complete criterion-by-criterion release report.

Budget changes require an update to the owning GitHub issue with the original
budget, reproducible before/after measurements, user impact and reason, followed
by reviewed code/spec changes. A weaker machine is not an automatic exemption;
record a new profile and rerun the required baseline. Do not mark a criterion
passed because a limit was silently raised, rows were hidden, a fixture was
shrunk, a capability was relabeled, or an acceptance check was removed.
